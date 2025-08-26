[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)][string]$VaultName,
  [Parameter(Mandatory = $true)][string]$ResourceGroup,
  [switch]$Apply,            # actually create role assignments
  [switch]$EnableRBAC,       # flip the vault's permission model to RBAC
  [string]$Output = ".\AccessPolicyToRBAC_$((Get-Date).ToString('yyyyMMdd_HHmmss')).csv"
)

# -----------------------------
# Helpers
# -----------------------------

function Ensure-Az {
  if (-not (Get-Module -ListAvailable -Name Az)) {
    Write-Host "Installing Az module (CurrentUser scope)..." -ForegroundColor Yellow
    Install-Module Az -Scope CurrentUser -Force -AllowClobber
  }
  Import-Module Az -ErrorAction Stop
}

function Get-RoleDef([string]$Name) {
  $rd = Get-AzRoleDefinition -Name $Name -ErrorAction SilentlyContinue
  if (-not $rd) { throw "Built-in role '$Name' not found. Make sure you're in the correct tenant/subscription." }
  return $rd
}

function ContainsAny([object[]]$set, [string[]]$need) {
  if (-not $set) { return $false }
  foreach ($n in $need) {
    if ($set -contains $n) { return $true }
  }
  return $false
}

function HasReadLike([object[]]$set) {
  return (ContainsAny -set $set -need @('Get','List'))
}

function HasWriteLike([object[]]$set) {
  return (ContainsAny -set $set -need @('Set','Delete','Purge','Recover','Backup','Restore','Import','Update','Create'))
}

# Map one access policy to 1..N RBAC role names
function Map-PolicyToRoles($policy) {
  $roles = New-Object System.Collections.Generic.List[string]

  # In Az.KeyVault, these are arrays of enum strings (or $null)
  $sec = $policy.PermissionsToSecrets
  $key = $policy.PermissionsToKeys
  $crt = $policy.PermissionsToCertificates

  $cryptoOps = @('Encrypt','Decrypt','WrapKey','UnwrapKey','Sign','Verify')
  $keyMgmt   = @('Create','Import','Delete','Update','Recover','Backup','Restore','Purge')

  $writeAll = (HasWriteLike $sec) -and (HasWriteLike $key) -and (HasWriteLike $crt)
  $readAll  = (HasReadLike  $sec) -and (HasReadLike  $key) -and (HasReadLike  $crt)
  $hasCrypto = ContainsAny -set $key -need $cryptoOps

  if ($writeAll -or ($readAll -and $hasCrypto)) {
    [void]$roles.Add('Key Vault Administrator')
    return $roles
  }

  # Secrets
  if ($sec) {
    if ((HasWriteLike $sec)) {
      [void]$roles.Add('Key Vault Secrets Officer')
    } elseif (HasReadLike $sec) {
      [void]$roles.Add('Key Vault Secrets User')
    }
  }

  # Keys (crypto vs. management)
  if ($key) {
    if (ContainsAny -set $key -need $keyMgmt) {
      [void]$roles.Add('Key Vault Crypto Officer')
    } elseif (ContainsAny -set $key -need $cryptoOps) {
      [void]$roles.Add('Key Vault Crypto User')
    }
  }

  # Certificates
  if ($crt) {
    if (HasWriteLike $crt) {
      [void]$roles.Add('Key Vault Certificates Officer')
    } elseif (HasReadLike $crt) {
      # No pure "certs read-only value" role; closest useful action is officer for mgmt
      [void]$roles.Add('Key Vault Certificates Officer')
    }
  }

  if ($roles.Count -eq 0) {
    [void]$roles.Add('Key Vault Reader') # metadata-only fallback
  }

  return $roles
}

function Ensure-Assignment([string]$ObjectId, [string]$RoleName, [string]$Scope) {
  $existing = Get-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleName -Scope $Scope -ErrorAction SilentlyContinue
  if ($existing) {
    return @{ Created = $false; Message = 'Exists' }
  }

  if ($PSCmdlet.ShouldProcess("$ObjectId ← $RoleName @ $Scope", "Create role assignment")) {
    New-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleName -Scope $Scope -ErrorAction Stop | Out-Null
    return @{ Created = $true; Message = 'Created' }
  }

  return @{ Created = $false; Message = 'Skipped' }
}

function Resolve-PrincipalObjectId {
  param([string]$ObjectId, [Guid]$ApplicationId)

  # If policy already has an ObjectId, prefer it
  if ($ObjectId -and $ObjectId -ne [string]::Empty) {
    return $ObjectId
  }

  # If only ApplicationId is present, resolve to SP object ID in this tenant
  if ($ApplicationId -and $ApplicationId -ne [Guid]::Empty) {
    $sp = Get-AzADServicePrincipal -ApplicationId $ApplicationId -ErrorAction SilentlyContinue
    if ($sp) { return $sp.Id }
  }

  return $null
}

function Fail-IfNullPrincipal {
  param($ResolvedId, $Policy)
  if (-not $ResolvedId) {
    throw ("Cannot resolve principal for policy. ObjectId='{0}' ApplicationId='{1}' TenantId='{2}'" -f `
      $Policy.ObjectId, $Policy.ApplicationId, $Policy.TenantId)
  }
}


# -----------------------------
# Main
# -----------------------------
try {
  $ErrorActionPreference = 'Stop'
  Ensure-Az

  $vault = Get-AzKeyVault -Name $VaultName -ResourceGroupName $ResourceGroup -ErrorAction Stop
  $scope = $vault.ResourceId
  Write-Host "Loaded Key Vault: $($vault.VaultName) in RG $ResourceGroup" -ForegroundColor Cyan

  $policies = $vault.AccessPolicies
  if (-not $policies -or $policies.Count -eq 0) {
    Write-Warning "No Access Policies found on this vault. Nothing to map."
  }

  # Validate roles exist up front
  $rolesToCheck = @(
    'Key Vault Administrator',
    'Key Vault Secrets Officer','Key Vault Secrets User',
    'Key Vault Crypto Officer','Key Vault Crypto User',
    'Key Vault Certificates Officer',
    'Key Vault Reader',
    'Key Vault Data Access Administrator'
  )
  foreach ($rn in $rolesToCheck) { [void](Get-RoleDef $rn) }

  $rows = @()

  foreach ($p in $policies) {
    # $principal = $p.ObjectId
    $principal = Resolve-PrincipalObjectId -ObjectId $p.ObjectId -ApplicationId $p.ApplicationId Fail-IfNullPrincipal -ResolvedId $principal -Policy $p
    $appid     = $p.ApplicationId
    $tenantId  = $p.TenantId

    $mappedRoles = Map-PolicyToRoles -policy $p

    if (-not $Apply) {
      foreach ($r in $mappedRoles) {
        $rows += [pscustomobject]@{
          PrincipalObjectId = $principal
          ApplicationId     = $appid
          TenantId          = $tenantId
          SuggestedRole     = $r
          Scope             = $scope
          Status            = 'Planned'
        }
      }
    } else {
      foreach ($r in $mappedRoles) {
        $res = Ensure-Assignment -ObjectId $principal -RoleName $r -Scope $scope
        $rows += [pscustomobject]@{
          PrincipalObjectId = $principal
          ApplicationId     = $appid
          TenantId          = $tenantId
          SuggestedRole     = $r
          Scope             = $scope
          Status            = $res.Message
        }
      }
    }
  }

  if ($rows.Count -gt 0) {
    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $Output
    Write-Host "Mapping exported to $Output" -ForegroundColor Green
  }

  if ($EnableRBAC) {
    if ($PSCmdlet.ShouldProcess($VaultName, "Enable RBAC authorization (disable Access Policies evaluation)")) {
      Update-AzKeyVault -Name $VaultName -ResourceGroupName $ResourceGroup -EnableRbacAuthorization:$true | Out-Null
      Write-Host "Vault permission model set to Azure RBAC." -ForegroundColor Green
    }
  } else {
    Write-Host "NOTE: Vault remains on its current permission model. Use -EnableRBAC to flip after verifying assignments." -ForegroundColor Yellow
  }

  Write-Host "`nNext steps:" -ForegroundColor Cyan
  Write-Host "• Review $Output to verify each principal→role mapping."
  Write-Host "• Test app paths (secret get, key sign/wrap, cert retrieval)."
  Write-Host "• Re-run with -Apply to create assignments; add -EnableRBAC for cutover."
  Write-Host "• Keep a break-glass group on 'Key Vault Administrator' and optionally 'Key Vault Data Access Administrator'."

} catch {
  Write-Error $_.Exception.Message
  throw
}
