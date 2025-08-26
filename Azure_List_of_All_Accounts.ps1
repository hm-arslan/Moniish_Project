<# 
.SYNOPSIS
  Inventory Entra ID privileged users, PIM state (Active/Eligible), and AAD Premium P2 licensing.
  Optionally assign P2 licenses to users who are missing it.

.EXAMPLE
  # Inventory only (no license changes)
  .\Get-PIM-Privileged-Inventory.ps1

.EXAMPLE
  # Inventory + assign Entra ID P2 to missing users
  .\Get-PIM-Privileged-Inventory.ps1 -AssignP2
#>

param(
  [switch]$AssignP2,                       # Assign AAD_PREMIUM_P2 to users missing it
  [string]$CsvPath = ".\PIM-Privileged-Inventory.csv",
  [switch]$VerboseOutput                   # Show extra progress
)

# -------------------- Helpers --------------------
function Write-Info($msg){ Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Warn($msg){ Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Ok($msg){ Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Err($msg){ Write-Host "[x] $msg" -ForegroundColor Red }

# -------------------- Connect Graph --------------------
$scopes = @(
  "Directory.Read.All",
  "RoleManagement.Read.Directory",
  "User.Read.All"
)
if ($AssignP2) { $scopes += "User.ReadWrite.All" }

Write-Info "Connecting to Microsoft Graph with scopes: $($scopes -join ', ')"
Connect-MgGraph -Scopes $scopes | Out-Null
Select-MgProfile -Name "beta" | Out-Null   # Needed for PIM schedule instance APIs

# -------------------- Identify AAD P2 SKU --------------------
Write-Info "Fetching subscribed SKUs to locate AAD_PREMIUM_P2..."
$skus = Get-MgSubscribedSku -All
$p2Sku = $skus | Where-Object { $_.SkuPartNumber -eq "AAD_PREMIUM_P2" }

if (-not $p2Sku) {
  Write-Warn "AAD_PREMIUM_P2 not found in tenant subscriptions. Inventory will proceed, but license assignment will be skipped."
}

# -------------------- Pull directory roles & members --------------------
Write-Info "Fetching directory roles and members..."
$dirRoles = Get-MgDirectoryRole -All

# If roles array is empty, you may need to "activate" built-in roles:
if (-not $dirRoles) {
  Write-Warn "No active directory roles returned. If this is a new tenant, run: 'Enable-MgDirectoryRoleTemplate' for built-ins, or make sure roles are present."
}

# We’ll gather PIM Active/Eligible via schedule instances
Write-Info "Fetching PIM role assignment/eligibility schedule instances (this can take a minute in large tenants)..."
$activeInstances   = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All
$eligibleInstances = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All

# Build quick lookup hash tables keyed by "principalId:roleDefinitionId"
$activeLookup   = @{}
$eligibleLookup = @{}
foreach ($ai in $activeInstances) {
  $key = "$($ai.PrincipalId):$($ai.RoleDefinitionId)"
  $activeLookup[$key] = $true
}
foreach ($ei in $eligibleInstances) {
  $key = "$($ei.PrincipalId):$($ei.RoleDefinitionId)"
  $eligibleLookup[$key] = $true
}

# Build a map of RoleDefinitionId by Directory Role (they differ!)
# DirectoryRole has RoleTemplateId; we need RoleDefinitionId from role management API:
$roleDefs = Get-MgRoleManagementDirectoryRoleDefinition -All
$roleDefByTemplate = @{}
foreach ($rd in $roleDefs) {
  if ($rd.RoleTemplateId) { $roleDefByTemplate[$rd.RoleTemplateId] = $rd.Id }
}

# You can restrict to “privileged” roles by template IDs below if you prefer.
# Otherwise, we’ll include all roles that have any members.
$inventory = New-Object System.Collections.Generic.List[object]

foreach ($role in $dirRoles) {
  # Skip empty roles quickly
  $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
  if (-not $members) { continue }

  # Resolve the RoleDefinitionId for PIM lookups
  $roleDefId = $null
  if ($role.RoleTemplateId -and $roleDefByTemplate.ContainsKey($role.RoleTemplateId)) {
    $roleDefId = $roleDefByTemplate[$role.RoleTemplateId]
  }

  foreach ($m in $members) {
    # Keep only real users; skip service principals/groups
    if ($m.AdditionalProperties.'@odata.type' -ne '#microsoft.graph.user') { continue }

    $userId = $m.Id
    $user = Get-MgUser -UserId $userId -Property "id,displayName,userPrincipalName,assignedLicenses" -ErrorAction SilentlyContinue
    if (-not $user) { continue }

    # Determine PIM state for this role/user
    $pimState = "Unknown"
    if ($roleDefId) {
      $key = "$($user.Id):$roleDefId"
      $isActive   = $activeLookup.ContainsKey($key)
      $isEligible = $eligibleLookup.ContainsKey($key)

      if ($isActive) { $pimState = "Active" }
      elseif ($isEligible) { $pimState = "Eligible" }
      else { $pimState = "Direct (Permanent)" }  # Member of DirectoryRole but not found in PIM schedules
    } else {
      # Fallback if we couldn’t resolve a RoleDefinitionId
      $pimState = "Direct (Permanent)"
    }

    # License check
    $hasP2 = $false
    if ($user.AssignedLicenses) {
      foreach ($al in $user.AssignedLicenses) {
        if ($al.SkuId -eq $p2Sku.SkuId) { $hasP2 = $true; break }
      }
    }

    # Add to inventory
    $inventory.Add([pscustomobject]@{
      UserDisplayName     = $user.DisplayName
      UserPrincipalName   = $user.UserPrincipalName
      UserId              = $user.Id
      RoleName            = $role.DisplayName
      RoleTemplateId      = $role.RoleTemplateId
      RoleDefinitionId    = $roleDefId
      PIM_State           = $pimState
      Has_AAD_Premium_P2  = $hasP2
    })
  }
}

# -------------------- Export CSV --------------------
Write-Info "Writing inventory to $CsvPath ..."
$inventory | Sort-Object RoleName, UserDisplayName | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $CsvPath
Write-Ok "Inventory exported."

# -------------------- Optional: Assign AAD P2 --------------------
if ($AssignP2 -and $p2Sku) {
  # Users missing P2
  $toLicense = $inventory | Where-Object { -not $_.Has_AAD_Premium_P2 } | Select-Object -Unique UserId,UserPrincipalName,UserDisplayName

  if (-not $toLicense) {
    Write-Ok "All privileged users already have AAD_PREMIUM_P2. Nothing to assign."
  } else {
    Write-Info "Assigning AAD_PREMIUM_P2 to $($toLicense.Count) user(s)..."
    foreach ($u in $toLicense) {
      try {
        if ($VerboseOutput) { Write-Info "Assigning P2 to $($u.UserPrincipalName) ..." }
        $add = @{ addLicenses = @(@{ skuId = $p2Sku.SkuId }); removeLicenses = @() }
        Update-MgUserLicense -UserId $u.UserId -BodyParameter $add | Out-Null
        Write-Ok "Assigned P2 -> $($u.UserPrincipalName)"
      }
      catch {
        Write-Err "Failed to assign P2 to $($u.UserPrincipalName): $($_.Exception.Message)"
      }
    }
  }
} elseif ($AssignP2 -and -not $p2Sku) {
  Write-Err "Cannot assign P2 because AAD_PREMIUM_P2 SKU was not found."
}

Write-Ok "Done."
