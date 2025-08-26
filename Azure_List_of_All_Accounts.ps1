Get-AzureADDirectoryRole | ForEach-Object {
    $role = $_.DisplayName
    Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId | 
    Select-Object @{Name="Role";Expression={$role}}, DisplayName, UserPrincipalName
}