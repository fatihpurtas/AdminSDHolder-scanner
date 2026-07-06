<#
.SYNOPSIS
    Scans Active Directory for accounts carrying the AdminSDHolder flag (adminCount=1).

.DESCRIPTION
    Finds user accounts with adminCount=1, classifies them by whether they are
    still members of a high-privilege group, filters out system and disabled
    accounts, and exports the results that need review to a CSV file.

    Uses only built-in System.DirectoryServices classes, so no ActiveDirectory
    PowerShell module is required.

.PARAMETER Server
    Optional domain controller to query directly (e.g. dc01.example.com or
    dc01.example.com:636). Defaults to the current domain.

.PARAMETER SearchBase
    Optional distinguished name to scope the search (e.g. OU=IT,DC=example,DC=com).
    Defaults to the domain's default naming context.

.PARAMETER OutputPath
    CSV output path. Defaults to .\adminsdholder_users_<domain>.csv

.EXAMPLE
    .\AdminSDHolder.ps1

.EXAMPLE
    .\AdminSDHolder.ps1 -Server dc01.example.com -OutputPath C:\Audit\adminsd.csv
#>
[CmdletBinding()]
param(
    [string]$Server,
    [string]$SearchBase,
    [string]$OutputPath
)

# Well-known high-privilege groups. Membership in any of these means the
# account currently holds serious privileges (not just a lingering flag).
$highPrivGroupNames = @(
    "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
    "Account Operators", "Backup Operators", "Server Operators", "Print Operators",
    "Key Admins", "Enterprise Key Admins"
)
$highPrivSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]$highPrivGroupNames, [System.StringComparer]::OrdinalIgnoreCase)

function Get-CnFromDn {
    # Extract the leading CN value from a distinguished name.
    param([string]$Dn)
    if ([string]::IsNullOrEmpty($Dn)) { return $null }
    if ($Dn -match '^CN=([^,]+)') { return $Matches[1] }
    return $null
}

# --- Determine domain and search root ---
try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domainName = $domain.Name -replace '\.', '_'
} catch {
    Write-Error "Unable to determine the current domain. Run this on a domain-joined machine, or specify -Server. Details: $($_.Exception.Message)"
    exit 1
}

$root = $null
if ($Server -or $SearchBase) {
    $prefix = if ($Server) { "LDAP://$Server/" } else { "LDAP://" }
    $base   = if ($SearchBase) { $SearchBase } else { $domain.GetDirectoryEntry().distinguishedName.Value }
    $root = New-Object System.DirectoryServices.DirectoryEntry("$prefix$base")
}

$searcher = if ($root) {
    New-Object System.DirectoryServices.DirectorySearcher($root)
} else {
    New-Object System.DirectoryServices.DirectorySearcher
}
$searcher.Filter = "(&(objectClass=user)(admincount=1))"
$searcher.PageSize = 1000   # enable paging so large domains return more than the default limit
foreach ($pr in @("name","samaccountname","admincount","distinguishedname","useraccountcontrol","memberof")) {
    [void]$searcher.PropertiesToLoad.Add($pr)
}

$results = $null
$output = [System.Collections.Generic.List[object]]::new()

try {
    try {
        $results = $searcher.FindAll()
    } catch {
        Write-Error "LDAP query failed: $($_.Exception.Message)"
        exit 1
    }

    $total = $results.Count
    $counter = 0

    foreach ($result in $results) {
        $counter++
        if ($total -gt 0) {
            Write-Progress -Activity "Analyzing AdminSDHolder users..." `
                           -Status "Processing user $counter of $total" `
                           -PercentComplete (($counter / $total) * 100)
        }

        $p = $result.Properties
        $userAccountControl = if ($p["useraccountcontrol"].Count -gt 0) { [int]$p["useraccountcontrol"][0] } else { 0 }

        $memberDns = @($p["memberof"])
        $groupCns  = @($memberDns | ForEach-Object { Get-CnFromDn $_ } | Where-Object { $_ })

        # High privilege check: exact CN match against the known-privileged set
        $isHighPriv = $false
        foreach ($cn in $groupCns) {
            if ($highPrivSet.Contains($cn)) { $isHighPriv = $true; break }
        }

        $highPrivStatus = if ($isHighPriv) {
            "True"                   # Confirmed member of a high-privilege group
        } elseif ($memberDns.Count -eq 0) {
            "No Group Membership"    # No direct groups (could still be privileged via nesting/primary group)
        } else {
            "False"                  # Has groups but none are high-privilege
        }

        $output.Add([PSCustomObject]@{
            Name               = if ($p["name"].Count -gt 0) { $p["name"][0] } else { "N/A" }
            SamAccountName     = if ($p["samaccountname"].Count -gt 0) { $p["samaccountname"][0] } else { "N/A" }
            HighPrivilege      = $highPrivStatus
            DistinguishedName  = if ($p["distinguishedname"].Count -gt 0) { $p["distinguishedname"][0] } else { "N/A" }
            Groups             = if ($memberDns.Count -gt 0) { $memberDns -join "; " } else { "No Groups" }
            UserAccountControl = $userAccountControl
            AdminCount         = if ($p["admincount"].Count -gt 0) { $p["admincount"][0] } else { "N/A" }
        })
    }
    Write-Progress -Activity "Analyzing AdminSDHolder users..." -Completed
} finally {
    if ($results) { $results.Dispose() }
    $searcher.Dispose()
    if ($root) { $root.Dispose() }
}

# Exclude default system accounts, computer accounts, and disabled users
$filteredUsers = foreach ($user in $output) {
    $isDisabled = ($user.UserAccountControl -band 2) -ne 0
    if ($user.SamAccountName -ne "krbtgt" -and
        $user.SamAccountName -ne "Administrator" -and
        -not $user.SamAccountName.EndsWith('$') -and
        -not $isDisabled) {
        $user
    }
}
$filteredUsers = @($filteredUsers)

if (-not $OutputPath) {
    $OutputPath = ".\adminsdholder_users_$domainName.csv"
}
$filteredUsers | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding Unicode

# --- Summary ---
$highCount = @($filteredUsers | Where-Object { $_.HighPrivilege -eq "True" }).Count
$reviewCount = @($filteredUsers | Where-Object { $_.HighPrivilege -eq "No Group Membership" }).Count

Write-Host "=== ADMINSDHOLDER USER ANALYSIS ===" -ForegroundColor Yellow
Write-Host "Total accounts with adminCount=1: $($output.Count)" -ForegroundColor White
Write-Host "Accounts requiring review:        $($filteredUsers.Count)" -ForegroundColor Green
Write-Host "  - Confirmed high privilege:     $highCount" -ForegroundColor Red
Write-Host "  - No group membership (nested?): $reviewCount" -ForegroundColor Magenta
Write-Host "CSV file saved (Unicode): $OutputPath" -ForegroundColor Cyan

$filteredUsers | Format-Table Name, SamAccountName, HighPrivilege, DistinguishedName -AutoSize
