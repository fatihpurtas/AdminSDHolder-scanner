# AdminSDHolder User Analysis Script

This PowerShell script identifies **Active Directory** users with the `AdminSDHolder` protection (`adminCount=1`), analyzes their group memberships for high-privilege detection, filters out system and disabled accounts, and exports the results into a **CSV report**.

## Purpose
In Active Directory, users with `adminCount=1` are usually members of **protected groups** (e.g., Domain Admins, Enterprise Admins).  
Even if a user has been removed from these groups, the `adminCount=1` flag often remains. This means the account continues to be protected by AdminSDHolder, retaining inherited ACLs from when it was previously privileged.

- Detects these users and analyzes their current privilege status.
- Categorizes users based on group membership analysis.
- Excludes `krbtgt`, `Administrator`, computer accounts (ending with `$`), and disabled accounts.
- Exports the remaining accounts that require review into a **CSV file**.
------------------------------ 
## How It Works
1. Uses `DirectorySearcher` with **paging enabled** (1000 objects per page) to find all users with `adminCount=1`, even in large domains.
2. Collects user properties:
   - **Name**
   - **SamAccountName**
   - **AdminCount**
   - **DistinguishedName**
   - **Group Memberships**
   - **UserAccountControl**
3. Analyzes group memberships to determine privilege status:
   - **True**: Confirmed member of a high-privilege group (see list below)
   - **False**: Has group memberships but none are high-privilege groups
   - **No Group Membership**: No direct group memberships found (requires manual review for nested privileges)
4. Evaluates `userAccountControl` to exclude disabled users.
5. Excludes system accounts (`krbtgt`, `Administrator`, computer objects), because these are default or service accounts that do not represent real user accounts requiring security review.
6. Exports filtered users into a **CSV** file.
------------------------------ 
## High Privilege Detection Logic
The script extracts the `CN` from each `memberOf` distinguished name and compares it (exact, case-insensitive) against the following known high-privilege / operator groups:
- **Domain Admins**, **Enterprise Admins**, **Schema Admins**
- **Administrators**
- **Account Operators**, **Backup Operators**, **Server Operators**, **Print Operators**
- **Key Admins**, **Enterprise Key Admins**

Exact CN matching avoids the false positives that substring matching can produce (e.g. a custom group whose name merely contains "Admins").

**Important Limitations:**
- Only detects **direct group memberships** (not nested group relationships).
- Users with "No Group Membership" may still have privileges through:
  - Nested group memberships
  - Primary group settings
  - Special permissions or roles
  - Historical privilege assignments
------------------------------ 
## Output
The script prints summary information to the console:

- **Total users found**
- **Users requiring review**
- **CSV file name**

The CSV file is named:
```
adminsdholder_users_<domain_name>.csv
```
Example: `adminsdholder_users_fatih_local.csv`

### CSV Columns
- **Name**: Display name of the user
- **SamAccountName**: Login name
- **HighPrivilege**: Privilege status (True/False/No Group Membership)
- **DistinguishedName**: Full AD path
- **Groups**: List of group memberships (or "No Groups")
- **UserAccountControl**: Account control flags
- **AdminCount**: AdminSDHolder flag value

## Example CSV Output

| Name          | SamAccountName | HighPrivilege        | DistinguishedName                                       | Groups                                    | UserAccountControl | AdminCount |
|---------------|----------------|----------------------|---------------------------------------------------------|-------------------------------------------|-------------------|------------|
| Fatih Purtaş  | fpurtas        | True                 | CN=Fatih Purtaş,OU=Users,OU=IT,DC=fatih,DC=local        | CN=Domain Admins,CN=Users,DC=fatih,DC=local; CN=Enterprise Admins,CN=Users,DC=fatih,DC=local; CN=IT-Admin,OU=Groups,DC=fatih,DC=local| 66048               | 1          |
| Kevin Mitnick | kmitnick       | False                | CN=Kevin Mitnick,OU=Support,OU=Groups,DC=fatih,DC=local | CN=Help Desk,OU=Groups,DC=fatih,DC=local; CN=IT Support,OU=Groups,DC=fatih,DC=local; CN=File Share Users,OU=Groups,DC=fatih,DC=local  | 512               | 1          |
| Bruce Schneier| bschneier      | No Group Membership  | CN=Bruce Schneier,OU=Former\_Employees,DC=fatih,DC=local| No Groups                                 | 512               | 1          |
| Terry Davis   | tdavis         | True                 | CN=Terry Davis,OU=Admins,OU=IT,DC=fatih,DC=local        | CN=Schema Admins,CN=Users,DC=fatih,DC=local; CN=Exchange Organization Admins,OU=Exchange,DC=fatih,DC=local| 512              | 1          |
| Marcus Hutchins| mhutchins     | False                | CN=Marcus Hutchins,OU=Marketing,OU=Users,DC=fatih,DC=local| CN=Marketing Team,OU=Groups,DC=fatih,DC=local; CN=Sales Access,OU=Groups,DC=fatih,DC=local; CN=VPN Users,OU=Groups,DC=fatih,DC=local   | 66048               | 1          |
------------------------------ 
## USAGE
Run the script in PowerShell:
```powershell
.\AdminSDHolder.ps1
```

Optional parameters:
```powershell
# Query a specific domain controller and choose the output path
.\AdminSDHolder.ps1 -Server dc01.example.com -OutputPath C:\Audit\adminsd.csv

# Scope the search to a specific OU
.\AdminSDHolder.ps1 -SearchBase "OU=IT,DC=example,DC=com"
```

| Parameter | Description |
|-----------|-------------|
| `-Server` | Domain controller to query directly (`dc01.example.com` or `:636`). Defaults to the current domain. |
| `-SearchBase` | Distinguished name to scope the search. Defaults to the domain's default naming context. |
| `-OutputPath` | CSV output path. Defaults to `.\adminsdholder_users_<domain>.csv`. |

If PowerShell execution policies prevent the script from running, you can bypass them temporarily:
```powershell
powershell -ExecutionPolicy Bypass -File "C:\Path\To\AdminSDHolder.ps1"
```

## Example Output
```plaintext
=== ADMINSDHOLDER USER ANALYSIS ===
Total accounts with adminCount=1: 15
Accounts requiring review:        3
  - Confirmed high privilege:     1
  - No group membership (nested?): 1
CSV file saved (Unicode): .\adminsdholder_users_example_com.csv
```

## Requirements & Notes
- No additional PowerShell modules are required. Script runs with **built-in .NET classes**.
- Must be executed on a machine **joined to the domain**.
- The resulting accounts should be manually reviewed to verify if they have privileged access.
- Users marked as "No Group Membership" require **additional investigation** for nested privileges.

---

## Security Implications

### Why It Matters
The **AdminSDHolder** mechanism is designed to protect privileged accounts (e.g., Domain Admins) by applying a static Access Control List (ACL) every 60 minutes.  
Any account with `adminCount=1` will inherit these protections, making them highly privileged and resistant to delegation changes.

### How Attackers Exploit It
Attackers who compromise a lower-privileged account may:
- Add that account into a protected group (e.g., Domain Admins).
- As a result, the account gets `adminCount=1` and inherits AdminSDHolder protection.
- Even if the account is later removed from the group, the flag (`adminCount=1`) often remains set, leaving the account with **persistently elevated rights**.

This creates a **stealthy persistence mechanism** for attackers inside AD environments.

### Analysis Results Interpretation
- **True**: Immediate security concern: user has confirmed high privileges.
- **False**: Lower priority: user has groups but no high privileges detected.
- **No Group Membership**: **High priority for manual review**: user may have:
  - Nested group privileges not detected by the script
  - Historical privileges that need cleanup
  - Special permissions or primary group settings

### Mitigation & Best Practices
- **Regularly audit** accounts with `adminCount=1` (use this script as part of security checks).
- **Reset adminCount values** for accounts that no longer belong to privileged groups.
  - This can be done by removing the attribute and reapplying normal ACL inheritance.
- Method 1: Using PowerShell (requires AD module)
  - Set-ADUser -Identity "username" -Clear adminCount
- Method 2: Using ADSI Edit
  - Open ADSI Edit and connect to the Default naming context
  - Navigate to the user object
  - Right-click, choose Properties, and find the "adminCount" attribute
  - Delete the adminCount attribute or set it to 0
- **Manually investigate** users with "No Group Membership" status for nested privileges.
- **Restrict membership** of protected groups to the bare minimum required.
- **Monitor group changes** with SIEM or AD auditing tools to detect suspicious privilege escalation attempts.
- **Enforce tiered administration** to reduce exposure of high-value accounts.
