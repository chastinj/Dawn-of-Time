# Power Shell Command Assist

### Connecting to vCenter
```powershell
Connect-VIserver rangevcenter.cnd.ca.gov
```  

### Storing Credentials using PowerShell SecretManagement Module  
PowerShell’s SecretManagement and SecretStore modules are robust options for securely storing and retrieving secrets.  

```powershell
Install-Module Microsoft.PowerShell.SecretManagement
Install-Module Microsoft.PowerShell.SecretStore
```  

### Register a new SecretStore vault and add your credentials  
```powershell
Register-SecretVault -Name "MySecretVault" -ModuleName Microsoft.PowerShell.SecretStore -Description "My Secure Vault"
Set-Secret -Name "vCenterCred" -Secret (Get-Credential)
```  

### Retrieve the credentials in PowerCLI  
```powershell
$cred = Get-Secret -Name "vCenterCred" -AsPlainText
Connect-VIServer -Server "rangevcenter.cnd.ca.gov" -Credential $cred
```  

### Retrieving Credentials from PowerShell SecretStore  
```powershell
$range = 'rangevcenter.cnd.ca.gov'
$cred = Get-Secret -Name "vCenterCred" -AsPlainText
Set-Alias -Name cv -Value Connect-VIServer
Set-Alias -Name dv -Value Disconnect-VIServer
```  

### vCenter Connect using PowerShell Stored Credentials  
```powershell
cv $range -Credential $cred
```  

### List VMs from a specific team 
```powershell
Get-VM -Name Team01-*
```  

### List DC VMs from a specific team or all DCs
```powershell
Get-VM -Name Team01-DC*
```  
or  
```powershell
Get-VM -Name *DC*
```  

### List Team01 workstation numbered 01-09  
```powershell
Get-VM -Name Team01-WK0[1-9]
```  

### List Team01 Systems and assign tags  
```powershell
Get-VM -Name Team01-* | New-TagAssignment -Tag "Team01"
```  

### List Multiple systems using regex  
```powershell
Get-VM | Where-Object { $_.Name -match 'Team0[6-9].*' -or $_.Name -match 'Team10.*' }
```  

### List all VMs in a specific folder   
```powershell
Get-Folder "Internet" | Get-VM
```  

### Update VMTools  
```powershell
Get-VM -Name Team15-WK* | Update-Tools
```  

### Upgrade VM Hardware by listing VMs in a specific folder  
```powershell
Get-Folder "Internet" | Get-VM | ForEach-Object { $_.ExtensionData.UpgradeVM('vmx-21') }
```  

### Upgrade VM Hardware by listing VMs with a specific name  
```powershell
Get-VM Team03-* | ForEach-Object { $_.ExtensionData.UpgradeVM('vmx-21') }
```  

### Start VMs  
```powershell
Get-VM -Name Team01-WK0[1-9] | Start-VM
```  

### Shutdown VMs Gracefully  
```powershell
Get-VM -Name Team01-WK0[1-9] | Shutdown-VMGuest -Confirm:$false
```  

### Restart VMs  
```powershell
Get-VM -Name Team01-WK0[1-9] | Restart-VM
```  

### Restart VMs with a delay  
```powershell
Get-VM -Name Team14-WK* | ForEach-Object { Restart-VM -VM $_ -Confirm:$false; Start-Sleep -Seconds 5 }
```  

### Restart VMs with a delay  
```powershell
# Get the VMs matching the specified name pattern
$vms = Get-VM | Where-Object { $_.Name -match '(Team0[1-9]-WK.*|Team1[0-4]-WK.*)' }

# Loop through the VMs and reboot them with a 5-second delay between each
foreach ($vm in $vms) {
    Restart-VM -VM $vm -Confirm:$false
    Start-Sleep -Seconds 8
}
```

### Restart all powered on WK VMs with specific exclusions  
```powershell
Get-VM | where{$_.PowerState -eq 'PoweredOn' -and $_.Name -match 'Team.*-WK.*' -and $_.Name -notmatch 'WK13'} | ForEach-Object { Restart-VM -VM $_ -Confirm:$false; Start-Sleep -Seconds 5 }
```  

### Remove VMs  
```powershell
Get-VM -Name Team01-WK0[1-9] | Remove-VM -DeletePermanently -Confirm:$false
```

### List all Windows VM IPv4 addresses  
```powershell
Get-VM team07-* | Where-Object { $_.PowerState -eq 'PoweredOn' -and $_.Guest.OSFullName -match 'Windows' } | Sort-Object Name | Select-Object Name, @{ Name="IP Address"; Expression={ ($_.Guest.IPAddress | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' }) -join '|' } }
```  

### List all the Windows VM Names with IPv4 10.x addresses  
```powershell
Get-VM team07-* | Where-Object { $_.PowerState -eq 'PoweredOn' -and $_.Guest.OSFullName -match 'Windows' } | Sort-Object Name | Select-Object Name, @{ Name="IP Address"; Expression={ ($_.Guest.IPAddress | Where-Object { $_ -match '^10\.' }) -join '|' } }
```  

### List all Windows VM with just IPv4 10.x addresses  
```powershell
Get-VM team07-* | Where-Object { $_.PowerState -eq 'PoweredOn' -and $_.Guest.OSFullName -match 'Windows' } | ForEach-Object { ($_.Guest.IPAddress | Where-Object { $_ -match '^10\.' }) -join '|' }
```  

### List all VMs that are powered off and exclude others by name  
```powershell
get-vm team03-* | where{$_.PowerState -eq 'PoweredOff' -and $_.Name -notmatch 'SO'}
```  

### Move VMs different folder  
```powershell
get-vm Team01-* | move-VM -InventoryLocation ConsoleAccess01
```  

### List VMs with corresponding datastore  
```powershell
Get-VM Team01-* | Select-Object Name,@{N="Datastore";E={[string]::Join(',',(Get-Datastore -Id $_.DatastoreIdList | Select -ExpandProperty Name))}}
```  

### Move VMs to a different datastore  
```powershell
Get-VM -Name "Team15*" | Move-VM -Datastore "RangeST01Volume08"
```  

### Move VMs to a different Host  
```powershell
Get-VM -Name "Team15*" | Move-VM -Destination "rangeesxi08.cnd.ca.gov"
```  

### Move VMs to a different Host and datastore  
```powershell
Move-VM -VM "VMName" -Destination "rangeesxi08.cnd.ca.gov" -Datastore "RangeST01Volume08"
```  

### Running Commands on VMGuest Systems  
```powershell
Invoke-VMScript -VM $varNmapServer -ScriptText $varCMD -GuestUser $varGuestUser -GuestPassword $varGuestPassword -ScriptType Bash | Out-Null
```  

### Create Snapshots Multiple Systems  
```powershell
Get-VM -Name Team01-* | New-Snapshot -Name nameofsnapshot
```  

### Restore Snapshots Multiple Systems  
```powershell
$varVMs = Get-VM -Name Team01-TL0[1-2]
Foreach ($varVM in $varVMs) {
    Set-VM -VM $varVM -SnapShot ExerciseBaseLine -Confirm:$false  -RunAsync | Out-Null
}
```  

### Remove all Snapshots on Multiple Systems  
```powershell
Get-VM -Name Team01-* | Get-Snapshot | Remove-Snapshot -Confirm:$false  -RunAsync
```

### Change CPU/Memory  
```powershell
get-vm -name Team*-EX01 | set-vm -NumCpu 4 -MemoryGB 8 -Confirm:$false
```  

### Create VMs in the same enclave from template  
The script tends to generate a lot of errors, but it does not prevent the script from running.  The variables in the script should be self explanatory, or explained below.  Ensure you save the script to disk before running.  It tended to generate a bunch of errors or failed if I did not save it.  

* Network Name Variable  
  * Team_XX_RangeJumpBoxes - This network will have internet access while you build the VM.  This network is external and has no access to the range.  
  * Team_XX_ZoneX_ZoneName - Range only Networks should be self explanatory.  Ultimately, it does not matter what network, each one has DHCP and will route traffic appropriately.  See [Range Enclave Spreadsheet](docs/range-network.csv) for a list of all networks.  Ranges 10-20 have DHCP enabled.  

change $num to be the starting and ending number for how many VMs are wanted.  It will also be part of the VM name. e.g. Team01-WK01, Team01-WK02 
`$num = 1 ; $num -le 3`  

```powershell
# This is the Range Team number, e.g. Team01, Team02, Team03.  It also determines what folder the VMs will be created in.  e.g. TeamXX_Range
$varRangeTeamNumber = "11"
# This is the machine type, e.g. WK, DC, FS
$varVMRole = "WK"
# This is the template name
$varVMTemplate = "Win10_2004_Commando_Template_v2"
# This is the folder that the VM will be placed in.  It will be placed in the folder based on the team number  
$varRangeFolder = "Team" + $varRangeTeamNumber + "_Range"
# This is the Network PortGroup that will be assigned for network access
$varNetworkName = "Team_11_RangeJumpBoxes"

for ($num = 1 ; $num -le 3 ; $num++) {
    # this will get the datastore with the most space
    $varDataStore = (Get-Datastore | Where-Object {$_.Name -like "RangePureStorage*"} | Sort-Object -Property FreeSpaceMB -Descending | Select-Object -First 1)
    # Set the VM name
    $varVMName = ("Team" + $varRangeTeamNumber + "-" + $varVMRole + "$($num.ToString("00"))")
    New-VM -Template $varVMTemplate -Name $varVMName -VMHost rangeesxi08.cnd.ca.gov -Datastore $varDataStore -Location $varRangeFolder -NetworkName $varNetworkName | Out-Null
}
```  

### Create multiple VMs across enclaves from template  
```powershell
# This is the Range Team number, e.g. Team01, Team02, Team03.  It also determines what folder the VMs will be created in.  e.g. TeamXX_Range
[int]$StartRangeNumber = "20"
[int]$EndRangeNumber = "20"
# This is the machine type, e.g. WK, DC, FS
$varVMRole = "PAN1"
# This is the template name
$varVMTemplate = "PAN_Template_11.02"


for($i=$StartRangeNumber;$i -le $EndRangeNumber;$i++) {
    # this will get the datastore with the most space
    $varDataStore = (Get-Datastore | Where-Object {$_.Name -like "*RangeST*"} | Sort-Object -Property FreeSpaceMB -Descending | Select-Object -First 1)
    # Set the VM name
    #$varVMName = ("Team" + $varRangeTeamNumber + "_" + $varVMRole)
    New-VM -Template $varVMTemplate -Name "Team$($i.ToString('00'))_$varVMRole" -VMHost rangeesxi08.cnd.ca.gov -Datastore $varDataStore -Location "Team$($i.ToString('00'))_Range" | Out-Null
    # Get the name of the new system
    $varVM = Get-VM -Name "Team$($i.ToString('00'))_$varVMRole"
    write-host $varVM
    $varNA = ($varVM | Get-NetworkAdapter)
    $varPG1 = Get-VDPortgroup -Name ("Team$($i.ToString('00'))_RangeJumpBoxes")
    $varPG2 = Get-VDPortgroup -Name ("Team$($i.ToString('00'))_Zone0_DMZ")
    $varPG3 = Get-VDPortgroup -Name ("Team$($i.ToString('00'))_Zone1_Servers")
    $varPG4 = Get-VDPortgroup -Name ("Team$($i.ToString('00'))_Zone2_Clients-1")
    $varPG5 = Get-VDPortgroup -Name ("Team$($i.ToString('00'))_Zone3_Clients-2")
    $varPG6 = Get-VDPortgroup -Name ("Team$($i.ToString('00'))_Zone4_ICS-1")
    $varPG7 = Get-VDPortgroup -Name ("Team$($i.ToString('00'))_Zone5_ICS-2")
    $varPG8 = Get-VDPortgroup -Name ("Team$($i.ToString('00'))_Zone6_Landing")
    $varPG9 = Get-VDPortgroup -Name "Internet"
    Set-NetworkAdapter -NetworkAdapter $varNA[0] -Portgroup $varPG1 -Confirm:$false
    Set-NetworkAdapter -NetworkAdapter $varNA[1] -Portgroup $varPG2 -Confirm:$false
    Set-NetworkAdapter -NetworkAdapter $varNA[2] -Portgroup $varPG3 -Confirm:$false
    Set-NetworkAdapter -NetworkAdapter $varNA[3] -Portgroup $varPG4 -Confirm:$false
    Set-NetworkAdapter -NetworkAdapter $varNA[4] -Portgroup $varPG5 -Confirm:$false
    Set-NetworkAdapter -NetworkAdapter $varNA[5] -Portgroup $varPG6 -Confirm:$false
    Set-NetworkAdapter -NetworkAdapter $varNA[6] -Portgroup $varPG7 -Confirm:$false
    Set-NetworkAdapter -NetworkAdapter $varNA[7] -Portgroup $varPG8 -Confirm:$false
    Set-NetworkAdapter -NetworkAdapter $varNA[8] -Portgroup $varPG9 -Confirm:$false
}
```  

### Create multiple VMs in the same enclave  
This will generate VMs with the name Team18_JQR50,51.  The script generates errors, but still works.  

Download [Build-MultipleVMs.ps1](https://github.com/cmdcnd/RangeBuild/blob/main/Build-MultipleVMs.ps1)  

```powershell
.\Build-MultipleVMs.ps1 -TeamNumber "18" -StartVMNumber "50" -EndVMNumber "51" -VMRole "JQR" -VMTemplate "CPT171_Team18_JQR_student_template_v2ubuntu_24.04" -PortGroupZone "RangeJumpBoxes"
```  


### Run Invoke-Script on multiple systems  
```powershell
# This is the Range Team number, e.g. Team01, Team02, Team03.  
# You can also use regex "0[1-7]"  
$varRangeTeamNumber = "06"

# This is the machine type, e.g. WK, DC, FS
$varVMRole = "TL"

# Guest VM administrative credentials
$varGuestUser = "admin account"
$varGuestPassword = "admin password"

# Get all vms from the team number/role identified.  It is is wildcard search.  
$varVMs = (Get-VM ("Team" + $varRangeTeamNumber + "-" + $varVMRole + "*"))

$varCMD = @'
commands to run
'@

foreach ($varVM in $varVMs) {
Write-Host "Running script on $varVM " -ForeGroundColor Green
Invoke-VMScript -VM $varVM -ScriptText $varCMD -GuestUser $varGuestUser -GuestPassword $varGuestPassword -ScriptType bat | Out-Null
}
```

### Run Invoke-Script on multiple systems and replace values  
```powershell
# This is the Range Team number, e.g. Team01, Team02, Team03.  
# You can also use regex "0[1-7]"  
$varRangeTeamNumber = "10"

# This is the machine type, e.g. WK, DC, FS
$varVMRole = "DC"

# Guest VM administrative credentials
$varGuestUser = "admin account"
$varGuestPassword = "admin password"

# Get all vms from the team number/role identified.  It is is wildcard search.  
$varVMs = (Get-VM ("Team" + $varRangeTeamNumber + "-" + $varVMRole + "01"))

$varCMD = @'
# Import required module
Import-Module ActiveDirectory

# Get all AD Users
$users = Get-ADUser -Filter * -Properties HomeDirectory

foreach ($user in $users)
{
    if ($user.HomeDirectory)
    {
        # Extract the folder name from the HomeDirectory path
        $folderName = Split-Path -Leaf $user.HomeDirectory

        # Create the directory on the remote server
        $remotePath = "\\Team#TEAMNUMBER#-FS01\Home\$folderName"

        if (!(Test-Path -Path $remotePath))
        {
            New-Item -ItemType Directory -Path $remotePath
            Write-Output "Created directory: $remotePath"
        }
        else
        {
            Write-Output "Directory already exists: $remotePath"
        }
    }
}
'@
$varCMD = $varCMD.Replace("#TEAMNUMBER#", $varRangeTeamNumber)
foreach ($varVM in $varVMs) {
Write-Host "Running script on $varVM " -ForeGroundColor Green
Invoke-VMScript -VM $varVM -ScriptText $varCMD -GuestUser $varGuestUser -GuestPassword $varGuestPassword -ScriptType powershell | Out-Null
}
```  

### Enable/Disable vCenter accounts  
```powershell
Connect-SsoAdminServer -Server rangevcenter.cnd.ca.gov -User administrator@rangevsphere.local
```  

* -Enable $false disables accounts, $true enables accounts  
```powershell
Get-SsoPersonUser -Name blueteam* -Domain rangevsphere.local | Set-SsoPersonUser -Enable $true
```  

* Display current account status  
```powershell
Get-SsoPersonUser -Name blueteam* -Domain rangevsphere.local
```  

* Only enable/disable Redteam account when prepping for Cyber Dawn
```powershell
Get-SsoPersonUser -Name redteam -Domain rangevsphere.local | Set-SsoPersonUser -Enable $false
```  

* Display current account status
```powershell
Get-SsoPersonUser -Name * -Domain rangevsphere.local
```  

