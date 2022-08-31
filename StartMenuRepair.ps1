#Requires -RunAsAdministrator

# Variables for Registry-Access Rule
$IdentityReference = [System.Security.Principal.SecurityIdentifier]("AC")   
$RegistryRights = [System.Security.AccessControl.RegistryRights]"ReadKey"
$Inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
$Propagation = [System.Security.AccessControl.PropagationFlags]"None"
$AccessType = [System.Security.AccessControl.AccessControlType]"Allow"
$Rule = New-Object System.Security.AccessControl.RegistryAccessRule($IdentityReference,$RegistryRights,$Inheritance,$Propagation,$AccessType)

$folders = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'

# Set new ACLs for broken Registry Keys
function RepairRegRights
{
    foreach ($folder in $folders)
    {
        # Read Ruleset
        $ACL = Get-Acl $folder

        # Add new Rule 
        try 
        {
            $ACL.AddAccessRule($Rule)
            $ACL | Set-Acl
            Write-Host "registry key updated"    
        }
        catch 
        {
            {Write-Host "registry couldn't be updated"}
        }

    }
}

# Reinstall all AppX-Packages if param -appx is given when starting the script
function RepairAppXPackages 
{
    $isRepairNeeded = $args[0]

    if ($isRepairNeeded -like "-appx")
    {
        try 
        {
            Get-AppXPackage -AllUsers | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
        }
        catch 
        {
            {Write-Host "skipped package"}
        }
    }
    
    else 
    {
        Write-Host "skipped AppX-repair"
    }
} 

# Initial Warning about the PC restart after running the script
Read-Host "
script for repairing a broken windows start menu / login into office applications
after repairing, the pc is about to restart, press 'enter' to start the repair"

# Call Functions for Registry + AppXPackages
RepairRegRights
RepairAppXPackages $args[0]

# Perform Restart
Write-Host 'restart in 10 sec...'
shutdown /r /t 10 /f                   
