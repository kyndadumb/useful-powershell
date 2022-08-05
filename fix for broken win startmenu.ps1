#Requires -RunAsAdministrator

function WriteRegRights
{
    $ACLValue = $args[0]
    $RuleValue = $args[1]
    
    try
    {    
        $ACLValue.AddAccessRule($RuleValue)                                          
        $ACLValue | Set-Acl
        Write-Host 'Updated registry permissions'
    }
    
    catch{ Write-Host 'Error...Update failed'}
}

Read-Host '
Bugfix for broken Windows start menu or bug when trying to login to O365 applications. The PC is restarted automatically.
Press "Enter" to start the repair:'

$IdentityReference = [System.Security.Principal.SecurityIdentifier]("AC")   
$RegistryRights = [System.Security.AccessControl.RegistryRights]"ReadKey"
$Inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
$Propagation = [System.Security.AccessControl.PropagationFlags]"None"
$AccessType = [System.Security.AccessControl.AccessControlType]"Allow"
$Rule = New-Object System.Security.AccessControl.RegistryAccessRule($IdentityReference,$RegistryRights,$Inheritance,$Propagation,$AccessType)

$Folder = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
$Acl = Get-Acl $Folder

WriteRegRights $acl $Rule

$Folder = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
$Acl = Get-Acl $Folder

WriteRegRights $acl $Rule

Get-AppXPackage -AllUsers | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}

Write-Host 'Restart in 10 Sek...'
shutdown /r /t 10 /f                   