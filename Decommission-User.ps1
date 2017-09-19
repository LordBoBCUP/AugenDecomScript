﻿#==================================================================================================================
#  https://github.com/LordBoBCUP/
#==================================================================================================================
#  Filename:        Decommission-User.ps1
#  Author:          Alex massey
#  Version:         1.01
#  Last Modified:   19-09-2017
#  Description:     Decommission users based on a list provided in a csv format
#                   Helps administrators be consistent with decommissioning processes to ensure the security
#                   of the active directory domains is maintained to the highest standard
#  Permissions:     Domain Administrator, CSAdministrator (Lync), Organizational Management (Exchange)
#
#                   NOTE - Please adjust lines 25-35 for your environment.
#
#                   Comments and suggestions always welcome!  alex.massey@augensoftwaregroup.com
#
#==================================================================================================================

#==================================================================================================================
#  Import Modules Required
#==================================================================================================================
Import-Module ActiveDirectory

#==================================================================================================================
#  Defined Variables
#==================================================================================================================
$DomainController = "zeus.augen.co.nz"
$DMZDomainController = "juliet.augen.co.nz"
$VNDomainController = "vndc.augensoftwaregroup.com"
$ExchangeServer = "http://zeus.augen.co.nz"
$LyncServer ="https://Lync02.augen.co.nz"
$FormerEmployeeOU = "OU=FormerAugeneersNZ,OU=FormerEmployees,OU=Users,OU=Augenland,DC=augen,DC=co,DC=nz"
$DMZFormerEmployeeOU = "OU=NZ,OU=FormerAugeneer,OU=Users,OU=Augen-DMZ,DC=dmz,DC=local"
$VNFormerEmployeeOU = "OU=NZ,OU=FormerAugeneers,OU=Users,OU=AugenVN,DC=augensoftwaregroup,DC=com"
$HomeDrivePath = "\\Umbriel.augen.co.nz\Staff\"
$InputList = "C:\Temp\Users.csv"
$DMZCredentials = 0
$VNCredentials = 0
Write-Host "Here"
#==================================================================================================================
#  Create Sessions to Domain Resources
#==================================================================================================================
Write-Verbose "Connecting to Powershell Sessions on remote platforms"
$ExchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "$ExchangeServer/PowerShell" -Authentication Kerberos 
$LyncSession = New-PSSession -ConnectionUri "$lyncServer/ocsPowershell" -Authentication NegotiateWithImplicitCredential

#==================================================================================================================
#  Create Domain Resource Credentials
#==================================================================================================================
Write-Verbose "Prompting for other domain credentials"
$DMZCredentials = Get-Credential -Message "Please enter your full DMZ Domain credentials" -UserName $ENV:USERNAME@dmz.local
$VNCredentials = Get-Credential -Message "Please enter your full Vietnam Domain Credentials" -Username $ENV:USERNAME@augensoftwaregroup.com.vn

#==================================================================================================================
#  Script
#==================================================================================================================
Write-Verbose "Testing Input file path otherwise exiting with error code 1"

if (!(Test-Path -Path $InputList)) {
    Write-Host -ForegroundColor Red "The inputlist parameter was not found"
    exit 1
} 

$Users = Get-Content -Path $InputList

if ($users.Length -eq 0) {
    Write-Host -ForegroundColor Red "There were no users in the file"
    exit 1
}

Import-PSSession $ExchangeSession
Import-PSSession $LyncSession

# Do the heavy lifting
foreach ($user in $Users) {
    Write-Host "Processing User: $user"
    Write-Verbose "Processing user: $user - $Users.Length"
    $VNUser = $True
    $DMZUser = $True
    # Get DN of Users for each domain
    $AugenUserDN = (Get-ADUser -Identity $user -Server zeus.augen.co.nz).DistinguishedName
    try {
        $DMZUserDN = (Get-ADUser -Identity $user -Server Juliet.dmz.local -Credential $DMZCredentials).DistinguishedName
    } catch {
        Write-Host "No Account found in the DMZ Domain"
        $DMZUser = $false
    }
    try {
        $VNUserDN = (Get-ADUser -Identity $user -Server Juliet.dmz.local -Credential $VNCredentials).DistinguishedName
    } catch {
        $VNUser = $false
        Write-Host "No Account found in the VN Domain"
    }

    # Disable Account in each domain
    Disable-ADAccount -Identity $AugenUserDN -Server $DomainController
    if ($DMZUser) {
        Disable-ADAccount -Identity $DMZUserDN -Server $DMZDomainController -Credential $DMZCredentials
    }
    if ($VNUser){
        Disable-ADAccount -Identity $VNUserDN -Server $VNDomainController -Credential $VNCredentials
    }

    # Move AD Account to Former User OU
    Move-ADObject -Identity $AugenUserDN -TargetPath $FormerEmployeeOU -Server $DomainController
    if ($DMZUser) {
        Move-ADObject -Identity $DMZUserDN -TargetPath $DMZFormerEmployeeOU -Server $DMZDomainController
    }
    if ($VNUser) {
        Move-ADObject -Identity $VNUserDN -TargetPath $VNFormerEmployeeOU -Server $VNDomainController
    }

    # Get new DN as original one has now been moved
    $AugenUserDN = (Get-ADUser -Identity $user -Server zeus.augen.co.nz).DistinguishedName
    if ($DMZUser) {
        $DMZUserDN = (Get-ADUser -Identity $user -Server Juliet.dmz.local -Credential $DMZCredentials).DistinguishedName
    }
    if ($VNUser) {
        $VNUserDN = (Get-ADUser -Identity $user -Server Juliet.dmz.local -Credential $VNCredentials).DistinguishedName
    }
    # Remove Existing Group Membership 
    $groups = Get-ADUser -Identity $AugenUserDN -Properties memberof -Server $DomainController
    write-host $groups
    if (!($groups.MemberOf.Count -eq 0)) {
    write-host "Number of Groups = $($groups.memberof.count)"
        foreach ($group in $groups.memberof) {
            if (!($group -eq "Domain Users")) {
                Remove-ADGroupMember $group -Members $AugenUserDN -confirm:$false
            }
        }
    }
    if ($DMZUser) {
        $groups = Get-ADUser -Identity $DMZUserDN -Properties memberof -Server $DMZDomainController
        if (!($groups.MemberOf.Count -eq 0)) {
            foreach ($group in $groups.memberof) {
                if (!($group -eq "Domain Users")) {
                    Remove-ADGroupMember $group -Members $AugenUserDN -confirm:$false
                }
            }
        }
    }
    if ($VNUser) {
        $groups = Get-ADUser -Identity $VNUserDN -Properties memberof -Server $VNDomainController | Remove-ADGroupMember -Members $VNUserDN | Where-Object {$_.Name -ne "Domain Users"}
        if (!($groups.MemberOf.Count -eq 0)) {
            foreach ($group in $groups.memberof) {
                if (!($group -eq "Domain Users")) {
                    Remove-ADGroupMember $group -Members $AugenUserDN -confirm:$false
                }
            }
        }
    }

    # Rename Mailbox
    $DisplayName = Get-ADUser -Identity $AugenUserDN
    Set-Mailbox -Identity $AugenUserDN -DisplayName "Former Employee - $($DisplayName.Name)"
    Remove-PSSession $ExchangeSession

    # Disable Lync Account
    $SIPAddress = Get-ADUser -Identity $AugenUserDN -properties proxyaddresses | Select -ExpandProperty proxyaddresses | Select-String -Pattern "SIP:"
    Disable-CSUser -Identity $SIPAddress
    Remove-PSSession $LyncSession

    # Move Home Drive
    if (Test-Path -Path $HomeDrivePath\(Get-ADUser -Identity $AugenUserDN).Name) {
        Move-Item -Path "$HomeDrivePath\(Get-ADUser -Identity $AugenUserDN).Name" -Destination "$HomeDrivePath\FormerEmployees\(Get-ADUser -Identity $AugenUserDN).Name"
    }


}

Remove-PSSession $ExchangeSession
Remove-PSSession $LyncSession
