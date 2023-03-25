
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Install-WindowsFeature -Name RSAT-AD-PowerShell
Install-WindowsFeature -Name RSAT-ADDS
Install-WindowsFeature -Name RSAT-DNS-Server
Install-WindowsFeature -Name RSAT-DHCP-Server

Install-WindowsFeature -Name DNS -IncludeManagementTools
Install-WindowsFeature -Name DHCP -IncludeManagementTools

Install-ADDSForest -DomainName evil.labo -DomainNetbiosName evil -SafeModeAdministratorPassword (ConvertTo-SecureString -AsPlainText "azerty" -Force) -Force

New-ADOrganizationalUnit -Name "Direction" -Path "DC=evil,DC=labo"
New-ADOrganizationalUnit -Name "Pedagogie" -Path "DC=evil,DC=labo"
New-ADOrganizationalUnit -Name "Administratif" -Path "DC=evil,DC=labo"
New-ADOrganizationalUnit -Name "Intervenants" -Path "DC=evil,DC=labo"
New-ADOrganizationalUnit -Name "Auditeurs 1" -Path "DC=evil,DC=labo"
New-ADOrganizationalUnit -Name "Auditeurs 2" -Path "DC=evil,DC=labo"

New-ADUser -Name "Rick" -GivenName "Rick" -Surname "Sanchez" -SamAccountName "Rick" -UserPrincipalName "Rick" -Path "OU=Direction,DC=evil,DC=labo" -AccountPassword (ConvertTo-SecureString -AsPlainText "azerty" -Force) -Enabled $true
New-ADUser -Name "Morty" -GivenName "Morty" -Surname "Smith" -SamAccountName "Morty" -UserPrincipalName "Morty" -Path "OU=Direction,DC=evil,DC=labo" -AccountPassword (ConvertTo-SecureString -AsPlainText "azerty" -Force) -Enabled $true
New-ADUser -Name "Summer" -GivenName "Summer" -Surname "Smith" -SamAccountName "Summer" -UserPrincipalName "Summer" -Path "OU=Direction,DC=evil,DC=labo" -AccountPassword (ConvertTo-SecureString -AsPlainText "azerty" -Force) -Enabled $true

New-ADUser -Name "Franck" -GivenName "Franck" -Surname "Nicolas" -SamAccountName "Franck" -UserPrincipalName "Franck" -Path "OU=Pedagogie,DC=evil,DC=labo" -AccountPassword (ConvertTo-SecureString -AsPlainText "azerty" -Force) -Enabled $true
New-ADUser -Name "Nicolas" -GivenName "Nicolas" -Surname "Nicolas" -SamAccountName "Nicolas" -UserPrincipalName "Nicolas" -Path "OU=Pedagogie,DC=evil,DC=labo" -AccountPassword (ConvertTo-SecureString -AsPlainText "azerty" -Force) -Enabled $true
New-ADUser -Name "Jean" -GivenName "Jean" -Surname "Jean" -SamAccountName "Jean" -UserPrincipalName "Jean" -Path "OU=Pedagogie,DC=evil,DC=labo" -AccountPassword (ConvertTo-SecureString -AsPlainText "azerty" -Force) -Enabled $true

New-ADUser -Name "Romain" -GivenName "Romain" -Surname "Hugues" -SamAccountName "Romain" -UserPrincipalName "Romain" -Path "OU=Administratif,DC=evil,DC=labo" -AccountPassword (ConvertTo-SecureString -AsPlainText "azerty" -Force) -Enabled $true
New-ADUser -Name "Hugues" -GivenName "Hugues" -Surname "Hugues" -SamAccountName "Hugues" -UserPrincipalName "Hugues" -Path "OU=Administratif,DC=evil,DC=labo" -AccountPassword (ConvertTo-SecureString -AsPlainText "azerty" -Force) -Enabled $true
New-ADUser -Name "Paul" -GivenName "Paul" -Surname "Paul" -SamAccountName "Paul" -UserPrincipalName "Paul" -Path "OU=Administratif,DC=evil,DC=labo" -AccountPassword (ConvertTo-SecureString -AsPlainText "azerty" -Force) -Enabled $true

New-ADGroup -Name "Intervenants" -GroupScope
New-ADGroup -Name "Auditeurs 1" -GroupScope
New-ADGroup -Name "Auditeurs 2" -GroupScope

Add-ADGroupMember -Identity "Intervenants" -Members "Intervenant1","Intervenant2","Intervenant3","Intervenant4","Intervenant5","Intervenant6","Intervenant7","Intervenant8","Intervenant9","Intervenant10"
Add-ADGroupMember -Identity "Auditeurs 1" -Members "Auditeur1","Auditeur2","Auditeur3","Auditeur4","Auditeur5","Auditeur6","Auditeur7","Auditeur8","Auditeur9","Auditeur10","Auditeur11","Auditeur12","Auditeur13","Auditeur14","Auditeur15","Auditeur16","Auditeur17","Auditeur18","Auditeur19","Auditeur20","Auditeur21","Auditeur22","Auditeur23","Auditeur24","Auditeur25","Auditeur26","Auditeur27","Auditeur28","Auditeur29","Auditeur30"
Add-ADGroupMember -Identity "Auditeurs 2" -Members "Auditeur31","Auditeur32","Auditeur33","Auditeur34","Auditeur35","Auditeur36","Auditeur37","Auditeur38","Auditeur39","Auditeur40","Auditeur41","Auditeur42","Auditeur43","Auditeur44","Auditeur45","Auditeur46","Auditeur47","Auditeur48","Auditeur49","Auditeur50","Auditeur51","Auditeur52","Auditeur53","Auditeur54","Auditeur55","Auditeur56","Auditeur57","Auditeur58","Auditeur59","Auditeur60"

New-DnsServerPrimaryZone -Name "evil.labo" -ZoneFile "evil.labo.dns" -DynamicUpdate "Secure" -Reverse $true -MasterServers "srv-1.evil.labo" -ReplicationScope "Forest" -AllowUpdate $true -AllowTransfer $true -AllowQuery $true -AllowRecursion $true -AllowZoneTransfer $true -Confirm:$false

New-DhcpServerv4Scope -Name "evil.labo" -StartRange "192.168.100.10" -EndRange "192.168.100.180" -SubnetMask "255.255.255.0" -Gateway "192.168.100.254" -LeaseDuration "1.00:00:00" -ScopeId "1" -Confirm:$false

Add-DnsServerResourceRecordA -Name "srv-1" -ZoneName "evil.labo" -IPv4Address "192.168.100.251" -Ttl 3600
Add-DnsServerResourceRecordA -Name "srv-2" -ZoneName "evil.labo" -IPv4Address "192.168.100.252" -Ttl 3600
Add-DnsServerResourceRecordA -Name "srv-3" -ZoneName "evil.labo" -IPv4Address "192.168.100.254" -Ttl 3600

New-DhcpServerv4Reservation -ComputerName "srv-1" -ScopeId "1" -IPAddress "192.168.100.251" -Description "srv-1" -Confirm:$false
New-DhcpServerv4Reservation -ComputerName "srv-2" -ScopeId "1" -IPAddress "192.168.100.252" -Description "srv-2" -Confirm:$false
New-DhcpServerv4Reservation -ComputerName "srv-3" -ScopeId "1" -IPAddress "192.168.100.254" -Description "srv-3" -Confirm:$false

Rename-Computer -NewName "srv-1" -Restart -Force