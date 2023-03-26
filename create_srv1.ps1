# a lancer a la main avant le script: Rename-Computer -NewName "srv-1" -Restart
$ip = "192.168.100.251"
$mask = "255.255.255.0"
$gw = "192.168.100.254"
$dns = "192.168.100.251"
$nic = Get-NetAdapter -Name "Ethernet"
$nic | Set-NetIPInterface -Dhcp Disabled
$nic | New-NetIPAddress -IPAddress $ip -PrefixLength 24 -DefaultGateway $gw
$nic | Set-DnsClientServerAddress -ServerAddresses $dns

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Install-WindowsFeature -Name DNS -IncludeManagementTools
Install-WindowsFeature -Name DHCP -IncludeManagementTools

Install-ADDSForest -DomainName evil.labo -DomainNetbiosName evil -SafeModeAdministratorPassword (ConvertTo-SecureString -AsPlainText "Passw0rd@123" -Force) -Force
