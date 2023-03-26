Import-Module GroupPolicy
$gpo1 = New-GPO -Name "Printer Restrictions"
Set-GPPermissions -Guid $gpo1.Id -TargetName "Authenticated Users" -TargetType Group -PermissionLevel GpoApply -Inherited Yes
Set-GPRegistryValue -Guid $gpo1.Id -Key "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoAddPrinter" -Type DWORD -Value 1
Set-GPRegistryValue -Guid $gpo1.Id -Key "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoDeletePrinter" -Type DWORD -Value 1

# Create the second GPO to deny users from changing the wallpaper
$gpo2 = New-GPO -Name "Wallpaper Restrictions"
Set-GPPermissions -Guid $gpo2.Id -TargetName "Authenticated Users" -TargetType Group -PermissionLevel GpoApply -Inherited Yes
Set-GPRegistryValue -Guid $gpo2.Id -Key "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "Wallpaper" -Type String -Value "C:\Windows\Web\Wallpaper\Windows\img0.jpg"
Set-GPRegistryValue -Guid $gpo2.Id -Key "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "WallpaperStyle" -Type String -Value "0"

# Link the GPOs to the "Auditeurs 1" and "Auditeurs 2" OUs
$ou1 = Get-ADOrganizationalUnit -Identity "OU=Auditeurs 1,DC=evil,DC=labo"
$ou2 = Get-ADOrganizationalUnit -Identity "OU=Auditeurs 2,DC=evil,DC=labo"
New-GPLink -Name "Printer Restrictions" -Target $ou1
New-GPLink -Name "Printer Restrictions" -Target $ou2
New-GPLink -Name "Wallpaper Restrictions" -Target $ou1
New-GPLink -Name "Wallpaper Restrictions" -Target $ou2

