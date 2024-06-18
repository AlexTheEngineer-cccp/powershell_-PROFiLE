exit

#region profile
mkdir c:\Scripts
New-Item -Path $profile -Force
@'
psedit C:\Scripts\0.ps1
'@  | Out-File -FilePath $profile -Force


@'
$isPriviliged = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
if($isPriviliged ){$root = "#"}else{$root = "$"}
$prpt = "$root>"
function prompt {     
    Write-Host "$((Get-Date).ToString("hh:mm:ss"))" -NoNewLine -ForegroundColor Gray 
    Write-Host " $($($env:COMPUTERNAME))"           -NoNewLine -ForegroundColor Cyan 
    Write-Host " $(Get-Location) $prpt"             -NoNewLine -ForegroundColor White 
    return " " 
}

if ($isPriviliged)
{
    $host.ui.RawUI.WindowTitle = "Administrator: $($env:COMPUTERNAME) $($env:USERDOMAIN)/$($env:USERNAME)"
}
else
{
    $host.ui.RawUI.WindowTitle = "$($env:COMPUTERNAME) $($env:USERDOMAIN)/$($env:USERNAME)"
}

$psISE.Options.SelectedScriptPaneState = 'Right'
#$psISE.PowerShellTabs.VerticalAddOnTools.IsVisible = $false
'@ | Out-File -FilePath $profile -Append

#endregion profile

#region initial network settings
New-NetIPAddress `
    -InterfaceAlias 'Ethernet' `
    -IPAddress      192.168.216.217 `
    -DefaultGateway 192.168.216.254 `
    -PrefixLength   24

Set-DnsClientServerAddress `
    -InterfaceAlias Ethernet `
    -ServerAddresses @('192.168.200.8','192.168.200.7')

Set-DnsClientGlobalSetting `
    -SuffixSearchList @('int.atosbox.ru')
#endregion initial network settings

#region  time zone
tzutil /s "Russian Standard Time"
#endregion  time zone

#region  time zone add russian input method
$ll = New-WinUserLanguageList -Language "en-US"
$ll.add("ru-RU")
Set-WinUserLanguageList -LanguageList $ll -Force

Set-WinSystemLocale -SystemLocale ru-RU; Restart-Computer
#endregion  time zone add russian input method


#region Enable RDP
set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name 'fDenyTSConnections' -Value 0
Enable-NetFirewallRule -Name "RemoteDesktop-UserMode-In-TCP"
#Disable NLA
(Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -ComputerName $env:ComputerName -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)
#endregion 

#region rename comuter & domain join
Rename-Computer -NewName $thisHost -Restart 

$cr = Get-Credential mw1b5561@int.atosbox.ru
Add-Computer `
    -DomainName 'int.atosbox.ru' `
    -Credential $cr `
    -Restart   `
    -OUPath     "OU=DefaultPolicy,OU=Servers,DC=int,DC=atosbox,DC=ru" 
#endregion 

#region File Explorer tweaks 
function SetDwordHKCUpath { 
    param($path, $name, $value) 
    try{ 
        if (-not (Test-Path $path)) { New-Item -Path $path -Verbose} 
        if( Get-ItemProperty -path $path -Name $name -ErrorAction Stop -Verbose ) 
        { 
            Set-ItemProperty -Path $path -Name $name -Value $value -Verbose 
        } 
    } 
    catch{ 
        New-ItemProperty -Path $path -Name $name -Value $value -PropertyType DWord  -Verbose 
    }  
} 
SetDwordHKCUpath -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -name Hidden               -value 1  
SetDwordHKCUpath -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -name ShowSuperHidden      -value 1  
SetDwordHKCUpath -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -name HideFileExt          -value 0 
SetDwordHKCUpath -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -name TaskbarSmallIcons    -value 1
SetDwordHKCUpath -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -name TaskbarGlomLevel     -value 2
SetDwordHKCUpath -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -name AllItemsIconView -value 1 
SetDwordHKCUpath -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -name StartupPage      -value 1 
SetDwordHKCUpath -path HKCU:\Software\Microsoft\ServerManager -name DoNotOpenServerManagerAtLogon -value 1
SetDwordHKCUpath -path HKCU:\Software\Microsoft\Windows\DWM   -name ColorPrevalence               -value 1  

REG LOAD HKU\DefaultUser "$env:systemdrive\Users\Default\NTUSER.DAT" 
REG ADD HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /d 1 /t REG_DWORD /f 
REG ADD HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /d 1 /t REG_DWORD /f 
REG ADD HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideFileExt /d 0 /t REG_DWORD /f 
REG ADD HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel /v AllItemsIconView /d 1 /t REG_DWORD /f 
REG ADD HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel /v StartupPage /d 1 /t REG_DWORD /f 
REG UNLOAD HKU\DefaultUser 
#endregion File Explorer tweaks 

 

 
#region Powershell ISE icon on taskbar
@' 
<?xml version="1.0" encoding="utf-8"?> 
<LayoutModificationTemplate 
    xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification" 
    xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" 
    xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" 
    xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" 
    Version="1"> 
  <CustomTaskbarLayoutCollection> 
    <defaultlayout:TaskbarLayout> 
      <taskbar:TaskbarPinList> 
          <taskbar:DesktopApp DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell ISE.lnk"/> 
      </taskbar:TaskbarPinList> 
    </defaultlayout:TaskbarLayout> 
  </CustomTaskbarLayoutCollection> 
</LayoutModificationTemplate> 
'@ | 
Out-File -FilePath "$env:TEMP\taskbar.iSE.xml" -Encoding ascii -Force 
Import-StartLayout "$env:TEMP\taskbar.iSE.xml" -MountPath c:\  
rm "$env:TEMP\taskbar.iSE.xml"

 [System.IO.FileInfo] $LinkFile = "$($env:APPDATA)\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell ISE.lnk"

$tempFileName = [IO.Path]::GetRandomFileName()
$tempFile = [IO.FileInfo][IO.Path]::Combine($LinkFile.Directory, $tempFileName)
        
$writer = new-object System.IO.FileStream $tempFile, ([System.IO.FileMode]::Create)
$reader = $LinkFile.OpenRead()
        
while ($reader.Position -lt $reader.Length)
{        
    $byte = $reader.ReadByte()
    if ($reader.Position -eq 22) {
        $byte = 34
    }
    $writer.WriteByte($byte)
}
        
$reader.Close()
$writer.Close()
        
$LinkFile.Delete()
        
Rename-Item -Path $tempFile -NewName $LinkFile.Name

Get-Process explorer| Stop-Process -Force; Start-Process explorer 
#endregion Powershell ISE icon on taskbar

#region psWindowsUpdate
Install-PackageProvider -Name NuGet -Force
install-Module psWindowsUpdate -Force -Verbose
Install-WindowsUpdate -Verbose -MicrosoftUpdate -AcceptAll -Install -AutoReboot -RecurseCycle 3

workflow temp {
    param ([string[]]$servers)     
    foreach -parallel ($i in $servers)    
    {
        inlinescript {        
            Install-WindowsUpdate -Verbose -MicrosoftUpdate -AcceptAll -Install -AutoReboot
        } -PSComputerName $i    
    }    
}
temp -servers $db.hostname

#endregion psWindowsUpdate

Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore
Dism.exe /Online /Cleanup-Image /StartComponentCleanup
Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase

function Disable-ieESC
{
    $AdminKey = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}'
    $UserKey =  'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}'
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
    Stop-Process -Name Explorer
    Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green
}

Disable-ieESC
