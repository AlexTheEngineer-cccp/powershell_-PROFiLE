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
          <taskbar:DesktopApp DesktopApplicationLinkPath="C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell ISE.lnk"/> 
      </taskbar:TaskbarPinList> 
    </defaultlayout:TaskbarLayout> 
  </CustomTaskbarLayoutCollection> 
</LayoutModificationTemplate> 
'@ | 
Out-File -FilePath "$env:TEMP\taskbar.iSE.xml" -Encoding utf8 -Force 
Import-StartLayout "$env:TEMP\taskbar.iSE.xml" -MountPath c:\  
rm "$env:TEMP\taskbar.iSE.xml"

#[System.IO.FileInfo] $LinkFile = "$($env:APPDATA)\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell ISE.lnk"
[System.IO.FileInfo] $LinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell ISE.lnk"


# Test-Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell ISE.lnk"



$tempFileName = [IO.Path]::GetRandomFileName()
$tempFile = [IO.FileInfo][IO.Path]::Combine($LinkFile.Directory, $tempFileName)
        
$writer = new-object System.IO.FileStream $tempFile, ([System.IO.FileMode]::Create)
$reader = $LinkFile.OpenRead()
        
while ($reader.Position -lt $reader.Length)
{        
    $byte = $reader.ReadByte()
    # "$($reader.Position) `t $byte"
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
