$ErrorActionPreference  = 'Stop'
$packageName    = 'sftpgo'
$softwareName   = 'SFTPGo'
$url            = 'https://github.com/drakkan/sftpgo/releases/download/v2.3.6/sftpgo_v2.3.6_windows_x86_64.exe'
$checksum       = 'A0247EE43FECC7D54504D0638631FAEFB223EF00FD2B10EEE988A2CCC9A014EA'
$silentArgs     = '/VERYSILENT'
$validExitCodes = @(0)

$packageArgs = @{
  packageName   = $packageName
  fileType      = 'exe'
  file          = $fileLocation
  url           = $url
  checksum      = $checksum
  checksumType  = 'sha256'
  silentArgs    = $silentArgs
  validExitCodes= $validExitCodes
  softwareName  = $softwareName
}

Install-ChocolateyPackage @packageArgs

$DefaultDataPath = Join-Path -Path $ENV:ProgramData -ChildPath "SFTPGo"
$DefaultConfigurationFilePath = Join-Path -Path $DefaultDataPath -ChildPath "sftpgo.json"
$EnvDirPath = Join-Path -Path $DefaultDataPath -ChildPath "env.d"

# `t = tab
Write-Output "---------------------------"
Write-Output ""
Write-Output "If you have never used SFTPGo before, the web administration panel is located here:"
Write-Output "`thttp://localhost:8080/web/admin"
Write-Output ""
Write-Output "Default web administration port:"
Write-Output "`t8080"
Write-Output "Default SFTP port:"
Write-Output "`t2022"
Write-Output ""
Write-Output "Default data location:"
Write-Output "`t$DefaultDataPath"
Write-Output "Default configuration file location:"
Write-Output "`t$DefaultConfigurationFilePath"
Write-Output "Directory to create environment variable files to set custom configurations:"
Write-Output "`t$EnvDirPath"
Write-Output "If the SFTPGo service does not start, make sure that TCP ports 2022 and 8080 are"
Write-Output "not used by other services or change the SFTPGo configuration to suit your needs."
Write-Output ""
Write-Output "General information (README) location:"
Write-Output "`thttps://github.com/drakkan/sftpgo"
Write-Output "Getting started guide location:"
Write-Output "`thttps://github.com/drakkan/sftpgo/blob/v2.3.6/docs/howto/getting-started.md"
Write-Output "Detailed information (docs folder) location:"
Write-Output "`thttps://github.com/drakkan/sftpgo/tree/v2.3.6/docs"
Write-Output ""
Write-Output "---------------------------"