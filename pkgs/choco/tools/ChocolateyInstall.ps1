﻿$ErrorActionPreference  = 'Stop'
$packageName    = 'sftpgo'
$softwareName   = 'SFTPGo'
$url            = 'https://github.com/drakkan/sftpgo/releases/download/v2.7.0/sftpgo_v2.7.0_windows_x86_64.exe'
$checksum       = 'E091845514444E93F7FD4C89888E418FCEEC5A38D7D7FE7DA7A8F8B65D36E51F'
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
Write-Output "General information:"
Write-Output "`thttps://sftpgo.com"
Write-Output "Documentation location:"
Write-Output "`thttps://docs.sftpgo.com/"
Write-Output ""
Write-Output "---------------------------"