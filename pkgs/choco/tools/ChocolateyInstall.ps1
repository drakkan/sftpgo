$ErrorActionPreference  = 'Stop'
$packageName    = 'gonas'
$softwareName   = 'GoNAS'
$url            = 'https://github.com/xrogers/gonas/releases/download/v2.7.6/gonas_v2.7.6_windows_x86_64.exe'
$checksum       = '63D29355DBCB7690BA1A2F58A4F8E6DB4320275C056E9D48141D258204BEC31B'
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

$DefaultDataPath = Join-Path -Path $ENV:ProgramData -ChildPath "GoNAS"
$DefaultConfigurationFilePath = Join-Path -Path $DefaultDataPath -ChildPath "gonas.json"
$EnvDirPath = Join-Path -Path $DefaultDataPath -ChildPath "env.d"

# `t = tab
Write-Output "---------------------------"
Write-Output ""
Write-Output "If you have never used GoNAS before, the web administration panel is located here:"
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
Write-Output "If the GoNAS service does not start, make sure that TCP ports 2022 and 8080 are"
Write-Output "not used by other services or change the GoNAS configuration to suit your needs."
Write-Output ""
Write-Output "General information:"
Write-Output "`thttps://github.com/xrogers/gonas"
Write-Output "Documentation location:"
Write-Output "`thttps://github.com/xrogers/gonas"
Write-Output ""
Write-Output "---------------------------"