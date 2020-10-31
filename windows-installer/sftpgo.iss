#define MyAppName "SFTPGo"
#if GetEnv("SFTPGO_ISS_VERSION") != ""
    #define MyAppVersion GetEnv("SFTPGO_ISS_VERSION")
#else
    #define MyAppVersion "v0.0.0"
#endif
#define MyAppURL "https://github.com/drakkan/sftpgo"
#define MyVersionInfo StringChange(MyAppVersion,"v","")
#if GetEnv("SFTPGO_ISS_DOC_URL") != ""
    #define DocURL GetEnv("SFTPGO_ISS_DOC_URL")
#else
    #define DocURL "https://github.com/drakkan/sftpgo/blob/master/README.md"
#endif
#define MyAppExeName "sftpgo.exe"
#define MyAppDir "..\output"
#define MyOutputDir ".."

[Setup]
AppId={{1FB9D57F-00DD-4B1B-8798-1138E5CE995D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
LicenseFile={#MyAppDir}\LICENSE.txt
OutputDir={#MyOutputDir}
OutputBaseFilename=sftpgo_windows_x86_64
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
ArchitecturesAllowed=x64
MinVersion=6.1
VersionInfoVersion={#MyVersionInfo}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#MyAppDir}\sftpgo.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#MyAppDir}\sftpgo.db"; DestDir: "{commonappdata}\{#MyAppName}"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "{#MyAppDir}\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#MyAppDir}\sftpgo.json"; DestDir: "{commonappdata}\{#MyAppName}"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "{#MyAppDir}\sftpgo_api_cli.exe"; DestDir: "{app}\examples\rest-api-cli"; Flags: ignoreversion; MinVersion: 10
Source: "{#MyAppDir}\templates\*"; DestDir: "{commonappdata}\{#MyAppName}\templates"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#MyAppDir}\static\*"; DestDir: "{commonappdata}\{#MyAppName}\static"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
Name: "{commonappdata}\{#MyAppName}\logs"; Permissions: everyone-full
Name: "{commonappdata}\{#MyAppName}\backups"; Permissions: everyone-full
Name: "{commonappdata}\{#MyAppName}\credentials"; Permissions: everyone-full

[Icons]
Name: "{group}\Web Admin"; Filename: "http://127.0.0.1:8080/web";
Name: "{group}\Service Control";  WorkingDir: "{app}"; Filename: "powershell.exe"; Parameters: "-Command ""Start-Process cmd \""/k cd {app} & {#MyAppExeName} service --help\"" -Verb RunAs"; Comment: "Manage SFTPGo Service"
Name: "{group}\REST API CLI";  WorkingDir: "{app}\examples\rest-api-cli"; Filename: "{cmd}"; Parameters: "/k sftpgo_api_cli.exe --help"; Comment: "Manage users, folders and connections"; MinVersion: 10
Name: "{group}\Documentation"; Filename: "{#DocURL}";
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"

[Run]
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=""SFTPGo Service"""; Flags: runhidden
Filename: "netsh"; Parameters: "advfirewall firewall add rule name=""SFTPGo Service"" dir=in action=allow program=""{app}\{#MyAppExeName}"""; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "service stop"; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "service uninstall"; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "service install -c ""{commonappdata}\{#MyAppName}"" -l ""logs\sftpgo.log"""; Description: "Install SFTPGo Windows Service"; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "service start";  Description: "Start SFTPGo Windows Service"; Flags: runhidden

[UninstallRun]
Filename: "{app}\{#MyAppExeName}"; Parameters: "service stop"; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "service uninstall"; Flags: runhidden
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=""SFTPGo Service"""; Flags: runhidden
