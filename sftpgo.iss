; Script used to generate SFTPGo's Windows setup
; You need to change the paths for the source files to match your environment

#define MyAppName "SFTPGo"
#define MyAppVersion "0.9.4-dev"
#define MyAppURL "https://github.com/drakkan/sftpgo"
#define MyAppExeName "sftpgo.exe"
#define MyAppDir "C:\Users\vbox\Desktop\sftpgo_setup"
#define MyOutputDir "C:\Users\vbox\Desktop"

[Setup]
; NOTE: The value of AppId uniquely identifies this application. Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppId={{1FB9D57F-00DD-4B1B-8798-1138E5CE995D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
;AppVerName={#MyAppName} {#MyAppVersion}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
LicenseFile={#MyAppDir}\LICENSE.txt
; Uncomment the following line to run in non administrative install mode (install for current user only.)
;PrivilegesRequired=lowest
OutputDir={#MyOutputDir}
OutputBaseFilename=sftpgo_windows_x86_64
Compression=lzma
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
ArchitecturesAllowed=x64
MinVersion=6.1

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#MyAppDir}\sftpgo.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#MyAppDir}\sftpgo.db"; DestDir: "{app}"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "{#MyAppDir}\README.pdf"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#MyAppDir}\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#MyAppDir}\sftpgo.json"; DestDir: "{app}"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "{#MyAppDir}\scripts\*"; DestDir: "{app}\scripts"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#MyAppDir}\sql\*"; DestDir: "{app}\sql"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#MyAppDir}\templates\*"; DestDir: "{app}\templates"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#MyAppDir}\static\*"; DestDir: "{app}\static"; Flags: ignoreversion recursesubdirs createallsubdirs
; NOTE: Don't use "Flags: ignoreversion" on any shared system files

[Dirs]
Name: "{app}\logs"; Permissions: everyone-full

[Icons]
Name: "{group}\Web Admin"; Filename: "http://127.0.0.1:8080/web";
Name: "{group}\Service Control";  WorkingDir: "{app}"; Filename: "powershell.exe"; Parameters: "-Command ""Start-Process cmd \""/k cd {app} & {#MyAppName} service --help\"" -Verb RunAs"; Comment: "Install, start, stop, uninstall SFTPGo Service"
Name: "{group}\REST API CLI";  WorkingDir: "{app}\scripts"; Filename: "{cmd}"; Parameters: "/k sftpgo_api_cli.exe --help"; Comment: "Manage users and connections"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"

[Run]
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=""SFTPGo Service"""; Flags: runhidden
Filename: "netsh"; Parameters: "advfirewall firewall add rule name=""SFTPGo Service"" dir=in action=allow program=""{app}\{#MyAppExeName}"""; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "service install -l ""{app}\logs\sftpgo.log"""; Description: "Install SFTPGo Windows Service"; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "service start";  Description: "Start SFTPGo Windows Service"; Flags: runhidden

[UninstallRun]
Filename: "{app}\{#MyAppExeName}"; Parameters: "service stop"; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "service uninstall"; Flags: runhidden
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=""SFTPGo Service"""; Flags: runhidden
