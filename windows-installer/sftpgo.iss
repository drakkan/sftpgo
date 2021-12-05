#define MyAppName "SFTPGo"
#if GetEnv("SFTPGO_ISS_VERSION") != ""
    #define MyAppVersion GetEnv("SFTPGO_ISS_VERSION")
#else
    #define MyAppVersion GetEnv("SFTPGO_ISS_DEV_VERSION")
#endif
#if GetEnv("SFTPGO_ISS_ARCH") != ""
    #define MyAppArch GetEnv("SFTPGO_ISS_ARCH")
    #define MySetupName "sftpgo_windows_" + MyAppArch
    #if MyAppArch == "x86"
        #define MyAppArch64 ""
    #else
        #define MyAppArch64 GetEnv("SFTPGO_ISS_ARCH")
    #endif
#else
    #define MyAppArch "x64"
    #define MyAppArch64 "x64"
    #define MySetupName "sftpgo_windows_x86_64"
#endif
#define MyAppURL "https://github.com/drakkan/sftpgo"
#define MyVersionInfo StringChange(MyAppVersion,"v","")
#if GetEnv("SFTPGO_ISS_DOC_URL") != ""
    #define DocURL GetEnv("SFTPGO_ISS_DOC_URL")
#else
    #define DocURL "https://github.com/drakkan/sftpgo/blob/main/README.md"
#endif
#define MyAppExeName "sftpgo.exe"
#define MyAppDir "..\output"
#define MyOutputDir ".."

[Setup]
AppId={{1FB9D57F-00DD-4B1B-8798-1138E5CE995D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher=Nicola Murino
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
AppCopyright=AGPL-3.0
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
LicenseFile={#MyAppDir}\LICENSE.txt
OutputDir={#MyOutputDir}
OutputBaseFilename={#MySetupName}
SetupIconFile=icon.ico
SolidCompression=yes
UninstallDisplayIcon={app}\sftpgo.exe
WizardStyle=modern
ArchitecturesInstallIn64BitMode={#MyAppArch64}
PrivilegesRequired=admin
ArchitecturesAllowed={#MyAppArch}
MinVersion=6.1sp1
VersionInfoVersion={#MyVersionInfo}
VersionInfoCopyright=AGPL-3.0
SignTool=signtool
SignedUninstaller=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#MyAppDir}\sftpgo.exe"; DestDir: "{app}"; Flags: ignoreversion signonce
Source: "{#MyAppDir}\sftpgo.db"; DestDir: "{commonappdata}\{#MyAppName}"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "{#MyAppDir}\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#MyAppDir}\sftpgo.json"; DestDir: "{commonappdata}\{#MyAppName}"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "{#MyAppDir}\sftpgo.json"; DestDir: "{commonappdata}\{#MyAppName}"; DestName: "sftpgo_default.json"; Flags: ignoreversion
Source: "{#MyAppDir}\templates\*"; DestDir: "{commonappdata}\{#MyAppName}\templates"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#MyAppDir}\static\*"; DestDir: "{commonappdata}\{#MyAppName}\static"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#MyAppDir}\openapi\*"; DestDir: "{commonappdata}\{#MyAppName}\openapi"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "README.txt"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Dirs]
Name: "{commonappdata}\{#MyAppName}\logs"; Permissions: everyone-full
Name: "{commonappdata}\{#MyAppName}\backups"; Permissions: everyone-full
Name: "{commonappdata}\{#MyAppName}\credentials"; Permissions: everyone-full

[Icons]
Name: "{group}\Web Admin"; Filename: "http://localhost:8080/web/admin";
Name: "{group}\Web Client"; Filename: "http://localhost:8080/web/client";
Name: "{group}\OpenAPI"; Filename: "http://localhost:8080/openapi";
Name: "{group}\Service Control";  WorkingDir: "{app}"; Filename: "powershell.exe"; Parameters: "-Command ""Start-Process cmd \""/k cd {app} & {#MyAppExeName} service --help\"" -Verb RunAs"; Comment: "Manage SFTPGo Service"
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
Filename: "{app}\{#MyAppExeName}"; Parameters: "service stop"; Flags: runhidden; RunOnceId: "Stop SFTPGo service"
Filename: "{app}\{#MyAppExeName}"; Parameters: "service uninstall"; Flags: runhidden; RunOnceId: "Uninstall SFTPGo service"
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=""SFTPGo Service"""; Flags: runhidden; RunOnceId: "Remove SFTPGo firewall rule"

[Messages]
FinishedLabel=Setup has finished installing SFTPGo on your computer. SFTPGo should already be running as a Windows service, it uses TCP port 8080 for HTTP service and TCP port 2022 for SFTP service by default, make sure the configured ports are not used by other services or edit the configuration according to your needs.