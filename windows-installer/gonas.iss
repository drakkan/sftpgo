#define MyAppName "GoNAS"
#if GetEnv("GONAS_ISS_VERSION") != ""
    #define MyAppVersion GetEnv("GONAS_ISS_VERSION")
#else
    #define MyAppVersion GetEnv("GONAS_ISS_DEV_VERSION")
#endif
#if GetEnv("GONAS_ISS_ARCH") != ""
    #define MyAppArch GetEnv("GONAS_ISS_ARCH")
    #define MySetupName "gonas_windows_" + MyAppArch
    #if MyAppArch == "x86"
        #define MyAppArch64 ""
    #else
        #define MyAppArch64 GetEnv("GONAS_ISS_ARCH")
    #endif
#else
    #define MyAppArch "x64"
    #define MyAppArch64 "x64"
    #define MySetupName "gonas_windows_x86_64"
#endif
#define MyAppURL "https://github.com/xrogers/gonas"
#define MyVersionInfo StringChange(MyAppVersion,"v","")
#define DocURL "https://github.com/xrogers/gonas"
#define MyAppExeName "gonas.exe"
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
AppCopyright=2019-2025 Nicola Murino
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
LicenseFile=LICENSE_with_NOTICE.txt
OutputDir={#MyOutputDir}
OutputBaseFilename={#MySetupName}
SetupIconFile=icon.ico
SolidCompression=yes
UninstallDisplayIcon={app}\gonas.exe
WizardStyle=modern
ArchitecturesInstallIn64BitMode={#MyAppArch64}
PrivilegesRequired=admin
ArchitecturesAllowed={#MyAppArch}
MinVersion=10.0.14393
VersionInfoVersion={#MyVersionInfo}
VersionInfoCopyright=2019-2025 Nicola Murino

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#MyAppDir}\gonas.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#MyAppDir}\gonas.db"; DestDir: "{commonappdata}\{#MyAppName}"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "{#MyAppDir}\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#MyAppDir}\NOTICE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#MyAppDir}\gonas.json"; DestDir: "{commonappdata}\{#MyAppName}"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "{#MyAppDir}\gonas.json"; DestDir: "{commonappdata}\{#MyAppName}"; DestName: "gonas_default.json"; Flags: ignoreversion
Source: "{#MyAppDir}\templates\*"; DestDir: "{commonappdata}\{#MyAppName}\templates"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#MyAppDir}\static\*"; DestDir: "{commonappdata}\{#MyAppName}\static"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#MyAppDir}\openapi\*"; DestDir: "{commonappdata}\{#MyAppName}\openapi"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "README.txt"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Dirs]
Name: "{commonappdata}\{#MyAppName}\logs"
Name: "{commonappdata}\{#MyAppName}\backups"
Name: "{commonappdata}\{#MyAppName}\env.d"
Name: "{commonappdata}\{#MyAppName}\certs"

[Icons]
Name: "{group}\Web Admin"; Filename: "http://localhost:8080/web/admin";
Name: "{group}\Web Client"; Filename: "http://localhost:8080/web/client";
Name: "{group}\OpenAPI"; Filename: "http://localhost:8080/openapi";
Name: "{group}\Service Control";  WorkingDir: "{app}"; Filename: "powershell.exe"; Parameters: "-Command ""Start-Process cmd \""/k cd {app} & {#MyAppExeName} service --help\"" -Verb RunAs"; Comment: "Manage GoNAS Service"
Name: "{group}\Documentation"; Filename: "{#DocURL}";
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"

[Run]
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=""GoNAS Service"""; Flags: runhidden
Filename: "netsh"; Parameters: "advfirewall firewall add rule name=""GoNAS Service"" dir=in action=allow program=""{app}\{#MyAppExeName}"""; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "service stop"; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "service uninstall"; Flags: runhidden
Filename: "{sys}\icacls.exe"; Parameters: """{commonappdata}\{#MyAppName}"" /inheritance:r /grant:r ""*S-1-5-18:(OI)(CI)F"" ""*S-1-5-32-544:(OI)(CI)F"""; Flags: runhidden; Check: IsFirstInstallCheck
Filename: "{app}\{#MyAppExeName}"; Parameters: "service install -c ""{commonappdata}\{#MyAppName}"" -l ""logs\gonas.log"""; Description: "Install GoNAS Windows Service"; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "service start";  Description: "Start GoNAS Windows Service"; Flags: runhidden

[UninstallRun]
Filename: "{app}\{#MyAppExeName}"; Parameters: "service stop"; Flags: runhidden; RunOnceId: "Stop GoNAS service"
Filename: "{app}\{#MyAppExeName}"; Parameters: "service uninstall"; Flags: runhidden; RunOnceId: "Uninstall GoNAS service"
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=""GoNAS Service"""; Flags: runhidden; RunOnceId: "Remove GoNAS firewall rule"

[Messages]
FinishedLabel=Setup has finished installing GoNAS on your computer. GoNAS should already be running as a Windows service, it uses TCP port 8080 for HTTP service and TCP port 2022 for SFTP service by default, make sure the configured ports are not used by other services or edit the configuration according to your needs.

[Code]

var
  IsUpdate: Boolean;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  IsUpdate := FileExists(ExpandConstant('{app}\{#MyAppExeName}'));

  if IsUpdate then
  begin
    Exec(ExpandConstant('{app}\{#MyAppExeName}'), 'service stop', '', SW_HIDE, ewWaitUntilTerminated, Code);
  end;

  Result := '';
end;

function IsFirstInstallCheck(): Boolean;
begin
  Result := not IsUpdate;
end;