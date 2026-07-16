; NovaProxy Windows Installer Script
; Requires Inno Setup (https://jrsoftware.org/isdl.php)

#define MyAppName "NovaProxy"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "TheCanniball"
#define MyAppURL "https://github.com/TheCanniball/Nova-Proxy-App"
#define MyAppExeName "novaproxy.exe"

[Setup]
AppId={{B7F3C8E1-2D4A-4F6B-8C9E-0A1B2C3D4E5F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=
PrivilegesRequired=admin
OutputDir=..\dist
OutputBaseFilename=NovaProxy-{#MyAppVersion}-Setup
SetupIconFile=..\assets\favicon.ico
UninstallDisplayIcon={app}\novaproxy.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "persian"; MessagesFile: "compiler:Languages\Persian.isl"

[Files]
Source: "..\novaproxy.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\assets\icon.png"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "..\assets\favicon.ico"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{app}\data\config"
Name: "{app}\data\rules"
Name: "{app}\data\cert"
Name: "{app}\data\Xray"
Name: "{app}\data\logs"

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autoprograms}\{#MyAppName} (Core)"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--core"; WorkingDir: "{app}"; IconFilename: "{app}\novaproxy.exe"
Name: "{autostartup}\{#MyAppName} Core"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--core"; WorkingDir: "{app}"; Flags: runonly

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: "--core"; Description: "Start NovaProxy Core"; Flags: postinstall nowait skipifsilent shellexec

[UninstallRun]
Filename: "taskkill"; Parameters: "/f /im novaproxy.exe"; Flags: runhidden

[Code]
function InitializeSetup: Boolean;
begin
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // Create default config files if they don't exist
  end;
end;
