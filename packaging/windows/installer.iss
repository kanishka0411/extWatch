; Inno Setup script for ExtWatch. Run build-installer.ps1, which fills in the paths.
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\build\ci-windows\src\Release\deploy"
#endif

[Setup]
AppId={{9C7B2F5E-6D1B-4E7C-9C4B-EXTWATCH0001}
AppName=ExtWatch
AppVersion={#AppVersion}
AppPublisher=ExtWatch
AppPublisherURL=https://github.com/kanishka0411/extWatch
DefaultDirName={autopf}\ExtWatch
DefaultGroupName=ExtWatch
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\..\dist
OutputBaseFilename=ExtWatch-{#AppVersion}-windows-setup
SetupIconFile=extwatch.ico
UninstallDisplayIcon={app}\extwatch.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
ChangesEnvironment=yes

[Tasks]
Name: "autostart"; Description: "Start ExtWatch when I sign in"; GroupDescription: "Startup:"
Name: "addpath"; Description: "Add the extwatch command to PATH (for the current user)"; GroupDescription: "Command line:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\ExtWatch"; Filename: "{app}\extwatch.exe"
Name: "{autodesktop}\ExtWatch"; Filename: "{app}\extwatch.exe"; Tasks: 

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "ExtWatch"; ValueData: """{app}\extwatch.exe"""; Flags: uninsdeletevalue; Tasks: autostart
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: addpath; Check: NeedsAddPath('{app}')

[Run]
Filename: "{app}\extwatch.exe"; Description: "Launch ExtWatch"; Flags: nowait postinstall skipifsilent

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(ExpandConstant(Param)) + ';', ';' + Uppercase(OrigPath) + ';') = 0;
end;
