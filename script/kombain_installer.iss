; Kombain for Windows — installer (Inno Setup 6)
#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
; numeric X.Y.Z for the file version resource ("1.0.0-dev.5" -> "1.0.0")
#define DashPos Pos("-", AppVersion)
#if DashPos > 0
  #define NumVersion Copy(AppVersion, 1, DashPos - 1)
#else
  #define NumVersion AppVersion
#endif

[Setup]
AppId={{6B1E4C2A-7D3F-4A58-9C61-2E8B0F4D7A11}
AppName=Kombain
AppVersion={#AppVersion}
AppVerName=Kombain {#AppVersion}
AppPublisher=Kombain
VersionInfoVersion={#NumVersion}
VersionInfoProductName=Kombain
VersionInfoDescription=Kombain Setup
SourceDir=..
OutputDir=deployment
OutputBaseFilename=Kombain-{#AppVersion}-windows-x64-setup
SetupIconFile=res\Throne.ico
UninstallDisplayName=Kombain
UninstallDisplayIcon={app}\Throne.exe
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
DefaultDirName={localappdata}\Kombain
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=force
RestartApplications=no
Compression=lzma2/ultra64
SolidCompression=yes

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "deployment\windows-amd64\*"; DestDir: "{app}"; Excludes: "*.pdb"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Kombain"; Filename: "{app}\Throne.exe"
Name: "{autodesktop}\Kombain"; Filename: "{app}\Throne.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Throne.exe"; Description: "{cm:LaunchProgram,Kombain}"; Flags: postinstall nowait skipifsilent

[Code]
var
  DeleteUserData: Boolean;

procedure StopKombain;
var
  Locator, Service, Processes, Process: Variant;
  Prefix, ExePath: String;
  I: Integer;
begin
  Prefix := Lowercase(AddBackslash(ExpandConstant('{app}')));
  try
    Locator := CreateOleObject('WbemScripting.SWbemLocator');
    Service := Locator.ConnectServer('.', 'root\CIMV2');
    Processes := Service.ExecQuery('SELECT * FROM Win32_Process WHERE Name = ''Throne.exe'' OR Name = ''ThroneCore.exe'' OR Name = ''kombain-node.exe''');
    for I := 0 to Processes.Count - 1 do
    begin
      Process := Processes.ItemIndex(I);
      if not VarIsNull(Process.ExecutablePath) then
      begin
        ExePath := Process.ExecutablePath;
        if Pos(Prefix, Lowercase(ExePath)) = 1 then
          Process.Terminate(0);
      end;
    end;
    Sleep(800);
  except
    Log('Could not stop Kombain: ' + GetExceptionMessage);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopKombain;
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    StopKombain;
    DeleteUserData := SuppressibleMsgBox('Удалить также профили, настройки и список ваших серверов?' + #13#10#13#10 +
      'Выберите «Нет», если собираетесь установить Kombain снова.', mbConfirmation, MB_YESNO, IDNO) = IDYES;
  end
  else if (CurUninstallStep = usPostUninstall) and DeleteUserData then
  begin
    DelTree(ExpandConstant('{app}\config'), True, True, True);
    DelTree(ExpandConstant('{localappdata}\Kombain\config'), True, True, True);
    RemoveDir(ExpandConstant('{app}'));
  end;
end;
