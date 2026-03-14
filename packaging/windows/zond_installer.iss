[Setup]
AppName=Zond Network Scanner
AppVersion=0.3.5
DefaultDirName={autopf}\Zond
DefaultGroupName=Zond
OutputDir=..\..\target\release
OutputBaseFilename=Zond_Setup
Compression=lzma
SolidCompression=yes
ChangesEnvironment=yes

[Files]
Source: "..\..\target\release\zond.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "npcap-1.87.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Run]
Filename: "{tmp}\npcap-1.87.exe"; Description: "Install Npcap (Required for packet capture)"; Flags: waituntilterminated

[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath(ExpandConstant('{app}'))

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;
