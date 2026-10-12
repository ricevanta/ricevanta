$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$vs) { throw "MSVC installation missing" }
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
cmd /c "`"$vcvars`" && set" | ForEach-Object {
  if ($_ -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
}
if ($LASTEXITCODE -ne 0) { throw "MSVC environment failed" }
$source = Join-Path $env:RUNNER_TEMP 'ricevanta-compiler.c'
$object = Join-Path $env:RUNNER_TEMP 'ricevanta-compiler.obj'
Set-Content -Path $source -Value 'int ricevanta_compiler_probe(void) { return 0; }'
(Get-Command cl.exe).Source
& cl.exe /Bv /c $source "/Fo$object"
if ($LASTEXITCODE -ne 0) { throw "MSVC qualification failed" }
