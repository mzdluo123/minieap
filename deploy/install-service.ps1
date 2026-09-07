$ErrorActionPreference = 'Stop'
$src = Split-Path -Parent $MyInvocation.MyCommand.Path
$dst = 'C:\minieap'

New-Item -ItemType Directory -Force -Path $dst | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $dst 'logs') | Out-Null

Copy-Item -Force (Join-Path $src '..\build\Release\minieap.exe') (Join-Path $dst 'minieap.exe')
Copy-Item -Force (Join-Path $src '..\build\Release\minieap.conf') (Join-Path $dst 'minieap.conf')
Copy-Item -Force (Join-Path $src 'WinSW-x64.exe') (Join-Path $dst 'minieap-service.exe')
Copy-Item -Force (Join-Path $src 'minieap-service.xml') (Join-Path $dst 'minieap-service.xml')

Get-Process -Name minieap -ErrorAction SilentlyContinue | Stop-Process -Force

$svc = Get-Service -Name minieap -ErrorAction SilentlyContinue
if ($svc) {
  if ($svc.Status -ne 'Stopped') { & "$dst\minieap-service.exe" stop }
  & "$dst\minieap-service.exe" uninstall
}

& "$dst\minieap-service.exe" install
& "$dst\minieap-service.exe" start
sc.exe config minieap start= delayed-auto | Out-Null
Get-Service minieap | Format-List Name, Status, StartType
