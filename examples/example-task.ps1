# Example: Windows Task Scheduler action
# Program/script: pwsh.exe
# Arguments (example):
#   -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Rotate-LXCA-O365SmtpToken.ps1" -LxcaBaseUrl "https://lxca.local" -LxcaUser "admin" -LxcaPass "********" -MonitorId "1768960044290" -RotateToken -TokenValue "DUMMYTOKEN_..." -DescriptionPrefix "ROTATED"

pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Rotate-LXCA-O365SmtpToken.ps1" `
  -LxcaBaseUrl "https://lxca.local" `
  -LxcaUser "admin" -LxcaPass "********" `
  -MonitorId "1768960044290" `
  -RotateToken `
  -TokenValue ("DUMMYTOKEN_" + ([guid]::NewGuid().ToString("N"))) `
  -DescriptionPrefix "TOKEN-ROTATE TEST"
