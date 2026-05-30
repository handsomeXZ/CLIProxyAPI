@echo off
setlocal

set "BYTES=%~1"
if "%BYTES%"=="" set "BYTES=32"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference = 'Stop';" ^
  "$bytesCount = 32;" ^
  "if (-not [int]::TryParse('%BYTES%', [ref]$bytesCount)) { throw 'Byte count must be an integer.' };" ^
  "if ($bytesCount -lt 16) { throw 'Byte count must be at least 16.' };" ^
  "$bytes = New-Object byte[] $bytesCount;" ^
  "$rng = [Security.Cryptography.RandomNumberGenerator]::Create();" ^
  "try { $rng.GetBytes($bytes) } finally { $rng.Dispose() };" ^
  "$secret = [Convert]::ToBase64String($bytes);" ^
  "Write-Output 'Generated affinity-rewrite secret:';" ^
  "Write-Output $secret;" ^
  "Write-Output '';" ^
  "Write-Output 'YAML:';" ^
  "Write-Output 'affinity-rewrite:';" ^
  "Write-Output '  enabled: true';" ^
  "Write-Output ('  secret: ' + [char]34 + $secret + [char]34);" ^
  "Write-Output ('  prefix: ' + [char]34 + 'ses' + [char]34);"

set "EXIT_CODE=%ERRORLEVEL%"
echo.
pause
if not "%EXIT_CODE%"=="0" exit /b %EXIT_CODE%
endlocal
