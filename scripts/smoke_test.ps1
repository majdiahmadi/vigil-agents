$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
Set-Location $project
& .\.venv\Scripts\python.exe -m vigil doctor
& .\.venv\Scripts\python.exe -m vigil triage investigate --alert .\fixtures\alerts\ssh_bruteforce.json
& .\.venv\Scripts\python.exe -m vigil orchestrator investigate --alert .\fixtures\alerts\ssh_bruteforce.json
& .\.venv\Scripts\python.exe -m pytest -q

