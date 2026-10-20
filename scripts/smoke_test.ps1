$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
Set-Location $project
$env:VIGIL_DATA_DIR = Join-Path $project '.smoke-data'
$env:VIGIL_CONFIG_DIR = Join-Path $project '.model-ui-smoke'
$env:VIGIL_CONNECTOR_MODE = 'mock'
& .\.venv\Scripts\python.exe -m vigil doctor
& .\.venv\Scripts\python.exe -m vigil triage investigate --alert .\fixtures\alerts\ssh_bruteforce.json
& .\.venv\Scripts\python.exe -m vigil malware analyze --alert .\fixtures\alerts\suspicious_file.json
& .\.venv\Scripts\python.exe -m vigil hunter hunt --alert .\fixtures\alerts\hunt_scenario.json
& .\.venv\Scripts\python.exe -m vigil orchestrator investigate --alert .\fixtures\alerts\ssh_bruteforce.json
& .\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider --basetemp=.pytest-tmp

