param(
  [switch]$WithAttack,   # also run scenario.py once everything is up
  [switch]$WithAgent     # also start the Go telemetry agent
)

$root = "C:\Users\dell\Desktop\aegiscloud-ai"
$ep   = "http://localhost:4566"
Set-Location $root

# Password comes from .env so it is not hardcoded here
$pw = ((Get-Content "$root\.env" | Where-Object { $_ -like "ELASTIC_PASSWORD=*" }) -replace "^ELASTIC_PASSWORD=","").Trim()
if (-not $pw) { Write-Host "ELASTIC_PASSWORD not found in .env" -ForegroundColor Red; return }

# Docker must be running (do NOT use 'exit' here: it would close your window)
docker info *> $null
if ($LASTEXITCODE -ne 0) {
  Write-Host "Docker is not running. Start Docker Desktop, wait until it is ready, then run this again." -ForegroundColor Red
  return
}

Write-Host "1/8 Starting containers..."
docker compose up -d

Write-Host "2/8 Waiting for Elasticsearch and LocalStack (up to 3 minutes)..."
$ready = $false
for ($i=0; $i -lt 60; $i++) {
  $es = curl.exe -s -o NUL -w "%{http_code}" -u "elastic:$pw" http://localhost:9200
  $ls = curl.exe -s -o NUL -w "%{http_code}" "$ep/_localstack/health"
  if ($es -eq "200" -and $ls -eq "200") { $ready = $true; break }
  Start-Sleep -Seconds 3
}
if (-not $ready) { Write-Host "Services did not become ready. Run 'docker compose ps' and 'docker compose logs' to see why." -ForegroundColor Red; return }

Write-Host "3/8 Rebuilding the lab with Terraform..."
Push-Location "$root\infrastructure\terraform"
terraform apply -auto-approve
$tf = $LASTEXITCODE
Pop-Location
if ($tf -ne 0) { Write-Host "Terraform failed, see the message above." -ForegroundColor Red; return }

Write-Host "4/8 Uploading the sensitive file..."
aws --endpoint-url=$ep s3 cp "$root\customer-data.csv" s3://aegiscloud-sensitive-data/customer-data.csv

Write-Host "5/8 Creating fresh access keys..."
$old = aws --endpoint-url=$ep iam list-access-keys --user-name test-analyst --query "AccessKeyMetadata[].AccessKeyId" --output text
foreach ($k in ($old -split "\s+")) {
  if ($k) { aws --endpoint-url=$ep iam delete-access-key --user-name test-analyst --access-key-id $k }
}
$new = aws --endpoint-url=$ep iam create-access-key --user-name test-analyst --query "AccessKey.[AccessKeyId,SecretAccessKey]" --output text
$parts = $new -split "\s+"
$env:AEGIS_ACCESS_KEY = $parts[0]
$env:AEGIS_SECRET_KEY = $parts[1]

Write-Host "6/8 Starting the backend in a new window..."
$cmd = "Set-Location '$root\backend'; .\venv\Scripts\Activate.ps1; `$env:ELASTIC_PASSWORD='$pw'; uvicorn main:app --reload --port 8000"
Start-Process powershell -ArgumentList "-NoExit","-Command",$cmd

Write-Host "7/8 Starting the incident engine in a new window..."
$cmd = "Set-Location '$root\incident-engine'; ..\backend\venv\Scripts\Activate.ps1; `$env:ELASTIC_PASSWORD='$pw'; python engine.py"
Start-Process powershell -ArgumentList "-NoExit","-Command",$cmd

Write-Host "8/8 Waiting for the backend..."
$up = $false
for ($i=0; $i -lt 30; $i++) {
  if ((curl.exe -s -o NUL -w "%{http_code}" http://localhost:8000/health) -eq "200") { $up = $true; break }
  Start-Sleep -Seconds 2
}
if (-not $up) { Write-Host "Backend not answering yet. Check its window for errors." -ForegroundColor Yellow }

if ($WithAgent) {
  $cmd = "Set-Location '$root\go-agent'; .\aegiscloud-agent.exe --interval 5s"
  Start-Process powershell -ArgumentList "-NoExit","-Command",$cmd
}

if ($WithAttack -and $up) {
  Write-Host "Running the attack scenario in a new window..."
  $cmd = "Set-Location '$root\attack-simulator\credential-abuse'; .\venv\Scripts\Activate.ps1; python scenario.py"
  Start-Process powershell -ArgumentList "-NoExit","-Command",$cmd
}

Write-Host ""
Write-Host "Lab ready." -ForegroundColor Green
Write-Host "  Kibana (can take 1-2 more minutes): http://localhost:5601   user: elastic"
Write-Host "  LocalStack Resource Browser:        https://app.localstack.cloud"
Write-Host "  To run the attack later:  . .\start-lab.ps1 -WithAttack   (or run scenario.py manually)"

## TO RUN : . .\start-lab.ps1