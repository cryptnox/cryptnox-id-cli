# Wraps a PIV card's PKCS#10 request in a CMC request on behalf of another user,
# signed with an enrollment agent certificate, so the key stays on the card.
# See docs/piv/windows-logon-and-remote-desktop.rst, Path A2.
param(
  [Parameter(Mandatory=$true)][string]$CsrPath,
  [Parameter(Mandatory=$true)][string]$RequesterName,
  [Parameter(Mandatory=$true)][string]$AgentThumbprint,
  [string]$OutPath = ".\eobo-cmc.req",
  [switch]$MachineStore
)
$ErrorActionPreference = 'Stop'
$store = if ($MachineStore) { "LocalMachine" } else { "CurrentUser" }
$agent = Get-Item ("Cert:\$store\My\" + ($AgentThumbprint -replace '\s',''))
if (-not $agent.HasPrivateKey) { throw "Enrollment Agent certificate has no private key in $store\My" }
$inner = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
$inner.InitializeDecode((Get-Content $CsrPath -Raw), 6)
$cmc = New-Object -ComObject X509Enrollment.CX509CertificateRequestCmc
$cmc.InitializeFromInnerRequest($inner)
$cmc.RequesterName = $RequesterName
$signer = New-Object -ComObject X509Enrollment.CSignerCertificate
$signer.Initialize([bool]$MachineStore, 0, 1, [Convert]::ToBase64String($agent.RawData))
$cmc.SignerCertificate = $signer
$cmc.Encode()
$b64 = $cmc.RawData(3)
[IO.File]::WriteAllText($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutPath), $b64)
Write-Host "CMC request written to $OutPath (requester $RequesterName, signed by $($agent.Subject))"
