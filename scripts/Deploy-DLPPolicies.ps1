#Requires -Version 7.0
<#
.SYNOPSIS
    Idempotently deploys a basic Microsoft Purview DLP policy (Exchange + OneDrive)
    for U.K. Financial Data / PII, in Simulation ("Test without notifications") mode.

.DESCRIPTION
    Connects to Security & Compliance PowerShell using certificate-based
    Service Principal authentication (no interactive/user auth, no client
    secret), then creates or updates:
      - A DLP compliance policy scoped to Exchange Online and OneDrive.
      - A single DLP compliance rule that matches U.K. Financial Data,
        U.K. National Insurance Numbers, and Credit Card Numbers, and
        would restrict access for people outside the organization once
        the policy is promoted out of simulation.

    The policy is strictly deployed in TestWithoutNotifications mode
    (simulation only, no policy tips, no enforcement). The script verifies
    this after every run and fails closed if the resulting mode is
    anything other than TestWithoutNotifications, so a bad parameter or a
    manual portal change can never be silently promoted to enforcement by
    a re-run of this pipeline.

    Re-running this script against the same tenant is safe: policy/rule
    existence is checked first and Set-* cmdlets are used to converge
    state rather than failing on "already exists".

.PARAMETER AppId
    Application (client) ID of the Entra ID App Registration / Service
    Principal used for certificate-based auth to Security & Compliance
    PowerShell.

.PARAMETER Organization
    Tenant's default/onmicrosoft.com domain, e.g. contoso.onmicrosoft.com.

.PARAMETER CertificateBase64
    Base64-encoded PFX certificate (private key included) whose public key
    is uploaded to the App Registration. Decoded to a temp file for the
    duration of the connection only, then deleted.

.PARAMETER CertificatePassword
    SecureString password protecting the PFX. Optional — pass an empty
    SecureString (default) if the PFX was exported without a password.

.PARAMETER PolicyName
    Name of the DLP compliance policy to create/update.

.PARAMETER RuleName
    Name of the DLP compliance rule to create/update inside the policy.

.EXAMPLE
    $pw = ConvertTo-SecureString -String $env:CERT_PASSWORD -AsPlainText -Force
    ./Deploy-DLPPolicies.ps1 -AppId $env:EXO_APP_ID -Organization $env:EXO_ORGANIZATION `
        -CertificateBase64 $env:CERT_BASE64 -CertificatePassword $pw
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AppId,

    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $true)]
    [string]$CertificateBase64,

    [securestring]$CertificatePassword = (New-Object System.Security.SecureString),

    [string]$PolicyName = 'UK-Financial-PII-Protection-Simulation',

    [string]$RuleName = 'UK-Financial-PII-Protection-Simulation-Rule',

    [string[]]$ExchangeLocation = @('All'),

    [string[]]$OneDriveLocation = @('All')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Simulation mode is not configurable via a parameter on purpose: this
# pipeline is scoped to deploying/validating a *test* policy. Promotion to
# enforcement (Mode 'Enable') is a deliberate, separate, reviewed action —
# not something a CI re-run should ever be able to do implicitly.
$RequiredSimulationMode = 'TestWithoutNotifications'

$SensitiveInfoTypes = @(
    @{ Name = 'Credit Card Number'; minCount = 1 }
    @{ Name = 'U.K. National Insurance Number (NINO)'; minCount = 1 }
    @{ Name = 'U.K. Financial Data'; minCount = 1 }
)

$tempCertPath = $null

function Assert-Module {
    param([string]$Name)

    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Host "Module '$Name' not found. Installing for CurrentUser scope..."
        Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck
    }
    Import-Module -Name $Name -ErrorAction Stop
}

function Wait-ForPolicyPropagation {
    param(
        [string]$Identity,
        [int]$TimeoutSeconds = 60
    )

    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        if (Get-DlpCompliancePolicy -Identity $Identity -ErrorAction SilentlyContinue) {
            return
        }
        Start-Sleep -Seconds 5
        $elapsed += 5
    }
    throw "Timed out waiting for DLP policy '$Identity' to become visible after creation."
}

try {
    Write-Host "==> Preparing certificate material"
    $certBytes = [Convert]::FromBase64String($CertificateBase64)
    $tempCertPath = Join-Path ([System.IO.Path]::GetTempPath()) "dlp-deploy-$([Guid]::NewGuid()).pfx"
    [System.IO.File]::WriteAllBytes($tempCertPath, $certBytes)

    Write-Host "==> Importing ExchangeOnlineManagement module"
    Assert-Module -Name ExchangeOnlineManagement

    Write-Host "==> Connecting to Security & Compliance PowerShell as app '$AppId' (organization: $Organization)"
    Connect-IPPSSession -AppId $AppId `
        -Organization $Organization `
        -CertificateFilePath $tempCertPath `
        -CertificatePassword $CertificatePassword `
        -ShowBanner:$false

    # --- DLP compliance policy: create or converge -----------------------
    Write-Host "==> Checking for existing policy '$PolicyName'"
    $existingPolicy = Get-DlpCompliancePolicy -Identity $PolicyName -ErrorAction SilentlyContinue

    if (-not $existingPolicy) {
        Write-Host "==> Policy not found. Creating '$PolicyName' in $RequiredSimulationMode mode"
        New-DlpCompliancePolicy -Name $PolicyName `
            -Comment 'Simulation-only: detects UK financial data / PII (NINO, credit card) across Exchange and OneDrive. No enforcement, no policy tips. Managed by CI/CD - manual portal edits will be overwritten on next run.' `
            -ExchangeLocation $ExchangeLocation `
            -OneDriveLocation $OneDriveLocation `
            -Mode $RequiredSimulationMode | Out-Null

        Wait-ForPolicyPropagation -Identity $PolicyName
    }
    else {
        Write-Host "==> Policy exists. Converging locations/mode for '$PolicyName'"
        Set-DlpCompliancePolicy -Identity $PolicyName `
            -ExchangeLocation $ExchangeLocation `
            -OneDriveLocation $OneDriveLocation `
            -Mode $RequiredSimulationMode | Out-Null
    }

    # --- DLP compliance rule: create or converge --------------------------
    Write-Host "==> Checking for existing rule '$RuleName'"
    $existingRule = Get-DlpComplianceRule -Identity $RuleName -ErrorAction SilentlyContinue

    if (-not $existingRule) {
        Write-Host "==> Rule not found. Creating '$RuleName'"
        New-DlpComplianceRule -Name $RuleName `
            -Policy $PolicyName `
            -Comment 'Flags UK Financial Data, UK NINO and Credit Card Number; would restrict external sharing once promoted out of simulation.' `
            -ContentContainsSensitiveInformation $SensitiveInfoTypes `
            -BlockAccess $true `
            -BlockAccessScope 'NotInOrganization' `
            -Disabled $false | Out-Null
    }
    else {
        Write-Host "==> Rule exists. Converging conditions/actions for '$RuleName'"
        Set-DlpComplianceRule -Identity $RuleName `
            -ContentContainsSensitiveInformation $SensitiveInfoTypes `
            -BlockAccess $true `
            -BlockAccessScope 'NotInOrganization' `
            -Disabled $false | Out-Null
    }

    # --- Fail closed if the tenant state isn't actually simulation-only ---
    Write-Host "==> Verifying deployed policy is strictly in $RequiredSimulationMode mode"
    $finalPolicy = Get-DlpCompliancePolicy -Identity $PolicyName
    if ($finalPolicy.Mode -ne $RequiredSimulationMode) {
        throw "Safety check failed: policy '$PolicyName' is in Mode '$($finalPolicy.Mode)', expected '$RequiredSimulationMode'. Refusing to leave the tenant in this state."
    }

    $finalRule = Get-DlpComplianceRule -Identity $RuleName
    Write-Host "==> Deployment complete."
    Write-Host "    Policy : $($finalPolicy.Name) | Mode: $($finalPolicy.Mode) | Exchange: $($finalPolicy.ExchangeLocation) | OneDrive: $($finalPolicy.OneDriveLocation)"
    Write-Host "    Rule   : $($finalRule.Name) | Disabled: $($finalRule.Disabled) | BlockAccessScope: $($finalRule.BlockAccessScope)"
}
finally {
    if ($tempCertPath -and (Test-Path $tempCertPath)) {
        Remove-Item -Path $tempCertPath -Force -ErrorAction SilentlyContinue
    }

    if (Get-Module -Name ExchangeOnlineManagement) {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
}
