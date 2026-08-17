# Purview DLP — Infrastructure as Code

Automates deployment of a Microsoft Purview Data Loss Prevention (DLP)
policy via PowerShell + GitHub Actions, since native Terraform providers
do not support Purview DLP configuration.

The pipeline creates/updates a DLP policy that:

- Targets **Exchange Online** and **OneDrive**.
- Detects **U.K. Financial Data**, **U.K. National Insurance Numbers
  (NINO)**, and **Credit Card Numbers**.
- Would restrict access for people outside the organization
  (`BlockAccessScope: NotInOrganization`) once out of simulation.
- Is deployed strictly in **Simulation Mode**
  (`TestWithoutNotifications` — no enforcement, no policy tips). The
  script verifies this after every run and fails the pipeline if the
  tenant's actual state doesn't match.

## Contents

| Path | Purpose |
|---|---|
| [`scripts/Deploy-DLPPolicies.ps1`](scripts/Deploy-DLPPolicies.ps1) | Idempotent deployment script (cert-based Service Principal auth to Security & Compliance PowerShell) |
| [`.github/workflows/deploy-dlp-policies.yml`](.github/workflows/deploy-dlp-policies.yml) | CI/CD pipeline: OIDC login to Entra ID, then runs the script on push to `main` |
| [`docs/SETUP.md`](docs/SETUP.md) | Step-by-step App Registration, API permission, and GitHub secrets setup |

## Quick start

See [`docs/SETUP.md`](docs/SETUP.md) for the full walkthrough. Summary:

1. Create an Entra ID App Registration (certificate auth only, no client
   secret) and assign its service principal the **Compliance
   Administrator** role.
2. Add a federated credential trusting `repo:<org>/<repo>:ref:refs/heads/main`
   for OIDC login.
3. Set the required GitHub secrets/variables (`AZURE_CLIENT_ID`,
   `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `EXO_CERT_BASE64`,
   `EXO_CERT_PASSWORD`, `EXO_ORGANIZATION`).
4. Push to `main` — the workflow deploys/converges the DLP policy.

## Running locally

```powershell
$pw = ConvertTo-SecureString -String '<pfx-password>' -AsPlainText -Force
./scripts/Deploy-DLPPolicies.ps1 `
    -AppId '<app-client-id>' `
    -Organization 'contoso.onmicrosoft.com' `
    -CertificateBase64 (Get-Content .\cert.pfx.b64 -Raw) `
    -CertificatePassword $pw
```
