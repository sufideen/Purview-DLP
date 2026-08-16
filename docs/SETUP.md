# Purview DLP CI/CD — Authentication & Setup

This pipeline uses **one** Entra ID App Registration for two independent
purposes:

1. **OIDC login to Azure/Entra ID** (`azure/login`) — proves the GitHub
   Actions run's identity to Entra ID with zero stored secrets.
2. **Certificate-based app-only auth to Security & Compliance PowerShell**
   (`Connect-IPPSSession`) — this is what actually lets
   `Deploy-DLPPolicies.ps1` create/update DLP policies. Exchange Online's
   app-only auth model requires a **certificate**, not an OIDC token, so
   the app's certificate (PFX) is stored as a GitHub encrypted secret and
   decoded at runtime.

## 1. Create the App Registration

1. **Entra admin center → App registrations → New registration.**
   - Name: e.g. `purview-dlp-cicd`.
   - Supported account types: single tenant.
   - No redirect URI needed (this is a headless/app-only client).
2. Note the **Application (client) ID** and **Directory (tenant) ID** —
   you'll need both for GitHub secrets.

## 2. Generate and attach the certificate (for `Connect-IPPSSession`)

Generate a self-signed cert (or use one from your internal CA / Key Vault):

```powershell
$cert = New-SelfSignedCertificate `
    -Subject "CN=purview-dlp-cicd" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -NotAfter (Get-Date).AddYears(1)

# Public key -> upload to the App Registration
Export-Certificate -Cert $cert -FilePath ".\purview-dlp-cicd.cer"

# Private key -> becomes the GitHub secret used by Connect-IPPSSession
$pwd = ConvertTo-SecureString -String "<choose-a-strong-password>" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath ".\purview-dlp-cicd.pfx" -Password $pwd
```

Upload the public key:

- **App registration → Certificates & secrets → Certificates → Upload
  certificate** → upload `purview-dlp-cicd.cer`.
- Do **not** create a client secret — this app should be certificate-only
  (avoids a long-lived shared secret entirely).

Base64-encode the PFX for GitHub:

```bash
base64 -w0 purview-dlp-cicd.pfx > purview-dlp-cicd.pfx.b64
```

Set a short **certificate rotation reminder** (e.g. 11 months out) since
the cert above expires in 1 year — this pipeline will fail closed (auth
error) once it expires, which is the safe failure mode.

## 3. API permissions

Security & Compliance app-only auth is **not** authorized via the normal
Graph "API permissions" blade — it's granted by adding the app's service
principal to an Entra ID role.

- **Entra admin center → App registration → API permissions**: no
  delegated/application Graph permissions are required for this specific
  workflow (the script only talks to Security & Compliance PowerShell, not
  Graph). Leave this blade at its default (`User.Read` delegated, unused).
- **Entra admin center → Roles and administrators**: assign the app's
  **service principal** (not a user) the **Compliance Administrator**
  role (least privilege that can manage DLP policies/rules). If your org
  restricts role assignment further, **Security Administrator** or a
  **custom role** scoped to `microsoft.office365.protectionCenter/*` also
  works — avoid Global Administrator.

  ```powershell
  Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"
  $roleId = (Get-MgDirectoryRole -Filter "displayName eq 'Compliance Administrator'").Id
  $spId   = (Get-MgServicePrincipal -Filter "appId eq '<APPLICATION_CLIENT_ID>'").Id
  New-MgDirectoryRoleMemberByRef -DirectoryRoleId $roleId -BodyParameter @{
      "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$spId"
  }
  ```

- Role assignment can take up to **~30–60 minutes** to propagate before
  `Connect-IPPSSession` will authorize successfully — account for this the
  first time you run the pipeline.

## 4. Federated credential (for OIDC `azure/login`)

**App registration → Certificates & secrets → Federated credentials → Add
credential → GitHub Actions deploying Azure resources.**

| Field | Value |
|---|---|
| Organization | your GitHub org/user |
| Repository | `purview-dlp` (this repo) |
| Entity type | Branch |
| Branch name | `main` |
| Name | `github-actions-main` |

This trusts tokens where `subject = repo:<org>/<repo>:ref:refs/heads/main`
— i.e. only workflow runs triggered from `main` in this exact repo can
authenticate as this app. Add a second federated credential scoped to
`pull_request` only if you later want PRs to run a dry-run/plan job.

No Azure resource access (subscription roles) is actually required for
`azure/login` to succeed here — it's used purely to obtain a verified
Entra ID identity for the run; the `AZURE_SUBSCRIPTION_ID` secret can point
at any subscription associated with the tenant.

## 5. GitHub repository configuration

**Repo → Settings → Environments → New environment → `production`**
(referenced by the workflow's `environment: production`) — this lets you
add required reviewers / deployment protection rules gating this workflow
before it enables enforcement modes in the future.

**Repo → Settings → Secrets and variables → Actions**

### Secrets (encrypted)

| Secret | Value |
|---|---|
| `AZURE_CLIENT_ID` | App Registration's Application (client) ID |
| `AZURE_TENANT_ID` | Directory (tenant) ID |
| `AZURE_SUBSCRIPTION_ID` | Any Azure subscription ID under the tenant (required by `azure/login`, not otherwise used) |
| `EXO_CERT_BASE64` | Contents of `purview-dlp-cicd.pfx.b64` from step 2 |
| `EXO_CERT_PASSWORD` | The PFX password chosen in step 2 (leave the secret empty/unset if you exported without a password) |

### Variables (non-sensitive)

| Variable | Value |
|---|---|
| `EXO_ORGANIZATION` | Your tenant's default domain, e.g. `contoso.onmicrosoft.com` |

## 6. First run checklist

- [ ] App Registration created, no client secret, certificate uploaded.
- [ ] Service principal added to **Compliance Administrator** (waited for propagation).
- [ ] Federated credential added for `repo:<org>/<repo>:ref:refs/heads/main`.
- [ ] All 5 secrets + 1 variable set in the `production` environment.
- [ ] Push to `main` (or run the workflow manually via **Actions → Deploy
      Purview DLP Policies (Simulation) → Run workflow**).
- [ ] Confirm in the Microsoft Purview compliance portal
      (**Data loss prevention → Policies**) that
      `UK-Financial-PII-Protection-Simulation` exists and shows
      **Simulation** status — never **On**.

## Notes on scope and safety

- `Deploy-DLPPolicies.ps1` hard-codes the required mode to
  `TestWithoutNotifications` and **verifies** it after every apply,
  throwing (failing the workflow) if the tenant's actual state doesn't
  match. Promoting the policy to enforcement (`Mode Enable`) is
  intentionally *not* something this pipeline can do — that should be a
  separate, reviewed change once simulation results have been validated.
- The PFX is written to a temp file only for the lifetime of the
  `Connect-IPPSSession` call and is deleted in a `finally` block even if
  the run fails.
- Rotate `EXO_CERT_BASE64` / `EXO_CERT_PASSWORD` before the certificate's
  1-year expiry (see step 2).
