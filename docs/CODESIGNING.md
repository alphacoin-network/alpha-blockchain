# Code Signing — Windows binaries (SmartScreen / Smart App Control fix)

Unsigned binaries are blocked by Windows Smart App Control. Options:

| Option | Cost | Notes |
|---|---|---|
| **SignPath.io** | **FREE** | Free Authenticode signing for open-source projects; GitHub Actions integration; requires application/review |
| Certum Open Source | ~€25/yr | Cheap OV cert for qualifying OSS projects |
| Microsoft Store | ~$19 once | Microsoft signs MSIX packages; awkward for console daemons |
| Azure Trusted Signing | ~$10/mo | Fast, official; steps below |
| SHA256 + GPG | FREE | Bitcoin's original model — users verify hashes manually; warnings remain |

Every release also ships `*.sha256` checksum files automatically.

## SignPath (free) setup

1. https://signpath.io → apply for open-source signing (repo must be public —
   Alpha qualifies).
2. On approval they provide a signing policy + GitHub Actions secrets; plug
   into the `Sign Windows binaries` step in `release.yml`.

## Azure Trusted Signing setup (paid alternative)

## One-time Azure setup (~30 min + identity review)

1. **Azure account** — https://portal.azure.com → create subscription
   (free signup; card needed for verification).

2. **Create Trusted Signing account**
   - Search bar → "Trusted Signing" → Create
   - Region: East US (or nearest available)
   - Note the **account name** → this is `TRUSTED_SIGNING_ACCOUNT`
   - Endpoint shown on the resource page, e.g.
     `https://eus.codesigning.azure.net` → `TRUSTED_SIGNING_ENDPOINT`

3. **Identity validation** — on the Trusted Signing account →
   "Identity validation" → New identity
   - Business org: company legal name + registration document
     (Certificate of Incorporation / GST). Review takes 1–7 days.
   - Individual identity also supported.

4. **Create Certificate Profile** — "Certificate profiles" → Create →
   type **Public Trust** → note profile name → `TRUSTED_SIGNING_PROFILE`

5. **Create Entra app (service principal)**
   - Entra ID → App registrations → New registration → name `alpha-signing`
   - Certificates & secrets → New client secret → copy the **value**
   - Note **Application (client) ID** and **Directory (tenant) ID**

6. **Grant signing permission** — Trusted Signing account →
   Access control (IAM) → Add role assignment →
   role **"Trusted Signing Certificate Profile Signer"** →
   assign to the `alpha-signing` app.

## GitHub repo configuration

Repo → Settings → Secrets and variables → Actions:

**Secrets** (New repository secret):

| Name | Value |
|---|---|
| `AZURE_TENANT_ID` | Directory (tenant) ID |
| `AZURE_CLIENT_ID` | Application (client) ID |
| `AZURE_CLIENT_SECRET` | client secret value |

**Variables** (Variables tab → New repository variable):

| Name | Value |
|---|---|
| `SIGNING_ENABLED` | `true` |
| `TRUSTED_SIGNING_ACCOUNT` | account name from step 2 |
| `TRUSTED_SIGNING_PROFILE` | profile name from step 4 |
| `TRUSTED_SIGNING_ENDPOINT` | e.g. `https://eus.codesigning.azure.net` |

## Release

Push a new tag (`git tag v1.0.1 && git push origin v1.0.1`) — the workflow
signs `alphad.exe` and `alpha_cli.exe` automatically. Verify locally:

```powershell
Get-AuthenticodeSignature alphad.exe   # Status: Valid
```

## Notes

- `SIGNING_ENABLED` unset/`false` → workflow builds unsigned (no failure).
- Timestamping uses Microsoft's RFC3161 server, so signatures stay valid
  after the certificate rotates.
- macOS notarization is a separate flow (Apple Developer account, $99/yr)
  and not covered here.
