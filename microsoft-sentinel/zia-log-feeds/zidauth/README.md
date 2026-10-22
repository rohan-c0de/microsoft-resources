# Zscaler ZIdentity Authentication Logs → Microsoft Sentinel (Cloud NSS)

This stands up a DCR-based ingest pipeline that lands ZIA **Authentication** logs — produced by ZIdentity, now named Authentication Services — in your Sentinel workspace's built-in `CommonSecurityLog` table via Zscaler's Cloud NSS feed.

> **The first Authentication feed takes up to 5 hours to start streaming.** This is a property of the Authentication log type, not a misconfiguration. Do not conclude the pipeline is broken because nothing has arrived after an hour. Use Step 6's smoke test to prove the Azure half works immediately, then wait.

**Repo files used (this directory):**
- `cloud-nss-zidauth.bicep` — DCE + DCR, transforming to `CommonSecurityLog`
- `cloud-nss-zidauth.bicepparam` — deployment parameters
- `cloud-nss-zidauth.fof` — Zscaler-side payload template for the Cloud NSS path
- `nss-zidauth.cef` — CEF line format for the VM/syslog path
- `nss-zidauth.workbook` — Sentinel workbook
- `../../cloud-nss-test/sample-zidauth.log` — sample record for `logtest.ps1`

---

## Prerequisites

- An Azure subscription with a Log Analytics workspace (Sentinel optional)
- Azure CLI ≥ 2.50 with the bicep extension (`az bicep version`)
- Zscaler tenant with ZIA + Cloud NSS enabled
- **Log Streaming role permissions enabled in the Authentication Service.** Without this the feed has nothing to send, and the failure is silent.
- Permissions to:
  - Deploy resources to the target subscription
  - Create an App Registration in Entra ID
  - **Assign roles on a DCR scope — this needs `Owner` or `User Access Administrator`. `Contributor` cannot assign roles**, and Step 3 will fail with an authorization error if that is all you have.
  - Configure the Zscaler admin portal

Values you'll need from Azure Portal → Log Analytics → your workspace → Overview:
Subscription ID, Resource group, Workspace name, Workspace ID (the GUID, **not** the resource ID), and Location (e.g. `australiaeast`).

---

## Step 1 — Create the App Registration Zscaler authenticates as

```bash
az ad sp create-for-rbac --name sp-zscaler-zidauth-cloudnss
```

Capture `appId`, `password`, and `tenant`. Treat the password as a secret.

---

## Step 2 — Deploy the bicep

Fill in `cloud-nss-zidauth.bicepparam`, then:

```bash
az stack group create \
  --name cloud-nss-zidauth \
  --resource-group <your-rg> \
  --parameters cloud-nss-zidauth.bicepparam \
  --deny-settings-mode 'none' \
  --action-on-unmanage deleteResources \
  --yes
```

Retrieve the ingest URL Zscaler needs:

```bash
az stack group show -g <your-rg> -n cloud-nss-zidauth --query outputs.api_url -o tsv
```

It ends in `/streams/Custom-nss_zidauth_CL?api-version=2021-11-01-preview`.

To remove the deployment later:

```bash
az stack group delete --name cloud-nss-zidauth --resource-group <your-rg> --delete-resources
```

---

## Step 3 — Grant the App Registration `Monitoring Metrics Publisher` on the DCR

Scope is the **DCR**, not the resource group.

```bash
SP_OBJECT_ID=$(az ad sp show --id <appId-from-step-1> --query id -o tsv)
DCR_ID=$(az resource show -g <your-rg> -n dcr-sentinel-cloud-zidauth \
  --resource-type Microsoft.Insights/dataCollectionRules --query id -o tsv)

az role assignment create \
  --assignee-object-id "$SP_OBJECT_ID" \
  --assignee-principal-type ServicePrincipal \
  --role 'Monitoring Metrics Publisher' \
  --scope "$DCR_ID"
```

Wait ~60 seconds for role propagation before testing.

---

## Step 4 — Configure the Zscaler portal Cloud NSS feed

ZIA admin portal → **Logs → Log Streaming → Internet Log Streaming - Nanolog Streaming Service** → **Cloud NSS Feeds** → **Add Cloud NSS Feed**.

### SIEM Connectivity

| Field | Value |
|---|---|
| **SIEM Type** | `Azure Sentinel` |
| **OAuth 2.0 Authentication** | enabled — the toggle is not editable for this SIEM type |
| **Client Id** | `<appId>` from Step 1 |
| **Client Secret** | `<password>` from Step 1 |
| **Scope** | `https://monitor.azure.com//.default` — the **double slash** before `.default` is deliberate, not a typo |
| **Grant Type** | `client_credentials` |
| **Authorization URL** | `https://login.microsoftonline.com/<tenantid>/oauth2/v2.0/token` |
| **API URL** | the `api_url` output from Step 2 |

### HTTP Headers

| Key | Value |
|---|---|
| `Content-Type` | `application/json` |

Required — the DCR ingest endpoint rejects payloads without it.

### Formatting

| Field | Value |
|---|---|
| **Log Type** | `Authentication` |
| **Feed Output Type** | `JSON` |
| **JSON Array Notation** | enabled |
| **Feed Escape Character** | `"\,` |
| **Feed Output Format** | paste the contents of `cloud-nss-zidauth.fof` |

Save and **enable** the feed. The up-to-5-hour clock starts now.

---

## Step 5 — Import the workbook

Azure Portal → Microsoft Sentinel → **Workbooks → Add workbook → Edit → Advanced Editor**: paste `nss-zidauth.workbook`, Apply, Save.

---

## Step 6 — Validate

**Before waiting on Zscaler**, prove the Azure half works on its own. Edit `../../cloud-nss-test/logtest.ps1` with your tenant/app/DCE/DCR values, set `$Table = "Custom-nss_zidauth_CL"` and `$log_file = "sample-zidauth.log"`, and run it. If this fails, the problem is in Azure, not in the Zscaler portal.

Then:

```kusto
// raw ingest sanity check
CommonSecurityLog
| where DeviceProduct == "NSSAuthenticationServiceslog"
| summarize rows=count(), latest=max(TimeGenerated)

// parsed event check
CommonSecurityLog
| where DeviceProduct == "NSSAuthenticationServiceslog"
| project TimeGenerated, Activity, DeviceAction, DeviceCustomString1, DeviceCustomString2,
          DeviceEventCategory, SourceUserName, SourceIP, EventOutcome, deviceExternalId
| top 20 by TimeGenerated desc
```

Every query against this feed must filter on `DeviceProduct`. ZIdentity Authentication and ZIA Admin Audit share almost the same field set and both land in `CommonSecurityLog`; `DeviceProduct` (`NSSAuthenticationServiceslog` vs `NSSAuditlog`) is the only thing separating them.

---

## Behaviour worth knowing before you file a bug

Three things about this feed surprise people. None is a defect.

**1. Obfuscation is a change you make, not something the feed does.**
The shipped `cloud-nss-zidauth.fof` uses `%s{resource}`, which puts the real admin identity into `SourceUserName`. If you need identities anonymized, replace it with `%s{oresource}` in your own copy of the feed output format — `o` is Zscaler's obfuscation prefix. Use one or the other, **never both**: they write the same CEF column.

Be aware of the consequence. Under `oresource`, `SourceUserName` is populated with a random string on every row. Any query that counts distinct users will return a healthy-looking number that means nothing.

**2. There is no failure-reason column.**
The Authentication log type carries no `errorcode` equivalent. The workbook can show you *that* an admin login failed, never *why*. ZIA Admin Audit has this; Authentication does not.

**3. `SourceUserName` is populated on some event types and not others.**
It is sourced from `resource`, which Zscaler documents as "the specific entity within a subcategory" — an identity for login events, but something else entirely for others. Zscaler's own sample shows `"resource":"Unknown"` on a policy-change event. This is the shape of the source data, not a mapping error.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Nothing arrives in the first few hours | Expected. The initial Authentication feed takes **up to 5 hours**. Confirm the pipeline with the `logtest.ps1` smoke test in Step 6 rather than waiting blind. |
| HTTP 403 from the Zscaler feed test | App Registration missing **Monitoring Metrics Publisher** on the DCR, or the role is still propagating (wait 60s) |
| `az role assignment create` fails with an authorization error | You have `Contributor`. Assigning roles needs `Owner` or `User Access Administrator`. |
| **Rows arrive but every field is empty** | The `.fof` in the Zscaler portal does not match the DCR stream declaration. Re-paste `cloud-nss-zidauth.fof` exactly; a single renamed or dropped key empties the whole record. |
| Rows arrive but `TimeGenerated` is wrong or missing | Year token mismatch. See the note on `%d{yy}` vs `%04d{yyyy}` below. |
| Values contain stray backslashes or quotes | Feed Escape Character. Try `"\,` first, then `"\,=`, then `,\"` — changing one value at a time. |
| `SourceUserName` is blank on many rows | Expected for non-login event types — see point 3 above. |
| `SourceUserName` is full of random strings | The feed is using `%s{oresource}`. See point 1 above. |
| ZIdentity and Admin Audit rows mixed together | A query missing its `DeviceProduct` filter. |
| No rows at all, ever | Check Log Streaming role permissions in the Authentication Service, then the portal's NSS Feed status page for delivery errors. |

### A note on the year token

`cloud-nss-zidauth.fof` builds `TimeGenerated` with `%d{yy}`, matching the other ZIA feeds in this repo. Zscaler's Authentication field reference documents `%04d{yyyy}` and does not list `%d{yy}`. If timestamps come through wrong or empty, swap **only** the year token to `%04d{yyyy}` and re-save the feed. `cloud-nss-sandbox.fof` in this repo uses the `%u{yyyy}` form as a further fallback.

---

## For the deployment guide

*The section below is written for the owner of the Zscaler and Microsoft Sentinel Deployment Guide to lay out. The PDF is not modified by this repo.*

### New row for the ZIA Log Feeds table (p.18)

| Zscaler Platform & Product | Feed Types |
|---|---|
| ZIA NSS | Authentication Logs |

### New section: Cloud NSS Feeds for Authentication Logs

For Cloud NSS Feeds for Authentication Logs, copy and paste the prepopulated Feed Output Format from the file `cloud-nss-zidauth.fof` in the Zscaler GitHub repo, or use the following:

```
\{"TimeGenerated":"%d{yy}-%02d{mth}-%02d{dd},%02d{hh}:%02d{mm}:%02d{ss}","sourcetype":"zscalernss-zid-auth","vendor":"Zscaler","product":"NSSAuthenticationServiceslog","version":"5.7","Severity":"3","name":"%s{category}","deviceEventClassId":"%s{action}","act":"%s{action}","cs1Label":"category","cs1":"%s{category}","cs2Label":"subcategory","cs2":"%s{subcategory}","cs3Label":"resource","cs3":"%s{resource}","cat":"%s{interface}","suser":"%s{resource}","src":"%s{clientip}","outcome":"%s{result}","deviceExternalId":"%d{recordid}"\}
```

Set **Log Type** to `Authentication`. All other SIEM connectivity and formatting fields follow the standard Cloud NSS settings documented for the other ZIA feeds.

Two notes specific to this feed type, worth carrying into the guide:

- The initial Authentication feed takes up to 5 hours to begin streaming.
- Log Streaming role permissions must be enabled in the Authentication Service before the feed will produce anything.
