# AzureDO Guardrails DevSecOps Extension

Extension Version: v1.3.2 | Task Version: v2.2.3
Automated, zero-touch Dynamic Application Security Testing (DAST) for Azure DevOps pipelines.

---

## Overview

The AzureDO Guardrails DevSecOps Extension automatically injects DAST scanning into Azure DevOps pipelines without requiring pipeline YAML modifications. It enforces centralized security governance, reads repository .dast-config.yml files, and blocks builds when vulnerability thresholds are breached.

### Key Features

* Zero-Touch Injection: Automatically injects scanning via pipeline decorators based on branch/environment rules.
* Centralized Governance: Enforces organization-wide security guardrails, scan speeds, and domain restrictions via the Admin Hub.
* Security-as-Code: Developers declare target metadata and authentication via .dast-config.yml in the repository root.
* Compliance Mapping: Annotates live scan events with SOC2, PCI-DSS, DORA, ISO27001, and OWASP control references in build logs.
* Fail-Secure Design: Immediately halts builds if required configurations or authentication parameters are missing.

---

## Architecture & Component Flow

1. decorator.yml: Auto-injects the scanner task into qualifying pipeline runs.
2. index.js (Orchestrator): Downloads policy settings, merges global/project overrides, and locates .dast-config.yml.
3. moduleA.js (Gatekeeper): Validates target URLs against domain policies, enforces required auth, and registers the Invicti asset.
4. moduleB.js (Configurator): Uploads API specifications, configures scan speed, and maps credentials.
5. moduleC.js (Enforcer): Dispatches the scan, streams compliance events, generates HTML reports, and evaluates pass/fail thresholds.
6. Admin Hub (App.tsx): React-based governance dashboard inside Azure DevOps settings.

---

## Admin Hub Configuration

Access the dashboard via Project Settings -> Extensions -> Enterprise Automated DAST Engine.

| Section | Key Settings | Description |
| --- | --- | --- |
| 1. Connection | API URL, API Key | Authenticates against the Invicti platform API. |
| 2. Triggers | Branches, Environments | Defines auto-injection rules (e.g., main, Staging). |
| 3. Guardrails | Allowed Domain Regex, Require Auth, Restrict API | Hard security limits that immediately fail builds when breached. |
| 4. Thresholds | Critical, High, Medium | Max finding limits (>= comparison fails the pipeline). |
| 5. Asset Tags | Project, Repo, User, Commit | Auto-applies tracking tags to findings in Invicti. |
| 6. Compliance | SOC2, PCI-DSS, DORA, ISO27001, OWASP | Enables live compliance mapping during scan execution. |
| 7. Target Naming | Prefix, ADO metadata inclusion | Enforces standardized naming in the Invicti inventory. |

Note: Project Overrides allow administrators to adjust baseline policies for individual Azure DevOps projects using the Project Overrides tab.

---

## Developer Guide: .dast-config.yml

Create a .dast-config.yml file in your repository root. Always reference sensitive credentials using Azure DevOps variable syntax: $(VARIABLE_NAME).

### Web Application Example

target:
name: "Customer Portal Staging"
url: "[https://myapp.staging.company.com](https://myapp.staging.company.com?utm_source=gemini)"
type: "web"
scan_speed: "fast"

authentication:
type: "form"
login_url: "[https://myapp.staging.company.com/login](https://myapp.staging.company.com/login?utm_source=gemini)"
username: "dast_service_user"
password: "$(FORM_LOGIN_PASSWORD)"

### API Target Example

target:
name: "Core Platform API"
url: "[https://api.staging.company.com](https://api.staging.company.com?utm_source=gemini)"
type: "api"
api_spec_file: "src/api/openapi.json"

authentication:
type: "bearer"
bearer_token: "$(API_BEARER_TOKEN)"

### Supported Authentication Types

| Type | Required Fields |
| --- | --- |
| none | No additional parameters (fails if Admin requires auth) |
| bearer | bearer_token |
| token | auth_token |
| form | authentication.login_url, username, password |
| oauth | oauth.grant_type (client_credentials, authorization_code, or password), access_token_url, client_id, client_secret |

---

## Live Compliance Logging

Module C polls events during execution and outputs mapped compliance logs directly to the pipeline console:

[Compliance Event] [WARN] Login form detected but no authentication configured
↳ Affected Address: [http://staging.company.com/login](http://staging.company.com/login?utm_source=gemini)
↳ Control Mappings:
SOC2: CC6.1 | PCI-DSS: Req 6.4.1 | DORA: Art.9.4(d) | ISO27001: A.14.2.8 | OWASP: WSTG-ATHN-01

---

## Troubleshooting

| Issue | Likely Cause | Resolution |
| --- | --- | --- |
| DAST task doesn't run | Branch/Environment mismatch | Verify target branch/environment matches Admin Hub trigger rules. |
| 403 Error when saving Admin settings | Insufficient permissions | Ensure your user account has Project Administrator privileges. |
| YAML parsing (422) error | Unquoted inline comments | Quote string values in .dast-config.yml (e.g., type: "web"). |
| Build fails at Module A | Domain regex breach or missing auth | Check target URL against Admin domain regex or add required auth block. |
| No compliance logs appear | Frameworks disabled | Enable desired compliance frameworks under Admin Hub -> Section 6. |