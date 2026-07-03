# Invicti DevSecOps Azure Extension — Project Context

## Project Goals and Technical Specifications
* Primary Objective: Build an enterprise-grade, fully automated DAST (Dynamic Application Security Testing) pipeline orchestrator for Azure DevOps.
* Security-as-Code: Allow developers to declare target context via `.dast-config.yml` while strictly enforcing admin-defined governance.
* Multi-Tenant Governance: Admins centrally manage severity thresholds, scan speeds, domain restrictions, and mandatory authentication requirements via the Admin Hub.
* CI/CD Automation: The extension itself is built, packaged, and deployed continuously via an `azure-pipelines.yml` factory using `tfx-cli`.

## System Design, Frameworks, and Architecture Rules
* Frontend Hubs (Admin & Report): Built with React, TypeScript, and Webpack. Leverages the `azure-devops-extension-sdk`.
* Backend Orchestrator (Node.js): Vanilla Node.js using native `https` and `fs` modules to eliminate third-party dependency vulnerabilities.
* Module A (Gatekeeper): Validates domain scopes, enforces auth presence, maps ADO telemetry tags, and securely registers the asset.
* Module B (Configurator): Injects Swagger/OpenAPI specs, forces API lockdown rules, and securely maps OAuth/Form credentials.
* Module C (Enforcer): Triggers the scan, polls for status, halts on threshold breaches, and publishes the S3 HTML artifact directly to the ADO pipeline.
* Fail-Secure Philosophy: If environment metadata is missing, credentials fail, or the domain regex is breached, the orchestrator must break the build immediately.

## Naming Conventions
* JavaScript/TypeScript Variables: Use strict `camelCase`.
* Azure DevOps Pipeline Variables: Use `UPPER_SNAKE_CASE` (e.g., `DAST_API_KEY`).
* Pipeline Secret Injection: Must use the exact `$(VAR_NAME)` syntax. Cleartext credentials are strictly prohibited.
* React Components: Use `PascalCase.tsx`.

## File Structure
* `vss-extension.json`: The core Azure DevOps manifest file.
* `azure-pipelines.yml`: The CI/CD factory pipeline.
* `dast-orchestrator-task/`: Contains the Node.js backend runner (`task.json`, `index.js`, `moduleA.js`, `moduleB.js`, `moduleC.js`).
* `src/admin-hub/`: The React TypeScript application for the organizational governance dashboard.
* `src/report-tab/`: The React TypeScript application for rendering the HTML compliance artifact.