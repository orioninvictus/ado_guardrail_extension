const fs = require('fs');
const path = require('path');
const https = require('https');
const url = require('url');
const { resolveManagedIdentityConfig, acquireManagedIdentityToken, evaluateTokenCoverage, isTrue } = require('./managedIdentity');

/**
 * Module B: Configures the target asset, handles spec ingestion, 
 * resolves pipeline variable credentials safely, and maps advanced OAuth settings.
 */
async function executeModuleB(targetId, devConfig, activePolicy) {
    console.log("\n[Module B] Starting Automated Configuration & Asset Customization Lifecycle...");

    if (!targetId) {
        throw new Error("Pipeline Architecture Error: Module B executed without a valid targetId context token.");
    }

    const apiUrl = (activePolicy.apiUrl || "https://platform.invicti.com").replace(/\/$/, '');
    const apiKey = activePolicy.apiKey || process.env['DAST_API_KEY'];
    const padlocks = activePolicy.padlocks || {};

    let finalOperationResponse = { statusCode: 200, data: "{}" };

    /**
     * Helper to cleanly prevent plain-text credentials in code repositories.
     * Extracts environment variables defined as $(VARIABLE_NAME) or falling back to raw names.
     */
    const resolveSecret = (configValue) => {
        if (!configValue) return "";
        const envVarMatch = String(configValue).match(/^\$\((.*)\)$/);
        if (envVarMatch && envVarMatch[1]) {
            const varName = envVarMatch[1];
            return process.env[varName] || process.env[varName.toUpperCase()] || "";
        }
        // Fallback check to see if the value itself points to an environment variable name directly
        return process.env[configValue] || process.env[String(configValue).toUpperCase()] || configValue;
    };

    // =====================================================================
    // 🛡️ GUARDRAIL ENFORCEMENT: API SPECIFICATION LOCKDOWN
    // =====================================================================
    const targetType = (devConfig["target.type"] || "web").toLowerCase();
    let restrictApi = devConfig["target.restrict_scans_to_import_files"] === "true";
    const relativeSpecPath = devConfig["target.api_spec_file"] || devConfig["target.api_specification_path"] || devConfig["target.import_file_path"];

    if (targetType === 'api' && (padlocks.restrict_api_scans === "true" || padlocks.restrict_api_scans === true)) {
        console.log(`[✔] Governance Guardrail Active: API Specification Lockdown enabled.`);
        restrictApi = true;

        if (!relativeSpecPath) {
            const errorMsg = "SECURITY GATE BREACHED: Target Type is 'api', but no contract specification file was declared. Provide 'target.api_spec_file' to proceed.";
            console.error(`##vso[task.logissue type=error;]${errorMsg}`);
            throw new Error(errorMsg);
        }
    }

    // =====================================================================
    // 📂 LIFECYCLE COMPONENT 1: CONTRACT SPECIFICATION HANDLING
    // =====================================================================
    if (relativeSpecPath) {
        const repoRoot = process.env['BUILD_SOURCESDIRECTORY'] || process.env['BUILD_REPOSITORY_LOCALPATH'] || process.cwd();
        const fullSpecPath = path.isAbsolute(relativeSpecPath) ? relativeSpecPath : path.join(repoRoot, relativeSpecPath);

        if (!fs.existsSync(fullSpecPath)) {
            throw new Error(`Compliance Failure: Configured API Specification was not found at path: ${fullSpecPath}`);
        }

        const importFileName = devConfig["target.import_file_name"] || "azure-decorator-spec.yaml";
        const fileStat = fs.statSync(fullSpecPath);
        const fileSize = fileStat.size;

        console.log(`[Module B] Local Spec Found: ${fullSpecPath} (${fileSize} bytes)`);

        const registerEndpoint = `${apiUrl}/api/v1/targets/${targetId}/configuration/imports`;
        const registerResult = await httpRequest('POST', registerEndpoint, { name: importFileName, size: fileSize }, apiKey);
        const registerBody = JSON.parse(registerResult.data);

        if (!registerBody || !registerBody.upload_url) {
            throw new Error("Invicti Ingestion Engine Failure: Endpoint did not distribute an allocation route.");
        }

        const absoluteUploadUrl = registerBody.upload_url.startsWith('http') 
            ? registerBody.upload_url 
            : `${apiUrl}${registerBody.upload_url}`;

        const specBuffer = fs.readFileSync(fullSpecPath);
        const uploadHeaders = {
            'Content-Type': 'application/octet-stream',
            'Content-Range': `bytes 0-${fileSize - 1}/${fileSize}`,
            'Content-Disposition': `attachment; filename="${importFileName}"`
        };

        const uploadResult = await httpRequest('POST', absoluteUploadUrl, specBuffer, apiKey, uploadHeaders);
        if (![201, 202, 204].includes(uploadResult.statusCode)) {
            throw new Error(`Invicti Ingestion Error: Stream rejected with status code: ${uploadResult.statusCode}`);
        }
        console.log(`[✔] Module B Spec Ingestion: Contract attached successfully.`);
        finalOperationResponse = uploadResult;
    }

    // =====================================================================
    // ⚙️ LIFECYCLE COMPONENT 2: CONFIGURATION & SCHEMAS
    // =====================================================================
    let targetScanSpeed = "fast";
    if (activePolicy.padlocks && activePolicy.padlocks.scan_speed) {
        console.log(`[✔] Governance Guardrail: Forcing corporate scan speed profile: [${activePolicy.padlocks.scan_speed}]`);
        targetScanSpeed = activePolicy.padlocks.scan_speed;
    }

    // Initialize Payload Structures
    let loginSchema = { kind: "none" };
    let oauthSchema = undefined;
    let customHeadersArray = [];
    
    const authType = String(devConfig["target.authentication.type"] || "none").toLowerCase();

    // Contextual Resolver Strategy
    if (authType === "form" || devConfig["target.authentication.enabled"] === "true") {
        loginSchema = {
            kind: "automatic",
            credentials: {
                enabled: true,
                username: devConfig["target.authentication.username"] || "",
                password: resolveSecret(devConfig["target.authentication.password"]),
                url: devConfig["target.authentication.login_url"] || ""
            }
        };
        console.log(`[Module B] Application-level Form Login mapped securely.`);
    } 
    else if (authType === "oauth") {
        // Map common text names to platform grant integers
        // 0 = AuthorizationCode, 1 = Implicit, 2 = ClientCredentials, 3 = Password
        let grantInt = 2; 
        const rawGrant = String(devConfig["target.oauth.grant_type"] || "").toLowerCase();
        if (rawGrant.includes("code")) grantInt = 0;
        if (rawGrant.includes("implicit")) grantInt = 1;
        if (rawGrant.includes("password")) grantInt = 3;

        loginSchema = { kind: "oauth" };
        oauthSchema = {
            settings: {
                grant_type: grantInt,
                access_token_url: devConfig["target.oauth.access_token_url"] || "",
                authorization_url: devConfig["target.oauth.authorization_url"] || "",
                redirect_uri: devConfig["target.oauth.redirect_uri"] || "",
                client_id: devConfig["target.oauth.client_id"] || "",
                client_secret: resolveSecret(devConfig["target.oauth.client_secret"]),
                state: devConfig["target.oauth.state"] || "",
                scope: devConfig["target.oauth.scope"] || "",
                username: devConfig["target.oauth.username"] || "",
                password: resolveSecret(devConfig["target.oauth.password"])
            },
            bls: ""
        };
        console.log(`[Module B] Advanced OAuth 2.0 Identity Engine configuration generated.`);
    }
    else if (authType === "token" && devConfig["target.auth_token"]) {
        customHeadersArray.push({ name: "Authorization", value: `Token ${resolveSecret(devConfig["target.auth_token"])}` });
        console.log(`[Module B] Dynamic API Authorization 'Token' header assigned.`);
    } 
    else if (authType === "bearer" && devConfig["target.bearer_token"]) {
        customHeadersArray.push({ name: "Authorization", value: `Bearer ${resolveSecret(devConfig["target.bearer_token"])}` });
        console.log(`[Module B] Dynamic API Authorization 'Bearer' header assigned.`);
    }

    else if (authType === "managed_identity") {
        // Pipeline-side Managed Identity: the ADO agent pulls an Entra ID token from IMDS
        // and the target is configured with it as an Authorization header.
        const mi = resolveManagedIdentityConfig(devConfig, padlocks);
        console.log(`[Module B] Acquiring Entra ID token via Managed Identity (resource: ${mi.resource}, identity: ${mi.clientId ? 'user-assigned ' + mi.clientId : 'system-assigned / default'})...`);
        const token = await acquireManagedIdentityToken(mi);
        const c = token.claims;
        console.log(`[✔] Managed Identity token acquired (valid ~${Math.floor(token.expiresInSeconds / 60)} min). aud=${c.aud} oid=${c.oid} appid=${c.appid}`);

        const maxScanTime = parseInt(devConfig["target.max_scan_time"] || '0', 10);
        const coverage = evaluateTokenCoverage(token, maxScanTime);
        if (coverage) {
            const failOnShort = padlocks.managed_identity_fail_on_short_token === undefined || isTrue(padlocks.managed_identity_fail_on_short_token);
            if (!coverage.unbounded && failOnShort) {
                const errorMsg = `SECURITY GATE BREACHED: ${coverage.message}`;
                console.error(`##vso[task.logissue type=error;]${errorMsg}`);
                throw new Error(errorMsg);
            }
            console.warn(`##vso[task.logissue type=warning;]${coverage.message}`);
        }

        process.env['DAST_MI_TOKEN_EXPIRES_AT'] = String(token.expiresAtMs);
        customHeadersArray.push({ name: "Authorization", value: `Bearer ${token.accessToken}` });
        console.log(`[Module B] Managed Identity 'Bearer' header assigned to target configuration.`);
    }
    // Assemble Native PATCH Payload Structure matching TargetConfiguration schema
    const patchPayload = {
        limit_crawler_scope: devConfig["target.limit_crawler_scope"] !== "false",
        login: loginSchema,
        oauth: oauthSchema, 
        description: devConfig["target.description"] || "Target updated dynamically by AppSec Enterprise Automated Decorator Workflow Engine.",
        sensor: false,
        proxy: { enabled: false },
        authentication: { enabled: false },
        client_certificate_password: "",
        scan_speed: targetScanSpeed,
        case_sensitive: "no",
        technologies: [],
        custom_headers: customHeadersArray,
        custom_cookies: [],
        excluded_paths: [],
        user_agent: "",
        debug: false,
        restrict_scans_to_import_files: restrictApi
    };

    // 4. Update Remote DAST Configuration Topology
    const configurationEndpoint = `${apiUrl}/api/v1/targets/${targetId}/configuration`;
    console.log(`[Module B] Distributing platform customization updates to configuration profile registry...`);
    
    const patchResult = await httpRequest('PATCH', configurationEndpoint, patchPayload, apiKey);
    if (patchResult.statusCode < 200 || patchResult.statusCode >= 300) {
        throw new Error(`Invicti Configuration Engine Failure: Modification request rejected with code ${patchResult.statusCode}`);
    }

    finalOperationResponse = patchResult;
    console.log(`[✔] Module B Success: Target orchestration parameters updated and customized.`);
    
    return finalOperationResponse;
}

/**
 * Dependency-free HTTP Client supporting Buffers, Objects, and custom overrides
 */
function httpRequest(method, targetUrl, payload, token, dynamicHeaders = {}) {
    return new Promise((resolve, reject) => {
        const parsedUrl = url.parse(targetUrl);
        const isBuffer = Buffer.isBuffer(payload);
        const bodyData = isBuffer ? payload : (payload ? JSON.stringify(payload) : '');

        const options = {
            hostname: parsedUrl.hostname,
            port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
            path: parsedUrl.path,
            method: method,
            headers: {
                'Accept': 'application/json',
                'X-Auth': token,
                'User-Agent': 'Enterprise-DevSecOps-Engine/1.1.11'
            },
            timeout: 30000
        };

        Object.assign(options.headers, dynamicHeaders);

        if (payload && !options.headers['Content-Type']) {
            options.headers['Content-Type'] = 'application/json';
        }
        if (payload) {
            options.headers['Content-Length'] = isBuffer ? bodyData.length : Buffer.byteLength(bodyData);
        }

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                const finalizedData = data || "{}";
                resolve({ statusCode: res.statusCode, headers: res.headers, data: finalizedData });
            });
        });

        req.on('error', (err) => reject(err));
        req.on('timeout', () => { req.destroy(); reject(new Error('Network operation timed out.')); });

        if (payload) req.write(bodyData);
        req.end();
    });
}

module.exports = { executeModuleB };