const fs = require('fs');
const path = require('path');
const https = require('https');
const url = require('url');

/**
 * Module B: Configures the target asset and uploads any contextual repository OpenAPI/Swagger specs.
 * Evaluates developer configurations against padlocked corporate governance profiles.
 * * @param {string} targetId - The resolved technical target identifier from Module A
 * @param {Object} devConfig - The parsed options from the local repository `.dast-config.yml`
 * @param {Object} activePolicy - The merged corporate policies resolved from the Extension Data Service
 * @returns {Promise<Object>} The configuration operation response metadata
 */
async function executeModuleB(targetId, devConfig, activePolicy) {
    console.log("\n[Module B] Starting Automated Configuration & Asset Customization Lifecycle...");

    if (!targetId) {
        throw new Error("Pipeline Architecture Error: Module B executed without a valid targetId context token.");
    }

    // 1. Resolve Infrastructure Credentials from AppSec Control Plane
    const apiUrl = (activePolicy.apiUrl || "https://platform.invicti.com").replace(/\/$/, '');
    const apiKey = activePolicy.apiKey || process.env['DAST_API_KEY'];
    const padlocks = activePolicy.padlocks || {};

    // Keep track of final execution telemetry data to pass safely back to the orchestrator plane
    let finalOperationResponse = { statusCode: 200, data: "{}" };

    // =====================================================================
    // 🛡️ GUARDRAIL ENFORCEMENT: API SPECIFICATION LOCKDOWN
    // =====================================================================
    const targetType = (devConfig["target.type"] || "web").toLowerCase();
    let restrictApi = devConfig["target.restrict_scans_to_import_files"] === "true";
    const relativeSpecPath = devConfig["target.api_spec_file"] || devConfig["target.api_specification_path"] || devConfig["target.import_file_path"];

    if (targetType === 'api' && (padlocks.restrict_api_scans === "true" || padlocks.restrict_api_scans === true)) {
        console.log(`[✔] Governance Guardrail Active: API Specification Lockdown enabled.`);
        console.log(`[Module B] Forcing 'restrict_scans_to_import_files' flag to TRUE to isolate crawling scope.`);
        restrictApi = true;

        if (!relativeSpecPath) {
            const errorMsg = "SECURITY GATE BREACHED: Target Type is 'api', but no OpenAPI/Swagger specification file was declared in .dast-config.yml. Provide 'target.api_spec_file' to continue.";
            console.error(`##vso[task.logissue type=error;]${errorMsg}`);
            throw new Error(errorMsg);
        }
    }

    // 2. Lifecycle Component 1: Context File Specification Uploads
    if (relativeSpecPath) {
        const repoRoot = process.env['BUILD_SOURCESDIRECTORY'] || process.env['BUILD_REPOSITORY_LOCALPATH'] || process.cwd();
        const fullSpecPath = path.isAbsolute(relativeSpecPath) ? relativeSpecPath : path.join(repoRoot, relativeSpecPath);

        if (!fs.existsSync(fullSpecPath)) {
            throw new Error(`Compliance Failure: Configured API Specification specification was not found at path: ${fullSpecPath}`);
        }

        const importFileName = devConfig["target.import_file_name"] || "azure-decorator-spec.yaml";
        const fileStat = fs.statSync(fullSpecPath);
        const fileSize = fileStat.size;

        console.log(`[Module B] Located local API Spec file: ${fullSpecPath} (${fileSize} bytes)`);

        // Phase A: Register Upload Slot request
        const registerEndpoint = `${apiUrl}/api/v1/targets/${targetId}/configuration/imports`;
        console.log(`[Module B] Requesting remote ingestion registration slot...`);
        
        const registerResult = await httpRequest('POST', registerEndpoint, { name: importFileName, size: fileSize }, apiKey);
        const registerBody = JSON.parse(registerResult.data);

        if (!registerBody || !registerBody.upload_url) {
            throw new Error("Invicti Spec Registration Engine Failure: Ingestion endpoint did not distribute a valid upload allocation route.");
        }

        // Phase B: Stream Binary Buffer Payload to Remote Ingestion Handle
        const absoluteUploadUrl = registerBody.upload_url.startsWith('http') 
            ? registerBody.upload_url 
            : `${apiUrl}${registerBody.upload_url}`;

        console.log(`[Module B] Uploading binary specification stream to secure target allocation point...`);
        const specBuffer = fs.readFileSync(fullSpecPath);
        
        const uploadHeaders = {
            'Content-Type': 'application/octet-stream',
            'Content-Range': `bytes 0-${fileSize - 1}/${fileSize}`,
            'Content-Disposition': `attachment; filename="${importFileName}"`
        };

        const uploadResult = await httpRequest('POST', absoluteUploadUrl, specBuffer, apiKey, uploadHeaders);
        if (![201, 202, 204].includes(uploadResult.statusCode)) {
            throw new Error(`Invicti Ingestion Error: Binary specification stream transmission rejected with status code: ${uploadResult.statusCode}`);
        }
        console.log(`[✔] Module B Spec Ingestion: API Specification successfully attached to target.`);
        finalOperationResponse = uploadResult;
    } else {
        console.log("[Module B] Zero API Specification paths declared inside local file. Skipping spec mapping phase.");
    }

    // 3. Lifecycle Component 2: Configuration & Padlock Engine Customization
    let targetScanSpeed = devConfig["target.scan_speed"] || "fast";
    if (activePolicy.padlocks && activePolicy.padlocks.scan_speed) {
        console.log(`[✔] Governance Guardrail: Overriding developer profile. Forcing padlocked scan speed: [${activePolicy.padlocks.scan_speed}]`);
        targetScanSpeed = activePolicy.padlocks.scan_speed;
    }

    // Authentication Mapping - Form Resolvers
    let loginSchema = { kind: "none" };
    const authType = devConfig["target.authentication.type"] || "none";
    
    if (authType === "form" || devConfig["target.authentication.enabled"] === "true") {
        let rawPassword = devConfig["target.authentication.password"] || "";
        const envVarMatch = rawPassword.match(/^\$\((.*)\)$/);
        if (envVarMatch && envVarMatch[1]) {
            rawPassword = process.env[envVarMatch[1]] || process.env[envVarMatch[1].toUpperCase()] || rawPassword;
        }

        loginSchema = {
            kind: "automatic",
            credentials: {
                enabled: true,
                username: devConfig["target.authentication.username"] || "",
                password: rawPassword,
                url: devConfig["target.authentication.login_url"] || ""
            }
        };
        console.log(`[Module B] Form Login Engine mapping initialized for endpoint: ${loginSchema.credentials.url}`);
    }

    // Authentication Mapping - API Header Resolvers
    let customHeadersArray = [];
    if (devConfig["target.auth_token"]) {
        customHeadersArray.push({ name: "Authorization", value: `Token ${devConfig["target.auth_token"]}` });
        console.log(`[Module B] Native 'Token' API authentication header dynamically injected.`);
    } else if (devConfig["target.bearer_token"]) {
        customHeadersArray.push({ name: "Authorization", value: `Bearer ${devConfig["target.bearer_token"]}` });
        console.log(`[Module B] Native 'Bearer' API authentication header dynamically injected.`);
    }

    // Assemble Native PATCH Payload Structure matching TargetConfiguration schema
    const patchPayload = {
        limit_crawler_scope: devConfig["target.limit_crawler_scope"] !== "false",
        login: loginSchema,
        description: devConfig["target.description"] || "Target updated dynamically by AppSec Enterprise Automated Decorator Workflow Engine.",
        sensor: false,
        proxy: { enabled: false },
        authentication: { enabled: false },
        client_certificate_password: "",
        scan_speed: targetScanSpeed,
        case_sensitive: "no",
        technologies: [],
        custom_headers: customHeadersArray, // Injected Auth Headers
        custom_cookies: [],
        excluded_paths: [],
        user_agent: "",
        debug: false,
        restrict_scans_to_import_files: restrictApi // Lock API scopes
    };

    // 4. Update Remote DAST Configuration Topology
    const configurationEndpoint = `${apiUrl}/api/v1/targets/${targetId}/configuration`;
    console.log(`[Module B] Distributing platform customization updates to configuration profile registry: ${configurationEndpoint}`);
    
    const patchResult = await httpRequest('PATCH', configurationEndpoint, patchPayload, apiKey);
    if (patchResult.statusCode < 200 || patchResult.statusCode >= 300) {
        throw new Error(`Invicti Configuration Engine Failure: Modification request rejected with code ${patchResult.statusCode}`);
    }

    // Map successful patch metadata as the final return package context
    finalOperationResponse = patchResult;

    console.log(`[✔] Module B Success: Target orchestration parameters updated and customized.`);
    
    // Explicitly return the response object back to index.js
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
                'User-Agent': 'Enterprise-DevSecOps-Engine/1.1.11',
                '...dynamicHeaders': '' // Quick cleanup artifact, see correctly spread dynamicHeaders below
            },
            timeout: 30000
        };

        // Correctly assign dynamic headers
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
                // Supply a valid JSON string fallback if the response body is empty (e.g., 204 No Content)
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