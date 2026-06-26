const fs = require('fs');
const path = require('path');
const https = require('https');
const url = require('url');

const { executeModuleA } = require('./moduleA');
const { executeModuleB } = require('./moduleB');
const { executeModuleC } = require('./moduleC');

const env = {
    accessToken: process.env['INPUT_SYSTEMACCESSTOKEN'] || process.env['SYSTEM_ACCESSTOKEN'],
    collectionUrl: process.env['SYSTEM_COLLECTIONURI'],
    projectId: process.env['SYSTEM_TEAMPROJECTID'],
    projectName: process.env['SYSTEM_TEAMPROJECT'],
    repoPath: process.env['BUILD_SOURCESDIRECTORY'] || process.env['BUILD_REPOSITORY_LOCALPATH'] || process.cwd(),
    publisherId: "ercumentekim",
    extensionId: "enterprise-secure-by-default-dast"
};

async function run() {
    console.log("=================================================================");
    console.log(" 🛡️  AppSec Security-as-Code Guardrail & Automated DAST Engine ");
    console.log("=================================================================");

    try {
        // Telemetry: Print out ground zero
        console.log(`[Diagnostic] Current working directory (cwd): ${process.cwd()}`);
        console.log(`[Diagnostic] Target lookup root path: ${env.repoPath}`);

        // 1. Synchronize Policy Framework from Extension Storage Data Plane
        console.log("[…] Synchronizing administrative configuration footprints from Extension Data Plane...");
        const globalPolicy = await fetchPolicyDocument("global-policy-collection", "baseline");
        const projectPolicy = await fetchPolicyDocument(`project-${env.projectId}-collection`, "override");

        const activePolicy = { 
            ...globalPolicy, 
            ...projectPolicy,
            padlocks: { ...(globalPolicy.padlocks || {}), ...(projectPolicy.padlocks || {}) }
        };
        console.log("[✔] Governance parameters successfully downloaded and synchronized.");

        // 2. Evaluate Gatekeeper Filters & Injection Constraints
        console.log("[…] Evaluating corporate injection constraints against active runtime telemetry...");
        const constraints = activePolicy.injection_constraints || { 
            enabled_branches: [], 
            enabled_environments: [], 
            strict_mode_enabled: false,
            detection_methods: ['deployment_job', 'native_env_object', 'pipeline_variable']
        };
        
        const pipelineBranch = process.env['BUILD_SOURCEBRANCH'] || ''; 
        
        // Dynamic Context Resolver Loop using the Admin-Hub strategy configuration array
        const detectionMethods = constraints.detection_methods || ['deployment_job', 'native_env_object', 'pipeline_variable'];
        let pipelineEnv = '';
        let matchedStrategy = '';

        const strategyMap = {
            'deployment_job': process.env['ENVIRONMENT_RESOURCE_NAME'],
            'native_env_object': process.env['ENVIRONMENT_NAME'],
            'pipeline_variable': process.env['Environment.Name'] || process.env['ENVIRONMENT.NAME']
        };

        for (const method of detectionMethods) {
            const value = strategyMap[method];
            if (value && value.trim() !== '') {
                pipelineEnv = value.trim();
                matchedStrategy = method;
                break;
            }
        }
        
        const isContextMissing = !pipelineEnv || pipelineEnv.trim() === '';

        if (!isContextMissing) {
            console.log(`[✔] Environment context resolved via strategy [${matchedStrategy}]: ${pipelineEnv}`);
        } else {
            console.log(`[Diagnostic] No environment context could be resolved using active methods: ${detectionMethods.join(', ')}`);
        }

        // Fail-Secure Rule: Intercept missing context blocks if Strict Mode is enabled
        if (isContextMissing && constraints.strict_mode_enabled) {
            logError("SECURITY POLICY VIOLATION: Environment tracking metadata missing under active Strict Context Mode.");
            logError(`Action Required: Explicit metadata must be visible via the active strategy filters: [${detectionMethods.join(', ')}].`);
            process.exit(1);
        }

        // Evaluate Branch Patterns (Supports basic wildcard '*' checking)
        const isBranchAllowed = (constraints.enabled_branches || []).some(allowedBranch => {
            if (allowedBranch.includes('*')) {
                const regexMatch = new RegExp('^' + allowedBranch.replace(/\*/g, '.*') + '$');
                return regexMatch.test(pipelineBranch);
            }
            return allowedBranch === pipelineBranch;
        });

        // Evaluate Environment Names
        const isEnvAllowed = (constraints.enabled_environments || []).some(allowedEnv => {
            return allowedEnv.toLowerCase() === pipelineEnv.toLowerCase();
        });

        // Clean Bypass Route: Only bypass if it doesn't match rules AND context is provided.
        // If context is missing but strict mode is false, we proceed down to protect the asset by running the scan.
        if (!isBranchAllowed && !isEnvAllowed && !isContextMissing) {
            console.log("\n=========================================================================");
            console.log("ℹ️ [AppSec Bypass Notice] Pipeline context does not match corporate tracking criteria.");
            console.log(`   - Current Branch: ${pipelineBranch}`);
            console.log(`   - Current Environment: ${pipelineEnv}`);
            console.log("   DAST Automated Engine execution bypassed safely. Moving to next stage.");
            console.log("=========================================================================\n");
            process.exit(0); 
        }

        console.log("[✔] Telemetry match validated. Launching mandatory DAST core execution blocks...");

        // 3. Configuration Scoping (Now safely evaluated only on targeted pipelines)
        const configPath = locateDastConfig(env.repoPath);
        
        if (!configPath) {
            logError("FAIL: Organizational Compliance Violation. Root 'dast-config.yml' is missing.");
            logError("Action Required: AppSec mandates all designated deployments or tags must possess a valid root-level DAST configuration schema layout.");
            
            printDirectoryContents(env.repoPath);
            process.exit(1); 
        }
        
        const devConfig = parseYamlLight(fs.readFileSync(configPath, 'utf8'));

        validateAndEnforceRules(devConfig, activePolicy);

        // 4. Sequential Core Module Execution Chain
        const targetId = await executeModuleA(devConfig, activePolicy);
        
        if (!targetId) {
            throw new Error("Target Resolution Error: Module A failed to yield a valid operational target tracking token.");
        }

        await executeModuleB(targetId, devConfig, activePolicy);
        await executeModuleC(targetId, devConfig, activePolicy);

        console.log("\n[✔] Automated AppSec Gate Execution finalized cleanly. Pipeline context safe to proceed.");
    } catch (error) {
        logError(`Orchestration Engine Exception Failure: ${error.message}`);
        process.exit(1);
    }
}

/**
 * Searches the folder for both .dast-config.yml and dast-config.yml formats
 */
function locateDastConfig(rootPath) {
    const fileNames = ['.dast-config.yml', 'dast-config.yml'];
    
    for (const name of fileNames) {
        const fullPath = path.join(rootPath, name);
        if (fs.existsSync(fullPath)) {
            console.log(`[✔] Located developer DAST configuration file: ${fullPath}`);
            return fullPath;
        }
    }

    try {
        const items = fs.readdirSync(rootPath, { withFileTypes: true });
        for (const item of items) {
            if (item.isDirectory() && !item.name.startsWith('.')) {
                for (const name of fileNames) {
                    const nestedPath = path.join(rootPath, item.name, name);
                    if (fs.existsSync(nestedPath)) {
                        console.log(`[✔] Match found in subfolder: s/${item.name}/${name}`);
                        const confirmedRepoRoot = path.join(rootPath, item.name);
                        env.repoPath = confirmedRepoRoot;
                        process.env['BUILD_REPOSITORY_LOCALPATH'] = confirmedRepoRoot;
                        process.env['BUILD_SOURCESDIRECTORY'] = confirmedRepoRoot;
                        return nestedPath;
                    }
                }
            }
        }
    } catch (err) {}

    return null;
}

function printDirectoryContents(dirPath) {
    try {
        console.log(`\n--- [Diagnostic Logs] Files detected inside directory: ${dirPath} ---`);
        const files = fs.readdirSync(dirPath);
        if (files.length === 0) console.log(" (Directory is empty) ");
        files.forEach(file => console.log(` -> ${file}`));
        console.log("-----------------------------------------------------------------------\n");
    } catch (e) {
        console.log(`Unable to read directory files: ${e.message}`);
    }
}

function validateAndEnforceRules(devConfig, activePolicy) {
    console.log("[…] Inspecting configuration map properties against padlocked parameters...");
    const padlocks = activePolicy.padlocks || {};
    
    const userSpeed = devConfig["target.scan_speed"] || "fast";
    if (padlocks.scan_speed && userSpeed !== padlocks.scan_speed) {
        logWarn(`[!] Guardrail Alert: Repository configuration declared scan_speed as '${userSpeed}'.`);
        logWarn(`    AppSec Management has padlocked this organizational boundary to: '${padlocks.scan_speed}'.`);
        devConfig["target.scan_speed"] = padlocks.scan_speed;
        console.log(`[✔] Governance Action: Enforced corporate baseline scan speed profile: ${devConfig["target.scan_speed"]}`);
    }

    const evaluationUrl = devConfig["target.url"] || devConfig["target.authentication.login_url"];
    if (!evaluationUrl) {
        throw new Error("Local Configuration Validation Exception: DAST engine targets must specify an operation URL reference.");
    }
    console.log("[✔] Local configuration audit checks finalized.");
}

function fetchPolicyDocument(collection, documentId) {
    return new Promise((resolve) => {
        if (!env.accessToken || !env.collectionUrl) {
            logWarn(`Missing operational Azure DevOps Pipeline Access Tokens. Reverting to local fallback governance presets.`);
            return resolve(getFallbackPolicy(documentId));
        }

        let baseStorageUrl = env.collectionUrl.replace(/\/$/, "");
        if (baseStorageUrl.includes("dev.azure.com")) {
            baseStorageUrl = baseStorageUrl.replace("https://dev.azure.com", "https://extmgmt.dev.azure.com");
        } else if (baseStorageUrl.includes(".visualstudio.com")) {
            baseStorageUrl = baseStorageUrl.replace(".visualstudio.com", ".extmgmt.visualstudio.com");
        }

        const apiPath = `/_apis/ExtensionManagement/InstalledExtensions/${env.publisherId}/${env.extensionId}/Data/Scopes/Default/Current/Collections/${collection}/Documents/${documentId}?api-version=7.1-preview.1`;
        const requestUrl = `${baseStorageUrl}${apiPath}`;

        console.log(`[Data Service API Request] URL: ${requestUrl}`);

        const options = {
            headers: {
                'Authorization': `Bearer ${env.accessToken}`,
                'Accept': 'application/json',
                'User-Agent': 'Enterprise-DAST-Orchestrator-Task-Core'
            }
        };

        https.get(requestUrl, options, (res) => {
            let bodyData = '';
            res.on('data', (chunk) => { bodyData += chunk; });
            res.on('end', () => {
                console.log(`[Data Service API Response] Collection: ${collection} | HTTP Status Code: ${res.statusCode}`);
                
                if (res.statusCode === 200) {
                    try {
                        const parsedData = JSON.parse(bodyData);
                        console.log(`[Data Service API Check] Found document record. API Key Present in DB: ${!!parsedData.apiKey}`);
                        resolve(parsedData);
                    } catch (e) {
                        console.log(`[Data Service Error] Failed to parse JSON body: ${e.message}`);
                        resolve(getFallbackPolicy(documentId));
                    }
                } else {
                    console.log(`[Data Service Target Warning] Non-200 received. Raw Response Snippet: ${bodyData.substring(0, 200)}`);
                    resolve(getFallbackPolicy(documentId));
                }
            });
        }).on('error', (err) => {
            console.log(`[Data Service Network Failure] ${err.message}`);
            resolve(getFallbackPolicy(documentId));
        });
    });
}

function parseYamlLight(yamlText) {
    const result = {};
    const lines = yamlText.split(/\r?\n/);
    const stack = [];

    for (let line of lines) {
        const indent = line.search(/\S/);
        if (indent === -1) continue;
        const clean = line.trim();
        if (clean.startsWith('#') || clean.startsWith('---')) continue;

        while (stack.length > 0 && stack[stack.length - 1].indent >= indent) { stack.pop(); }

        const sep = clean.indexOf(':');
        if (sep === -1) continue;

        const key = clean.substring(0, sep).trim();
        const val = clean.substring(sep + 1).trim().replace(/^["']|["']$/g, '');
        const parent = stack.length > 0 ? stack[stack.length - 1].path : '';
        const currentPath = parent ? `${parent}.${key}` : key;

        if (val === '') { stack.push({ indent, path: currentPath }); } else { result[currentPath] = val; }
    }
    return result;
}

function getFallbackPolicy(id) {
    // For project-level overrides that don't exist, return empty policy
    // This prevents overwriting the global policy with defaults
    if (id === "override") {
        return { 
            id: id,
            padlocks: {}
        };
    }
    
    // For global baseline, return full defaults only if it's truly missing
    return {
        id: id,
        apiUrl: "https://platform.invicti.com",
        default_criticality: "low",
        injection_constraints: {
            enabled_branches: ["refs/heads/main", "refs/heads/master", "refs/heads/release/*"],
            enabled_environments: ["Staging", "UAT"],
            strict_mode_enabled: false,
            detection_methods: ["deployment_job", "native_env_object", "pipeline_variable"]
        },
        padlocks: {
            scan_speed: "fast",
            critical_threshold: "1",
            high_threshold: "3",
            medium_threshold: "5",
            fail_build_on_findings: "true",
            abort_scan_on_findings: "false",
            generate_report: "true",
            report_template_id: "11111111-1111-1111-1111-111111111111"
        }
    };
}

function logError(msg) { console.error(`##vso[task.logissue type=error;]${msg}`); }
function logWarn(msg) { console.warn(`##vso[task.logissue type=warning;]${msg}`); }

run();