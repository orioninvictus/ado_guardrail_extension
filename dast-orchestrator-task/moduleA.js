const https = require('https');
const url = require('url');

/**
 * Module A: Asset Inventory & Guardrail Gatekeeper
 * Resolves or provisions the target using the proven legacy schema, while 
 * enforcing organizational compliance guardrails and dynamic ADO telemetry.
 */
function executeModuleA(devConfig, activePolicy) {
    return new Promise((resolve, reject) => {
        console.log("\n[Module A] Registering asset identity metadata against platform registry...");

        const baseApiUrl = (activePolicy.apiUrl || "https://platform.invicti.com").replace(/\/$/, "");
        const apiKey = activePolicy.apiKey;
        const padlocks = activePolicy.padlocks || {};
        
        const targetUrl = devConfig["target.url"];
        const targetName = devConfig["target.name"] || `AzureDevOps-${Date.now()}`;
        
        // Dynamically parse target type (defaults to 'web' if not specified)
        const targetType = (devConfig["target.type"] || "web").toLowerCase();

        if (!targetUrl) {
            return reject(new Error("AppSec Gatekeeper Error: Developer configuration is missing the mandatory 'target.url' property."));
        }

        // =====================================================================
        // 🛡️ GUARDRAIL 1: DOMAIN SCOPE (URL Allowed-Lists)
        // =====================================================================
        if (padlocks.allowed_domain_regex) {
            console.log(`[Module A] Validating target URL against corporate domain scope regex...`);
            const domainRegex = new RegExp(padlocks.allowed_domain_regex, 'i'); // Case-insensitive
            
            if (!domainRegex.test(targetUrl)) {
                const errorMsg = `SECURITY GATE BREACHED: Target URL (${targetUrl}) violates organizational allowed domain scope policy (${padlocks.allowed_domain_regex}).`;
                console.error(`##vso[task.logissue type=error;]${errorMsg}`);
                return reject(new Error(errorMsg));
            }
            console.log(`[✔] Domain scope validated.`);
        }

        // =====================================================================
        // 🛡️ GUARDRAIL 2: MANDATORY AUTHENTICATION ENFORCEMENT
        // =====================================================================
        if (padlocks.require_auth === "true" || padlocks.require_auth === true) {
            console.log(`[Module A] Validating mandatory authentication declarations...`);
            const hasAuth = devConfig["target.username"] || devConfig["target.auth_token"] || devConfig["target.bearer_token"] || devConfig["target.oauth_endpoint"];
            
            if (!hasAuth) {
                const errorMsg = "SECURITY GATE BREACHED: AppSec Policy Violation - Unauthenticated (shallow) scans are not permitted. Please supply authentication parameters in your .dast-config.yml.";
                console.error(`##vso[task.logissue type=error;]${errorMsg}`);
                return reject(new Error(errorMsg));
            }
            console.log(`[✔] Authentication parameters detected.`);
        }

        // =====================================================================
        // 🏷️ AUTOMATED ORGANIZATIONAL TAGGING
        // =====================================================================
        console.log(`[Module A] Resolving Azure DevOps telemetry tags...`);
        let generatedTags = [];
        
        if (padlocks.tag_project === "true" || padlocks.tag_project === true) {
            if (process.env['SYSTEM_TEAMPROJECT']) generatedTags.push(`ADO_Project:${process.env['SYSTEM_TEAMPROJECT']}`);
        }
        if (padlocks.tag_repo === "true" || padlocks.tag_repo === true) {
            if (process.env['BUILD_REPOSITORY_NAME']) generatedTags.push(`ADO_Repo:${process.env['BUILD_REPOSITORY_NAME']}`);
        }
        if (padlocks.tag_user === "true" || padlocks.tag_user === true) {
            if (process.env['BUILD_REQUESTEDFOR']) generatedTags.push(`ADO_User:${process.env['BUILD_REQUESTEDFOR']}`);
        }
        if (padlocks.tag_commit === "true" || padlocks.tag_commit === true) {
            if (process.env['BUILD_SOURCEVERSION']) generatedTags.push(`ADO_Commit:${process.env['BUILD_SOURCEVERSION'].substring(0, 8)}`);
        }
        
        if (padlocks.custom_tags) {
            const cTags = padlocks.custom_tags.split(',').map(t => t.trim()).filter(Boolean);
            generatedTags = generatedTags.concat(cTags);
        }

        if (devConfig["target.tags"]) {
            const dTags = devConfig["target.tags"].split(',').map(t => t.trim()).filter(Boolean);
            generatedTags = generatedTags.concat(dTags);
        }

        generatedTags = [...new Set(generatedTags)];
        console.log(`[Module A] Metadata tags generated: ${generatedTags.join(', ')}`);

        // =====================================================================
        // 📦 LEGACY ASSET REGISTRY & MAPPING
        // =====================================================================
        // Exact working legacy JSON payload structure matching AssetCreateRequest spec
        const payload = {
            name: targetName,
            businessImpact: 'low',
            description: 'DAST created from Automated DevSecOps Governance Engine',
            tags: generatedTags,
            assetType: 'target',
            assetDetail: {
                assetType: 'target',
                url: targetUrl,
                targetType: targetType, // Dynamically maps to 'web' or 'api'
                isEphemeral: false
            }
        };

        const payloadString = JSON.stringify(payload);
        const targetEndpoint = url.parse(`${baseApiUrl}/api/inventory/v1/assets`);

        const options = {
            hostname: targetEndpoint.hostname,
            path: targetEndpoint.path,
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'X-Auth': apiKey,
                'User-Agent': 'curl/8.4.0',
                'Content-Length': Buffer.byteLength(payloadString)
            }
        };

        const req = https.request(options, (res) => {
            let body = '';
            res.on('data', (chunk) => { body += chunk; });
            res.on('end', () => {
                console.log(`[Module A] Create Asset Response Status: ${res.statusCode}`);
                
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    const locationHeader = res.headers['location'] || res.headers['Location'];
                    if (!locationHeader) {
                        return reject(new Error("Asset created but no Location header was returned by Invicti."));
                    }

                    const assetId = locationHeader.split('/').pop();
                    console.log(`[Module A] Successfully parsed Asset ID from location: ${assetId}`);

                    fetchTargetOriginId(baseApiUrl, apiKey, assetId)
                        .then(targetId => resolve(targetId))
                        .catch(err => reject(err));

                } else if (res.statusCode === 400 && (body.includes("AssetNameExistInOrganizationException") || body.includes("already exist"))) {
                    // IDEMPOTENCY ROUTE: Intercept unique name duplicate conflicts
                    console.log(`[Module A] Conflict Detected: Asset Name "${targetName}" already claimed inside this organization.`);
                    console.log(`[Module A] Executing targeted server-side name query...`);
                    
                    lookupAssetByInventoryName(baseApiUrl, apiKey, targetName)
                        .then(targetId => resolve(targetId))
                        .catch(err => reject(err));
                        
                } else {
                    reject(new Error(`API request failed with code ${res.statusCode}: ${body}`));
                }
            });
        });

        req.on('error', (err) => reject(err));
        req.write(payloadString);
        req.end();
    });
}

/**
 * Fallback detail lookup query hitting explicit single-resource endpoints if needed.
 */
function fetchTargetOriginId(baseApiUrl, apiKey, assetId) {
    return new Promise((resolve, reject) => {
        const targetEndpoint = url.parse(`${baseApiUrl}/api/inventory/v1/assets/${assetId}`);
        
        const options = {
            hostname: targetEndpoint.hostname,
            path: targetEndpoint.path,
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'X-Auth': apiKey,
                'User-Agent': 'curl/8.4.0'
            }
        };

        https.get(options, (res) => {
            let body = '';
            res.on('data', (chunk) => { body += chunk; });
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    try {
                        const assetData = JSON.parse(body);
                        if (!assetData.originIds || !Array.isArray(assetData.originIds) || assetData.originIds.length === 0) {
                            return reject(new Error(`No operational origin Target IDs returned for asset mapping: ${assetId}`));
                        }
                        resolve(assetData.originIds[0]);
                    } catch (e) {
                        reject(new Error(`Failed parsing asset validation body: ${e.message}`));
                    }
                } else {
                    reject(new Error(`Asset verification lookup failed with status: ${res.statusCode}`));
                }
            });
        }).on('error', (err) => reject(err));
    });
}

/**
 * Server-Side Filtered Resolution Engine
 * Executes GET /api/inventory/v1/assets?name={targetName}&pageSize=50&pageNumber=1 exactly like your working curl test.
 */
function lookupAssetByInventoryName(baseApiUrl, apiKey, targetName) {
    return new Promise((resolve, reject) => {
        const inventoryFilterPath = `/api/inventory/v1/assets?name=${encodeURIComponent(targetName)}&pageSize=50&pageNumber=1`;
        const directoryEndpoint = url.parse(`${baseApiUrl}${inventoryFilterPath}`);

        const options = {
            hostname: directoryEndpoint.hostname,
            path: directoryEndpoint.path,
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'X-Auth': apiKey,
                'User-Agent': 'curl/8.4.0',
                'X-Correlation-ID': '68d46790-d42f-4666-aecb-18e48d656e31'
            }
        };

        https.get(options, (res) => {
            let body = '';
            res.on('data', (chunk) => { body += chunk; });
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    try {
                        const responsePayload = JSON.parse(body);
                        const assetItems = responsePayload.items || [];
                        
                        // Strict validation match against the items array
                        const matchedRecord = assetItems.find(item => item && item.name === targetName);

                        if (matchedRecord) {
                            const originIds = matchedRecord.originIds || [];
                            if (originIds.length > 0 && originIds[0]) {
                                const resolvedTargetId = originIds[0];
                                console.log(`[Module A] ✅ Existing footprint mapped. Target ID successfully resolved: ${resolvedTargetId}`);
                                resolve(resolvedTargetId);
                            } else {
                                console.log(`[Module A] Asset located but origin summary empty. Re-routing to detail processor...`);
                                fetchTargetOriginId(baseApiUrl, apiKey, matchedRecord.id)
                                    .then(resolve)
                                    .catch(reject);
                            }
                        } else {
                            reject(new Error(`Inventory sync failure: Name filter query returned an empty items collection index.`));
                        }
                    } catch (e) {
                        reject(new Error(`Failed parsing inventory JSON response schema: ${e.message}`));
                    }
                } else {
                    reject(new Error(`Inventory search query failed with platform response status: ${res.statusCode}`));
                }
            });
        }).on('error', (err) => reject(err));
    });
}

module.exports = { executeModuleA };