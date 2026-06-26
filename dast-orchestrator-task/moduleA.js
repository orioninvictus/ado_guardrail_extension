const https = require('https');
const url = require('url');

/**
 * Module A: Resolves or provisions the target using your proven legacy schema.
 * Directly leverages server-side name filtering for idempotent asset mapping.
 */
function executeModuleA(devConfig, activePolicy) {
    return new Promise((resolve, reject) => {
        console.log("\n[Module A] Registering asset identity metadata against platform registry...");

        const baseApiUrl = (activePolicy.apiUrl || "https://platform.invicti.com").replace(/\/$/, "");
        const apiKey = activePolicy.apiKey;
        
        const targetUrl = devConfig["target.url"];
        const targetName = devConfig["target.name"] || `AzureDevOps-${Date.now()}`;

        // Exact working legacy JSON payload structure matching AssetCreateRequest spec
        const payload = {
            name: targetName,
            businessImpact: 'low',
            description: 'DAST created from Automated DevSecOps Governance Engine',
            assetType: 'target',
            assetDetail: {
                assetType: 'target',
                url: targetUrl,
                targetType: 'web',
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