const http = require('http');

/**
 * Managed Identity support (pipeline-side).
 *
 * The Azure DevOps agent (which must be a self-hosted agent running on an Azure VM / VMSS
 * with a system- or user-assigned managed identity) requests an Entra ID access token from
 * the Azure Instance Metadata Service (IMDS). Module B then injects that token into the
 * Invicti target configuration as an Authorization header.
 *
 * NOTE: the injected token is static for the scan. Its lifetime is read from the IMDS
 * response (expires_in) at runtime so scans that would outlive it can be flagged.
 */

const IMDS_HOST = '169.254.169.254';
const IMDS_PATH = '/metadata/identity/oauth2/token';
const IMDS_API_VERSION = '2018-02-01';

const isTrue = (v) => v === true || String(v).toLowerCase() === 'true';

/**
 * Reads the managed identity block from the flattened .dast-config.yml and applies
 * admin padlocks. Throws (fail-secure) on any violation.
 */
function resolveManagedIdentityConfig(devConfig, padlocks) {
    const pick = (...keys) => {
        for (const k of keys) {
            if (devConfig[k] !== undefined && String(devConfig[k]).trim() !== '') return String(devConfig[k]).trim();
        }
        return '';
    };

    if (padlocks.managed_identity_enabled !== undefined && !isTrue(padlocks.managed_identity_enabled)) {
        throw new Error("SECURITY GATE BREACHED: AppSec Policy Violation - Managed Identity authentication is disabled by the organization policy.");
    }

    const resource = pick(
        'target.authentication.managed_identity.resource',
        'target.managed_identity.resource',
        'target.authentication.resource'
    );
    if (!resource) {
        throw new Error("Managed Identity Configuration Error: 'managed_identity.resource' (the Entra ID Application ID URI / audience of the target) is required when authentication type is 'managed_identity'.");
    }

    if (padlocks.managed_identity_allowed_resource_regex) {
        const re = new RegExp(padlocks.managed_identity_allowed_resource_regex, 'i');
        if (!re.test(resource)) {
            throw new Error(`SECURITY GATE BREACHED: Managed Identity resource '${resource}' violates the organizational allowed resource policy (${padlocks.managed_identity_allowed_resource_regex}).`);
        }
    }

    const devClientId = pick(
        'target.authentication.managed_identity.client_id',
        'target.managed_identity.client_id',
        'target.authentication.client_id'
    );
    // Admin-forced identity always wins over the developer's choice.
    const forcedClientId = (padlocks.managed_identity_client_id || '').trim();
    const clientId = forcedClientId || devClientId;
    if (forcedClientId && devClientId && forcedClientId.toLowerCase() !== devClientId.toLowerCase()) {
        console.warn(`##vso[task.logissue type=warning;]Governance Action: developer-declared managed identity client_id ignored; organization policy enforces a specific identity.`);
    }

    if (clientId && !/^[0-9a-fA-F-]{36}$/.test(clientId)) {
        throw new Error("Managed Identity Configuration Error: 'managed_identity.client_id' must be a GUID.");
    }

    return { resource, clientId, forcedIdentity: !!forcedClientId };
}

function imdsGet(path) {
    return new Promise((resolve, reject) => {
        const req = http.request({
            host: IMDS_HOST,
            path,
            method: 'GET',
            headers: { 'Metadata': 'true' },
            timeout: 5000
        }, (res) => {
            let data = '';
            res.on('data', (c) => { data += c; });
            res.on('end', () => resolve({ statusCode: res.statusCode, body: data }));
        });
        req.on('timeout', () => { req.destroy(new Error('IMDS request timed out (is this agent running on an Azure VM with a managed identity?)')); });
        req.on('error', reject);
        req.end();
    });
}

/**
 * Acquires an access token from IMDS with retry on transient errors (404/410/429/5xx
 * per Microsoft guidance). The token is registered as a pipeline secret so it is masked in logs.
 */
async function acquireManagedIdentityToken({ resource, clientId }) {
    let path = `${IMDS_PATH}?api-version=${IMDS_API_VERSION}&resource=${encodeURIComponent(resource)}`;
    if (clientId) path += `&client_id=${encodeURIComponent(clientId)}`;

    const maxAttempts = 5;
    let lastError;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            const res = await imdsGet(path);
            if (res.statusCode === 200) {
                const parsed = JSON.parse(res.body);
                if (!parsed.access_token) throw new Error('IMDS response did not contain an access_token.');

                // Mask before anything else can print it.
                console.log(`##vso[task.setsecret]${parsed.access_token}`);

                const expiresInSeconds = parseInt(parsed.expires_in, 10) || decodeExp(parsed.access_token) - Math.floor(Date.now() / 1000);
                return {
                    accessToken: parsed.access_token,
                    expiresInSeconds,
                    expiresAtMs: Date.now() + expiresInSeconds * 1000,
                    claims: safeClaims(parsed.access_token)
                };
            }
            lastError = new Error(`IMDS returned HTTP ${res.statusCode}: ${res.body.substring(0, 300)}`);
            // 400 = bad request (e.g. unknown identity / resource); not retryable.
            if (res.statusCode === 400) break;
        } catch (err) {
            lastError = err;
        }
        if (attempt < maxAttempts) {
            const delay = Math.min(1000 * Math.pow(2, attempt - 1), 8000);
            console.log(`[Managed Identity] Token request attempt ${attempt} failed (${lastError.message}). Retrying in ${delay}ms...`);
            await new Promise(r => setTimeout(r, delay));
        }
    }
    throw new Error(`Managed Identity Token Acquisition Failure: ${lastError ? lastError.message : 'unknown error'}`);
}

function decodePayload(jwt) {
    try {
        const part = jwt.split('.')[1];
        return JSON.parse(Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    } catch (e) {
        return {};
    }
}
function decodeExp(jwt) { return parseInt(decodePayload(jwt).exp, 10) || 0; }

/** Non-sensitive claims only, for diagnostics. Signature is NOT validated here (the target does that). */
function safeClaims(jwt) {
    const p = decodePayload(jwt);
    return { aud: p.aud, iss: p.iss, tid: p.tid, oid: p.oid, appid: p.appid || p.azp, idtyp: p.idtyp, roles: p.roles };
}

/**
 * Compares token validity with the configured scan limit and returns a human message when
 * the token may expire mid-scan. Returns null when safe.
 */
function evaluateTokenCoverage(token, maxScanTimeMinutes) {
    const remainingMin = Math.floor(token.expiresInSeconds / 60);
    if (!maxScanTimeMinutes || maxScanTimeMinutes <= 0) {
        return { unbounded: true, remainingMin, message: `No max_scan_time is set; the injected token is valid for ~${remainingMin} min and will not be refreshed during the scan.` };
    }
    if (maxScanTimeMinutes > remainingMin) {
        return { unbounded: false, remainingMin, message: `max_scan_time (${maxScanTimeMinutes} min) exceeds the injected token lifetime (~${remainingMin} min). Authentication will fail after the token expires.` };
    }
    return null;
}

module.exports = { resolveManagedIdentityConfig, acquireManagedIdentityToken, evaluateTokenCoverage, isTrue };
