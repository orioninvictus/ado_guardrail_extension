const fs = require('fs');
const path = require('path');
const https = require('https');
const url = require('url');

// =====================================================================
// 📋 COMPLIANCE FRAMEWORK EVENT MAP
// Maps Invicti scan event kinds → relevant compliance control references.
// Admins select which frameworks to enable in the Admin Hub.
// =====================================================================
const COMPLIANCE_EVENT_MAP = {
    'httpwrn_no_credentials': {
        severity: 'WARN',
        summary: 'HTTP authentication required but no credentials configured for this endpoint',
        frameworks: {
            'SOC2':    ['CC6.1 - Logical Access Controls', 'CC6.6 - Points of External Access'],
            'PCI-DSS': ['Req 6.4.1 - Authenticated vulnerability scanning required', 'Req 8.2.1 - Strong authentication enforced'],
            'DORA':    ['Art.9.4(d) - ICT security testing must cover authenticated paths'],
            'ISO27001':['A.9.4.1 - Information access restriction'],
            'OWASP':   ['WSTG-ATHN-01 - Testing for Credentials Transported over Encrypted Channel']
        }
    },
    'al_error': {
        severity: 'WARN',
        summary: 'Automatic login session timed out — authenticated scan coverage incomplete',
        frameworks: {
            'SOC2':    ['CC6.1 - Logical and Physical Access Controls', 'CC6.6 - Logical Access Security Measures'],
            'PCI-DSS': ['Req 6.4.1 - Authenticated scanning for cardholder data systems'],
            'DORA':    ['Art.9.4(d) - Security testing with authentication verification'],
            'ISO27001':['A.9.4.3 - Password management system', 'A.14.2.8 - System security testing'],
            'OWASP':   ['WSTG-ATHN-01 - Authentication Testing']
        }
    },
    'ls_error': {
        severity: 'WARN',
        summary: 'Login script execution failed — authenticated scan coverage may be incomplete',
        frameworks: {
            'SOC2':    ['CC6.1 - Logical Access Controls'],
            'PCI-DSS': ['Req 6.4.1 - Authenticated scanning', 'Req 8.2 - User Identification and Authentication'],
            'DORA':    ['Art.9.4(d) - ICT Security Testing scope'],
            'ISO27001':['A.9.4.3 - Password management', 'A.14.2.8 - System security testing'],
            'OWASP':   ['WSTG-SESS-01 - Session Management Testing']
        }
    },
    'form_detected_noLsr_noAl': {
        severity: 'WARN',
        summary: 'Login form detected but no authentication method configured — private areas NOT scanned',
        frameworks: {
            'SOC2':    ['CC6.1 - Logical Access Controls', 'CC6.6 - External Access Points'],
            'PCI-DSS': ['Req 6.4.1 - Authenticated scan required for in-scope systems', 'Req 11.3.1 - Penetration testing scope coverage'],
            'DORA':    ['Art.9.4(d) - Comprehensive ICT security testing coverage'],
            'ISO27001':['A.14.2.8 - System security testing', 'A.9.4.1 - Information access restriction'],
            'OWASP':   ['WSTG-ATHN-01 - Authentication Testing', 'WSTG-ATHN-10 - Testing for Weaker Authentication in Alternative Channel']
        }
    },
    'preflight_notification': {
        severity: 'INFO',
        summary: 'Pre-flight notification received from scanner (connectivity, redirect, or auth status)',
        frameworks: {
            'SOC2':    ['CC7.1 - System Monitoring and Change Detection'],
            'PCI-DSS': ['Req 11.3.1 - External penetration test execution and connectivity verification'],
            'ISO27001':['A.12.6.1 - Technical vulnerability management']
        }
    },
    'importer_out_of_scope': {
        severity: 'INFO',
        summary: 'Imported URL is outside defined scan scope boundary — not tested',
        frameworks: {
            'PCI-DSS': ['Req 11.3.1 - Define and document penetration testing scope'],
            'DORA':    ['Art.25.1 - Threat-Led Penetration Testing (TLPT) scope definition'],
            'ISO27001':['A.12.6.1 - Technical vulnerability management scope']
        }
    },
    'antivirus_found': {
        severity: 'INFO',
        summary: 'Security software (antivirus/EDR) detected on scanner host environment',
        frameworks: {
            'SOC2':    ['CC6.8 - Prevention of Unauthorized or Malicious Software'],
            'ISO27001':['A.12.2.1 - Controls against malware']
        }
    }
};

/**
 * Module C: Hardened Governance Engine
 * Validates scan findings, manages report artifacts, and executes pipeline gates.
 * Supports dynamic target scanning and compliance-tagged event logging.
 */
async function executeModuleC(targetId, devConfig, activePolicy) {
    console.log("\n[Module C] Starting Automated Scan Trigger & Lifecycle Monitoring Engine...");

    const policyPadlocks = activePolicy.padlocks || {};

    const getVal = (key, fallback) => {
        if (policyPadlocks[key] !== undefined) return policyPadlocks[key];
        if (devConfig[`target.${key}`] !== undefined) return devConfig[`target.${key}`];
        if (devConfig[key] !== undefined) return devConfig[key];
        return fallback;
    };

    if (!targetId) {
        throw new Error("Pipeline Architecture Error: Module C executed without a valid targetId context.");
    }

    const apiUrl = (activePolicy.apiUrl || "https://platform.invicti.com").replace(/\/$/, '');
    const apiKey = activePolicy.apiKey || process.env['DAST_API_KEY'];
    const profileId = getVal('profile_id', '11111111-1111-1111-1111-111111111111');

    const criticalThreshold = parseInt(getVal('critical_threshold', '0'), 10);
    const highThreshold     = parseInt(getVal('high_threshold', '0'), 10);
    const mediumThreshold   = parseInt(getVal('medium_threshold', '5'), 10);

    const failBuildOnFindings  = String(getVal('fail_build_on_findings', 'true')) === 'true';
    const abortScanOnFindings  = String(getVal('abort_scan_on_findings', 'false')) === 'true';

    const generateReport    = String(getVal('generate_report', 'true')) === 'true';
    const reportTemplateId  = getVal('report_template_id', '11111111-1111-1111-1111-111111111111');

    // Compliance frameworks enabled by the admin (array of strings e.g. ["SOC2","PCI-DSS"])
    const enabledFrameworks = Array.isArray(policyPadlocks.compliance_frameworks)
        ? policyPadlocks.compliance_frameworks
        : [];
    const complianceEnabled = enabledFrameworks.length > 0;

    if (complianceEnabled) {
        console.log(`[Module C] Compliance logging active for: ${enabledFrameworks.join(', ')}`);
    }

    console.log(`[Module C] Governance Guardrail Active Thresholds:`);
    console.log(`    -> Critical: ${criticalThreshold} | High: ${highThreshold} | Medium: ${mediumThreshold}`);
    console.log(`    -> Fail Build: ${failBuildOnFindings} | Abort Scan: ${abortScanOnFindings}`);

    // =====================================================================
    // 🏷️ AUTOMATED ORGANIZATIONAL SCAN TAGGING
    // =====================================================================
    console.log(`[Module C] Resolving Azure DevOps telemetry tags for active scan...`);
    let generatedTags = [];

    if (policyPadlocks.tag_project === "true" || policyPadlocks.tag_project === true) {
        if (process.env['SYSTEM_TEAMPROJECT']) generatedTags.push(`ADO_Project:${process.env['SYSTEM_TEAMPROJECT']}`);
    }
    if (policyPadlocks.tag_repo === "true" || policyPadlocks.tag_repo === true) {
        if (process.env['BUILD_REPOSITORY_NAME']) generatedTags.push(`ADO_Repo:${process.env['BUILD_REPOSITORY_NAME']}`);
    }
    if (policyPadlocks.tag_user === "true" || policyPadlocks.tag_user === true) {
        if (process.env['BUILD_REQUESTEDFOR']) generatedTags.push(`ADO_User:${process.env['BUILD_REQUESTEDFOR']}`);
    }
    if (policyPadlocks.tag_commit === "true" || policyPadlocks.tag_commit === true) {
        if (process.env['BUILD_SOURCEVERSION']) generatedTags.push(`ADO_Commit:${process.env['BUILD_SOURCEVERSION'].substring(0, 8)}`);
    }

    if (policyPadlocks.custom_tags) {
        const cTags = policyPadlocks.custom_tags.split(',').map(t => t.trim()).filter(Boolean);
        generatedTags = generatedTags.concat(cTags);
    }

    if (devConfig["target.tags"]) {
        const dTags = devConfig["target.tags"].split(',').map(t => t.trim()).filter(Boolean);
        generatedTags = generatedTags.concat(dTags);
    }

    generatedTags = [...new Set(generatedTags)];

    // =====================================================================
    // ⚡ DYNAMIC TARGET DETECTION
    // When target.dynamic=true the scan must include the live 'address' field.
    // =====================================================================
    const isDynamic = devConfig["target.dynamic"] === "true";

    // =====================================================================
    // ⚙️ INCREMENTAL SCAN ENFORCEMENT
    // =====================================================================
    const enforceIncremental = String(policyPadlocks.incremental_mode) === "true";
    const isIncremental = enforceIncremental || (devConfig["target.incremental"] === 'true');

    // =====================================================================
    // 1. DISPATCH SCAN
    // =====================================================================
    const scanPayload = {
        user_authorized_to_scan: "yes",
        target_id: targetId,
        profile_id: profileId,
        report_template_id: reportTemplateId,
        max_scan_time: parseInt(devConfig["target.max_scan_time"] || '0', 10),
        incremental: isIncremental,
        tags: generatedTags
    };

    if (isDynamic) {
        // Dynamic scans require a time-sensitive schedule and the live address
        scanPayload.schedule = {
            disable: false,
            time_sensitive: true,
            history_limit: 10,
            triggerable: false
        };
        scanPayload.address = devConfig["target.url"];
        console.log(`[Module C] Dynamic scan mode: injecting live address "${devConfig["target.url"]}" into scan payload.`);
    } else {
        scanPayload.schedule = { disable: false };
    }

    const scanInitResult = await httpRequest('POST', `${apiUrl}/api/v1/scans`, scanPayload, apiKey);
    const scanInitBody = JSON.parse(scanInitResult.data);
    const scanId = scanInitBody.scan_id;

    if (!scanId) throw new Error(`Platform failed to initialize. Response: ${scanInitResult.data}`);
    console.log(`[✔] Scan initialized${isDynamic ? ' (Dynamic)' : ''}${isIncremental ? ' (Incremental)' : ''}. ID: ${scanId}`);

    // =====================================================================
    // 2. POLLING & COMPLIANCE EVENT LOOP
    // =====================================================================
    const scanStatusUrl = `${apiUrl}/api/v1/scans/${scanId}`;
    let scanStatus = 'queued';
    let pollCount = 0;
    const maxPollAttempts = 60; // Up to 30 mins

    // Track seen event IDs so we never log the same event twice across polls
    const seenEventIds = new Set();
    let currentScanSessionId = null;

    while (!['completed', 'failed', 'aborted'].includes(scanStatus) && pollCount < maxPollAttempts) {
        await new Promise(r => setTimeout(r, 30000));
        pollCount++;

        const pollRes = await httpRequest('GET', scanStatusUrl, null, apiKey);
        const pollData = JSON.parse(pollRes.data);
        const session = pollData.current_session || {};
        scanStatus = (session.status || 'unknown').toLowerCase();

        const counts = session.severity_counts || {};
        const c = parseInt(counts.critical || 0, 10);
        const h = parseInt(counts.high || 0, 10);
        const m = parseInt(counts.medium || 0, 10);

        console.log(`[Module C] Attempt ${pollCount}: Status=${scanStatus.toUpperCase()} | Findings -> C:${c}, H:${h}, M:${m}`);

        // Capture scan_session_id as soon as it becomes available
        if (session.scan_session_id && session.scan_session_id !== currentScanSessionId) {
            currentScanSessionId = session.scan_session_id;
        }

        // Fetch and log compliance events if frameworks are enabled and session ID is known
        if (complianceEnabled && currentScanSessionId) {
            await fetchAndLogComplianceEvents(apiUrl, apiKey, currentScanSessionId, enabledFrameworks, seenEventIds);
        }

        // Immediate Enforcement Gate
        const criticalBreached = (criticalThreshold > 0 && c >= criticalThreshold);
        const highBreached     = (highThreshold > 0 && h >= highThreshold);
        const mediumBreached   = (mediumThreshold > 0 && m >= mediumThreshold);

        if (criticalBreached || highBreached || mediumBreached) {
            console.log(`\n⚠️  [Guardrail Trigger] Security threshold breach detected!`);

            if (abortScanOnFindings && scanStatus !== 'aborted') {
                console.log(`[🛑] Aborting active scan on platform to conserve engine resources...`);
                await httpRequest('POST', `${scanStatusUrl}/abort`, {}, apiKey);
                scanStatus = 'aborted';
            }
            break; // Exit loop — generate report before failing build
        }
    }

    // =====================================================================
    // CRITICAL ALIGNMENT: 40 Second Finalization Delay
    // =====================================================================
    if (['completed', 'aborted'].includes(scanStatus)) {
        console.log(`[Module C] Scan halted. Sleeping 40s to allow backend data to finalize for reporting...`);
        await new Promise(r => setTimeout(r, 40000));
    }

    // Fetch final canonical data and extract Session ID for report
    const finalData = await fetchFinalScanData(scanStatusUrl, apiKey);
    const finalCounts = finalData.counts;
    const scanSessionId = finalData.scanSessionId || currentScanSessionId;

    if (!scanSessionId) {
        console.log(`[Module C Warning] Could not resolve a valid scan_session_id. Report rendering may fail.`);
    }

    // Do a final compliance event sweep after scan ends
    if (complianceEnabled && scanSessionId) {
        console.log(`\n[Module C] Final compliance event sweep...`);
        await fetchAndLogComplianceEvents(apiUrl, apiKey, scanSessionId, enabledFrameworks, seenEventIds);
    }

    // =====================================================================
    // 3. REPORT GENERATION & ARTIFACT PUBLISHING
    // =====================================================================
    if (generateReport && scanSessionId && ['completed', 'aborted'].includes(scanStatus)) {
        await runReportPipeline(apiUrl, apiKey, scanSessionId, reportTemplateId, devConfig["target.name"]);
    }

    // =====================================================================
    // 4. FINAL SECURITY GATE (fail build AFTER report is safely attached)
    // =====================================================================
    const finalCriticalBreach = (criticalThreshold > 0 && finalCounts.c >= criticalThreshold);
    const finalHighBreach     = (highThreshold > 0 && finalCounts.h >= highThreshold);
    const finalMediumBreach   = (mediumThreshold > 0 && finalCounts.m >= mediumThreshold);

    if ((finalCriticalBreach || finalHighBreach || finalMediumBreach) && failBuildOnFindings) {
        const errorMsg = `SECURITY GATE BREACHED: (Critical: ${finalCounts.c}/${criticalThreshold}, High: ${finalCounts.h}/${highThreshold}, Medium: ${finalCounts.m}/${mediumThreshold})`;
        console.error(`##vso[task.logissue type=error;]${errorMsg}`);
        throw new Error(errorMsg);
    }

    if (scanStatus === 'completed') {
        console.log("🎉 Security gate passed. No threshold breaches detected.");
    } else if (scanStatus !== 'aborted') {
        throw new Error(`Scan finished with unexpected status: ${scanStatus}`);
    }
}

// =====================================================================
// 🔐 COMPLIANCE EVENT FETCHER
// Polls the Invicti events API for the active scan session, maps each
// event kind to relevant compliance controls, and logs to the console.
// Tracks seen notification IDs to never duplicate a log entry.
// =====================================================================
async function fetchAndLogComplianceEvents(apiUrl, apiKey, scanSessionId, enabledFrameworks, seenEventIds) {
    try {
        const eventsUrl = `${apiUrl}/api/v1/events?q=resource_id:${scanSessionId}`;
        const res = await httpRequest('GET', eventsUrl, null, apiKey);
        if (res.statusCode !== 200) return;

        const eventsData = JSON.parse(res.data);
        const notifications = eventsData.notifications || [];

        for (const notif of notifications) {
            const notifId = notif.notification_id;
            if (!notifId || seenEventIds.has(notifId)) continue;
            seenEventIds.add(notifId);

            const kind   = notif.data && notif.data.kind;
            const detail = notif.data && notif.data.data ? notif.data.data : '';

            if (!kind || !COMPLIANCE_EVENT_MAP[kind]) continue;

            const mapping = COMPLIANCE_EVENT_MAP[kind];

            // Only log entries that touch at least one enabled framework
            const matchedFrameworks = Object.entries(mapping.frameworks)
                .filter(([fw]) => enabledFrameworks.includes(fw));

            if (matchedFrameworks.length === 0) continue;

            const frameworkLines = matchedFrameworks
                .map(([fw, controls]) => `      ${fw}: ${controls.join(' | ')}`)
                .join('\n');

            console.log(`\n[🔐 Compliance Event] [${mapping.severity}] ${mapping.summary}`);
            if (detail) console.log(`   ↳ Scanner Detail: ${detail}`);
            console.log(`   ↳ Control Mappings:\n${frameworkLines}`);
        }
    } catch (e) {
        // Non-critical — never break the scan pipeline on event fetch failure
        console.log(`[Module C] Compliance event fetch skipped: ${e.message}`);
    }
}

/**
 * Extracts the explicit scan_session_id and final severity counts
 */
async function fetchFinalScanData(scanUrl, apiKey) {
    const res = await httpRequest('GET', scanUrl, null, apiKey);
    const data = JSON.parse(res.data);
    const session = data.current_session || {};
    const counts = session.severity_counts || {};
    return {
        counts: {
            c: parseInt(counts.critical || 0, 10),
            h: parseInt(counts.high || 0, 10),
            m: parseInt(counts.medium || 0, 10)
        },
        scanSessionId: session.scan_session_id
    };
}

/**
 * Executes the DAST Report lifecycle targeting the scan_session_id
 */
async function runReportPipeline(apiUrl, apiKey, scanSessionId, templateId, targetName) {
    console.log(`\n[Module C Report] Initializing compliance report generation for Session ID: ${scanSessionId}...`);

    const payload = {
        template_id: templateId,
        email_notifications_enabled: false,
        user_notifications_enabled: false,
        source: {
            description: targetName || `AzureDevOps-Report`,
            list_type: "scan_result",
            id_list: [scanSessionId]
        }
    };

    try {
        const initRes = await httpRequest('POST', `${apiUrl}/api/v1/reports`, payload, apiKey);
        const initBody = JSON.parse(initRes.data);
        const reportId = initBody.report_id;

        if (!reportId) {
            console.log(`[Module C Report] ⚠️ Failed to generate report. API Response: ${initRes.data}`);
            return;
        }

        console.log(`[Module C Report] Report task queued (ID: ${reportId}). Sleeping 15s for initial rendering...`);
        await new Promise(r => setTimeout(r, 15000));

        let status = 'queued';
        let reportData = null;
        let attempts = 0;

        while (status !== 'completed' && attempts < 30) {
            await new Promise(r => setTimeout(r, 10000));
            attempts++;

            const statusRes = await httpRequest('GET', `${apiUrl}/api/v1/reports/${reportId}`, null, apiKey);
            reportData = JSON.parse(statusRes.data);
            status = (reportData.status || 'unknown').toLowerCase();

            console.log(`[Module C Report] Render Attempt ${attempts}: Status=${status.toUpperCase()}`);

            if (status === 'failed' || status === 'error') {
                console.log(`[Module C Report] ⚠️ Report compilation failed on the platform side.`);
                return;
            }
        }

        if (status !== 'completed' || !reportData || !reportData.download || reportData.download.length === 0) {
            console.log(`[Module C Report] ⚠️ Report polling timed out or no S3 download URLs were provided.`);
            return;
        }

        const downloadUrls = reportData.download;
        const htmlUrl = downloadUrls.find(u => u.toLowerCase().includes('.html')) || downloadUrls[0];

        console.log(`[Module C Report] Downloading rendered HTML artifact from S3 secure storage...`);
        await downloadAndPublishArtifact(htmlUrl, scanSessionId);

    } catch (err) {
        console.log(`[Module C Report] ⚠️ Report generation sequence failed: ${err.message}`);
    }
}

/**
 * Streams the pre-signed S3 report file directly to Azure DevOps
 */
function downloadAndPublishArtifact(downloadUrl, scanSessionId) {
    return new Promise((resolve) => {
        const stagingDir = process.env['BUILD_ARTIFACTSTAGINGDIRECTORY'] || process.cwd();
        const filePath = path.join(stagingDir, `DAST-Security-Report-${scanSessionId}.html`);
        const fileStream = fs.createWriteStream(filePath);

        https.get(downloadUrl, (res) => {
            if (res.statusCode !== 200) {
                console.log(`[Module C Report] ⚠️ Artifact download rejected with HTTP Status: ${res.statusCode}`);
                resolve();
                return;
            }

            res.pipe(fileStream);
            fileStream.on('finish', () => {
                fileStream.close();
                console.log(`[Module C Report] ✅ Artifact successfully downloaded: ${filePath}`);
                console.log(`##vso[task.addattachment type=invicti-dast-report;name=Invicti-DAST-Scan-Report;]${filePath}`);
                console.log(`##vso[artifact.upload containername=DAST-Compliance-Report;artifactname=DAST-Compliance-Report;]${filePath}`);
                resolve();
            });
        }).on('error', (err) => {
            console.log(`[Module C Report] ⚠️ Artifact network stream failed: ${err.message}`);
            resolve();
        });
    });
}

function httpRequest(method, targetUrl, payload, token) {
    return new Promise((resolve, reject) => {
        const parsedUrl = url.parse(targetUrl);
        const bodyData = payload ? JSON.stringify(payload) : '';
        const options = {
            hostname: parsedUrl.hostname,
            port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
            path: parsedUrl.path,
            method: method,
            headers: {
                'Accept': 'application/json',
                'X-Auth': token,
                'User-Agent': 'Enterprise-DevSecOps-Engine/1.3.2',
                'Content-Type': 'application/json'
            },
            timeout: 30000
        };
        if (payload) options.headers['Content-Length'] = Buffer.byteLength(bodyData);

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => { resolve({ statusCode: res.statusCode, data: data || "{}" }); });
        });
        req.on('error', (err) => reject(err));
        req.on('timeout', () => { req.destroy(); reject(new Error('Network operation timed out.')); });
        if (payload) req.write(bodyData);
        req.end();
    });
}

module.exports = { executeModuleC };
