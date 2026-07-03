const fs = require('fs');
const path = require('path');
const https = require('https');
const url = require('url');

/**
 * Module C: Hardened Governance Engine
 * Validates scan findings, manages report artifacts, and executes pipeline gates.
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
    const highThreshold = parseInt(getVal('high_threshold', '0'), 10);
    const mediumThreshold = parseInt(getVal('medium_threshold', '5'), 10);
    
    const failBuildOnFindings = String(getVal('fail_build_on_findings', 'true')) === 'true';
    const abortScanOnFindings = String(getVal('abort_scan_on_findings', 'false')) === 'true';
    
    const generateReport = String(getVal('generate_report', 'true')) === 'true';
    const reportTemplateId = getVal('report_template_id', '11111111-1111-1111-1111-111111111111');

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
    // ⚙️ INCREMENTAL SCAN ENFORCEMENT
    // =====================================================================
    // If Admin enforced incremental globally, force it. Otherwise, defer to devConfig.
    const enforceIncremental = String(policyPadlocks.incremental_mode) === "true";
    const isIncremental = enforceIncremental || (devConfig["target.incremental"] === 'true');

    // 1. Dispatch Scan
    const scanPayload = {
        user_authorized_to_scan: "yes",
        target_id: targetId,
        profile_id: profileId,
        report_template_id: reportTemplateId, // Injected for backend mapping
        schedule: { disable: false },
        max_scan_time: parseInt(devConfig["target.max_scan_time"] || '0', 10),
        incremental: isIncremental, // Enforced toggle applied
        tags: generatedTags // Telemetry tags appended
    };

    const scanInitResult = await httpRequest('POST', `${apiUrl}/api/v1/scans`, scanPayload, apiKey);
    const scanInitBody = JSON.parse(scanInitResult.data);
    const scanId = scanInitBody.scan_id;

    if (!scanId) throw new Error(`Platform failed to initialize. Response: ${scanInitResult.data}`);
    console.log(`[✔] Scan initialized dynamically (Incremental: ${isIncremental}). ID: ${scanId}`);

    // 2. Polling Loop
    const scanStatusUrl = `${apiUrl}/api/v1/scans/${scanId}`;
    let scanStatus = 'queued';
    let pollCount = 0;
    const maxPollAttempts = 60; // Up to 30 mins

    while (!['completed', 'failed', 'aborted'].includes(scanStatus) && pollCount < maxPollAttempts) {
        await new Promise(r => setTimeout(r, 30000)); // Poll every 30 seconds
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

        // Immediate Enforcement Gate
        const criticalBreached = (criticalThreshold > 0 && c >= criticalThreshold);
        const highBreached = (highThreshold > 0 && h >= highThreshold);
        const mediumBreached = (mediumThreshold > 0 && m >= mediumThreshold);

        if (criticalBreached || highBreached || mediumBreached) {
            console.log(`\n⚠️  [Guardrail Trigger] Security threshold breach detected!`);
            
            if (abortScanOnFindings && scanStatus !== 'aborted') {
                console.log(`[🛑] Aborting active scan on platform to conserve engine resources...`);
                await httpRequest('POST', `${scanStatusUrl}/abort`, {}, apiKey);
                scanStatus = 'aborted';
            }
            // We BREAK the loop so we can generate the report before failing the build
            break;
        }
    }

    // --- CRITICAL ALIGNMENT: 40 Second Finalization Delay ---
    if (['completed', 'aborted'].includes(scanStatus)) {
        console.log(`[Module C] Scan execution halted. Sleeping for 40 seconds to allow backend session data to fully finalize for reporting...`);
        await new Promise(r => setTimeout(r, 40000));
    }

    // Fetch the final canonical data, ensuring we extract the actual Session ID
    const finalData = await fetchFinalScanData(scanStatusUrl, apiKey);
    const finalCounts = finalData.counts;
    const scanSessionId = finalData.scanSessionId;

    if (!scanSessionId) {
        console.log(`[Module C Warning] Could not resolve a valid scan_session_id from the platform. Report rendering may fail.`);
    }

    // 3. Report Generation & Artifact Publishing
    // Targets the Session ID directly via 'scan_result' list type
    if (generateReport && scanSessionId && ['completed', 'aborted'].includes(scanStatus)) {
        await runReportPipeline(apiUrl, apiKey, scanSessionId, reportTemplateId, devConfig["target.name"]);
    }

    // 4. Final Security Gate Evaluation (Fail the build AFTER the report is safely attached)
    const finalCriticalBreach = (criticalThreshold > 0 && finalCounts.c >= criticalThreshold);
    const finalHighBreach = (highThreshold > 0 && finalCounts.h >= highThreshold);
    const finalMediumBreach = (mediumThreshold > 0 && finalCounts.m >= mediumThreshold);

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
 * Executes the DAST Report lifecycle specifically targeting the 'scan_session_id'
 */
async function runReportPipeline(apiUrl, apiKey, scanSessionId, templateId, targetName) {
    console.log(`\n[Module C Report] Initializing compliance report generation for Session ID: ${scanSessionId}...`);
    
    // Payload explicitly mapped to "scan_result" to parse session tokens correctly
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
        
        console.log(`[Module C Report] Report task queued (ID: ${reportId}). Sleeping for 15 seconds to allow initial rendering...`);
        await new Promise(r => setTimeout(r, 15000));

        let status = 'queued';
        let reportData = null;
        let attempts = 0;

        // Poll every 10 seconds for up to 5 minutes
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

        // Isolate the pre-signed HTML URL from the S3 array
        const downloadUrls = reportData.download;
        const htmlUrl = downloadUrls.find(u => u.toLowerCase().includes('.html')) || downloadUrls[0];

        console.log(`[Module C Report] Downloading rendered HTML artifact from S3 secure storage...`);
        await downloadAndPublishArtifact(htmlUrl, scanSessionId);

    } catch (err) {
        console.log(`[Module C Report] ⚠️ Report generation sequence failed: ${err.message}`);
    }
}

/**
 * Streams the pre-signed S3 report file directly to Azure DevOps without stripping signatures
 */
function downloadAndPublishArtifact(downloadUrl, scanSessionId) {
    return new Promise((resolve) => {
        const stagingDir = process.env['BUILD_ARTIFACTSTAGINGDIRECTORY'] || process.cwd();
        const filePath = path.join(stagingDir, `DAST-Security-Report-${scanSessionId}.html`);
        const fileStream = fs.createWriteStream(filePath);

        // Native HTTPS get handles the raw S3 URL perfectly without breaking signature headers
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
                
                // 1. Bind HTML to the Native Pipeline UI Tab
                console.log(`##vso[task.addattachment type=invicti-dast-report;name=Invicti-DAST-Scan-Report;]${filePath}`);
                
                // 2. Publish to the standard Artifacts Drop
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
                'User-Agent': 'Enterprise-DevSecOps-Engine/1.2.20',
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