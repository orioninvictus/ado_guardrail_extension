import * as React from "react";
import * as SDK from "azure-devops-extension-sdk";
import { CommonServiceIds, IExtensionDataService, getClient } from "azure-devops-extension-api";
import { CoreRestClient, TeamProjectReference } from "azure-devops-extension-api/Core";

export default function App() {
    const [status, setStatus] = React.useState<string>("Initializing SDK...");
    const [activeTab, setActiveTab] = React.useState<"global" | "project">("global");
    const [projects, setProjects] = React.useState<TeamProjectReference[]>([]);
    const [selectedProjectId, setSelectedProjectId] = React.useState<string>("");

    // Form State (Using strings for everything so "" can represent "Inherit")
    const [apiUrl, setApiUrl] = React.useState<string>("");
    const [apiKey, setApiKey] = React.useState<string>("");
    const [scanSpeed, setScanSpeed] = React.useState<string>("");
    const [criticalThreshold, setCriticalThreshold] = React.useState<string>("");
    const [highThreshold, setHighThreshold] = React.useState<string>("");
    const [mediumThreshold, setMediumThreshold] = React.useState<string>("");
    const [failBuild, setFailBuild] = React.useState<string>("");
    const [abortScan, setAbortScan] = React.useState<string>("");
    
    // Constraints State
    const [enabledBranches, setEnabledBranches] = React.useState<string>("");
    const [enabledEnvironments, setEnabledEnvironments] = React.useState<string>("");
    const [strictModeEnabled, setStrictModeEnabled] = React.useState<string>("");
    
    // Detection Strategy State
    const [detectionMethods, setDetectionMethods] = React.useState<string[]>([]);
    const [overrideDetection, setOverrideDetection] = React.useState<boolean>(false);

    // --- NEW GUARDRAIL STATES ---
    const [allowedDomainRegex, setAllowedDomainRegex] = React.useState<string>("");
    const [requireAuth, setRequireAuth] = React.useState<string>("");
    const [restrictApiScans, setRestrictApiScans] = React.useState<string>("");
    const [tagProject, setTagProject] = React.useState<string>("");
    const [tagRepo, setTagRepo] = React.useState<string>("");
    const [tagUser, setTagUser] = React.useState<string>("");
    const [tagCommit, setTagCommit] = React.useState<string>("");
    const [customTags, setCustomTags] = React.useState<string>("");
    // ----------------------------
    
    const [etag, setEtag] = React.useState<number | undefined>(undefined);

    React.useEffect(() => {
        const initHub = async () => {
            try {
                await SDK.init();
                await SDK.ready();
                setStatus("Loading Azure DevOps Projects...");

                const coreClient = getClient(CoreRestClient);
                const projList = await coreClient.getProjects();
                setProjects(projList);

                await loadPolicy("global");
            } catch (err: any) {
                console.error("[Admin Hub] Initialization failed:", err);
                setStatus(`Error initializing: ${err.message || err.toString()}`);
            }
        };
        initHub();
    }, []);

    const resetForm = (isGlobal: boolean) => {
        setApiUrl(isGlobal ? "https://platform.invicti.com" : "");
        setApiKey("");
        setScanSpeed(isGlobal ? "fast" : "");
        setCriticalThreshold(isGlobal ? "1" : "");
        setHighThreshold(isGlobal ? "3" : "");
        setMediumThreshold(isGlobal ? "5" : "");
        setFailBuild(isGlobal ? "true" : "");
        setAbortScan(isGlobal ? "false" : "");
        setEnabledBranches(isGlobal ? "refs/heads/main, refs/heads/master, refs/heads/release/*" : "");
        setEnabledEnvironments(isGlobal ? "Staging, UAT" : "");
        setStrictModeEnabled(isGlobal ? "false" : "");
        setDetectionMethods(isGlobal ? ["deployment_job", "native_env_object", "pipeline_variable"] : []);
        setOverrideDetection(isGlobal);

        // Reset New Guardrails
        setAllowedDomainRegex(isGlobal ? "^https:\\/\\/.*\\.staging\\.company\\.com" : "");
        setRequireAuth(isGlobal ? "false" : "");
        setRestrictApiScans(isGlobal ? "false" : "");
        setTagProject(isGlobal ? "true" : "");
        setTagRepo(isGlobal ? "true" : "");
        setTagUser(isGlobal ? "true" : "");
        setTagCommit(isGlobal ? "true" : "");
        setCustomTags("");

        setEtag(undefined);
    };

    const loadPolicy = async (tab: "global" | "project", projId?: string) => {
        try {
            setStatus(`Loading ${tab} policies...`);
            resetForm(tab === "global");

            if (tab === "project" && !projId) {
                setStatus("Please select a project to configure overrides.");
                return;
            }

            const dataService = await SDK.getService<IExtensionDataService>(CommonServiceIds.ExtensionDataService);
            const accessToken = await SDK.getAccessToken();
            const dataManager = await dataService.getExtensionDataManager(SDK.getExtensionContext().id, accessToken);

            const collection = tab === "global" ? "global-policy-collection" : `project-${projId}-collection`;
            const docId = tab === "global" ? "baseline" : "override";

            try {
                const doc = await dataManager.getDocument(collection, docId);
                if (doc) {
                    if (doc.apiUrl !== undefined) setApiUrl(doc.apiUrl);
                    if (doc.apiKey !== undefined) setApiKey(doc.apiKey);

                    if (doc.padlocks) {
                        if (doc.padlocks.scan_speed !== undefined) setScanSpeed(doc.padlocks.scan_speed);
                        if (doc.padlocks.critical_threshold !== undefined) setCriticalThreshold(doc.padlocks.critical_threshold);
                        if (doc.padlocks.high_threshold !== undefined) setHighThreshold(doc.padlocks.high_threshold);
                        if (doc.padlocks.medium_threshold !== undefined) setMediumThreshold(doc.padlocks.medium_threshold);
                        if (doc.padlocks.fail_build_on_findings !== undefined) setFailBuild(doc.padlocks.fail_build_on_findings);
                        if (doc.padlocks.abort_scan_on_findings !== undefined) setAbortScan(doc.padlocks.abort_scan_on_findings);

                        // Load New Guardrails
                        if (doc.padlocks.allowed_domain_regex !== undefined) setAllowedDomainRegex(doc.padlocks.allowed_domain_regex);
                        if (doc.padlocks.require_auth !== undefined) setRequireAuth(doc.padlocks.require_auth);
                        if (doc.padlocks.restrict_api_scans !== undefined) setRestrictApiScans(doc.padlocks.restrict_api_scans);
                        if (doc.padlocks.tag_project !== undefined) setTagProject(doc.padlocks.tag_project);
                        if (doc.padlocks.tag_repo !== undefined) setTagRepo(doc.padlocks.tag_repo);
                        if (doc.padlocks.tag_user !== undefined) setTagUser(doc.padlocks.tag_user);
                        if (doc.padlocks.tag_commit !== undefined) setTagCommit(doc.padlocks.tag_commit);
                        if (doc.padlocks.custom_tags !== undefined) setCustomTags(doc.padlocks.custom_tags);
                    }

                    if (doc.injection_constraints) {
                        if (doc.injection_constraints.enabled_branches !== undefined) setEnabledBranches(doc.injection_constraints.enabled_branches.join(", "));
                        if (doc.injection_constraints.enabled_environments !== undefined) setEnabledEnvironments(doc.injection_constraints.enabled_environments.join(", "));
                        if (doc.injection_constraints.strict_mode_enabled !== undefined) setStrictModeEnabled(String(doc.injection_constraints.strict_mode_enabled));
                        
                        if (doc.injection_constraints.detection_methods !== undefined) {
                            setDetectionMethods(doc.injection_constraints.detection_methods);
                            setOverrideDetection(true);
                        }
                    }
                    setEtag(doc.__etag);
                }
            } catch (e) {
                // Document missing, perfectly fine (defaults to empty/inherit for projects)
            }
            setStatus(`Ready. Editing ${tab === "global" ? "Global Baseline" : "Project Overrides"}.`);
        } catch (err: any) {
            setStatus(`Failed to load policy: ${err.message}`);
        }
    };

    const handleTabChange = async (tab: "global" | "project") => {
        setActiveTab(tab);
        if (tab === "global") {
            setSelectedProjectId("");
            await loadPolicy("global");
        } else {
            resetForm(false);
            setStatus("Please select a project to configure overrides.");
        }
    };

    const handleProjectChange = async (e: React.ChangeEvent<HTMLSelectElement>) => {
        const pId = e.target.value;
        setSelectedProjectId(pId);
        
        if (!pId) {
            resetForm(false);
            setStatus("Please select a project to configure overrides.");
            return;
        }
        
        await loadPolicy("project", pId);
    };

    const handleToggleMethod = (methodId: string) => {
        setDetectionMethods(prev => 
            prev.includes(methodId) ? prev.filter(m => m !== methodId) : [...prev, methodId]
        );
    };

    const handleSave = async () => {
        setStatus("Saving governance policies...");
        try {
            const dataService = await SDK.getService<IExtensionDataService>(CommonServiceIds.ExtensionDataService);
            const accessToken = await SDK.getAccessToken();
            const dataManager = await dataService.getExtensionDataManager(SDK.getExtensionContext().id, accessToken);
            
            const isGlobal = activeTab === "global";
            const collection = isGlobal ? "global-policy-collection" : `project-${selectedProjectId}-collection`;
            const docId = isGlobal ? "baseline" : "override";

            const branchArray = enabledBranches ? enabledBranches.split(",").map(b => b.trim()).filter(Boolean) : undefined;
            const envArray = enabledEnvironments ? enabledEnvironments.split(",").map(e => e.trim()).filter(Boolean) : undefined;

            const cleanObj = (obj: any) => {
                Object.keys(obj).forEach(key => (obj[key] === "" || obj[key] === undefined) && delete obj[key]);
                return obj;
            };

            const policyDocument: any = {
                id: docId,
                ...cleanObj({
                    apiUrl: apiUrl,
                    apiKey: apiKey
                }),
                injection_constraints: cleanObj({
                    enabled_branches: branchArray,
                    enabled_environments: envArray,
                    strict_mode_enabled: strictModeEnabled === "" ? undefined : strictModeEnabled === "true",
                    detection_methods: overrideDetection ? detectionMethods : undefined
                }),
                padlocks: cleanObj({
                    scan_speed: scanSpeed,
                    critical_threshold: criticalThreshold,
                    high_threshold: highThreshold,
                    medium_threshold: mediumThreshold,
                    fail_build_on_findings: failBuild,
                    abort_scan_on_findings: abortScan,
                    // New Guardrails Attached
                    allowed_domain_regex: allowedDomainRegex,
                    require_auth: requireAuth,
                    restrict_api_scans: restrictApiScans,
                    tag_project: tagProject,
                    tag_repo: tagRepo,
                    tag_user: tagUser,
                    tag_commit: tagCommit,
                    custom_tags: customTags
                })
            };

            if (Object.keys(policyDocument.injection_constraints).length === 0) delete policyDocument.injection_constraints;
            if (Object.keys(policyDocument.padlocks).length === 0) delete policyDocument.padlocks;

            console.log(`[Admin Hub] Saving ${isGlobal ? 'Global' : 'Project'} Payload:`, JSON.stringify(policyDocument, null, 2));

            if (etag !== undefined) policyDocument.__etag = etag;

            const savedDoc = await dataManager.setDocument(collection, policyDocument);
            if (savedDoc && savedDoc.__etag) setEtag(savedDoc.__etag);
            
            setStatus(`Success! ${isGlobal ? 'Global policies' : 'Project overrides'} saved.`);
        } catch (err: any) {
            console.error("[Admin Hub] Save failed:", err);
            setStatus(`Failed to save policies: ${err.message || err.toString()}`);
        }
    };

    const renderSelect = (label: string, value: string, setter: any, options: {val: string, lbl: string}[], desc: string) => (
        <div style={{ marginBottom: "15px" }}>
            <label style={{ fontWeight: "600" }}>{label}</label><br/>
            <select value={value} onChange={e => setter(e.target.value)} style={{ width: "100%", padding: "6px", marginTop: "5px" }}>
                {activeTab === "project" && <option value="">-- Inherit from Global --</option>}
                {options.map(o => <option key={o.val} value={o.val}>{o.lbl}</option>)}
            </select>
            <p style={{ margin: "4px 0 0 0", fontSize: "12px", color: "#666" }}>{desc}</p>
        </div>
    );

    const renderInput = (label: string, value: string, setter: any, placeholder: string, desc: string, inputType: string = "text") => (
        <div style={{ marginBottom: "15px" }}>
            <label style={{ fontWeight: "600" }}>{label}</label><br/>
            <input type={inputType} value={value} onChange={e => setter(e.target.value)} 
                   placeholder={activeTab === "project" ? "Leave blank to Inherit from Global" : placeholder} 
                   style={{ width: "100%", padding: "6px", marginTop: "5px" }} />
            <p style={{ margin: "4px 0 0 0", fontSize: "12px", color: "#666" }}>{desc}</p>
        </div>
    );

    const isProjectTabActive = activeTab === "project";
    const hideForm = isProjectTabActive && !selectedProjectId;

    return (
        <div style={{ fontFamily: "Segoe UI, sans-serif", maxWidth: "800px", padding: "20px" }}>
            <h2>AppSec Governance: DAST Policy Engine</h2>
            
            <div style={{ display: "flex", borderBottom: "2px solid #ccc", marginBottom: "15px" }}>
                <div onClick={() => handleTabChange("global")} 
                     style={{ padding: "10px 20px", cursor: "pointer", fontWeight: "bold", borderBottom: activeTab === "global" ? "3px solid #005a9e" : "none", color: activeTab === "global" ? "#005a9e" : "#555" }}>
                    🌍 Global Baseline
                </div>
                <div onClick={() => handleTabChange("project")} 
                     style={{ padding: "10px 20px", cursor: "pointer", fontWeight: "bold", borderBottom: activeTab === "project" ? "3px solid #005a9e" : "none", color: activeTab === "project" ? "#005a9e" : "#555" }}>
                    🎯 Project Overrides
                </div>
            </div>

            <p><strong>Status:</strong> {status}</p>
            <hr />

            {isProjectTabActive && (
                <div style={{ marginBottom: "20px", padding: "15px", backgroundColor: "#f0f8ff", border: "1px solid #cce0ff", borderRadius: "5px" }}>
                    <label style={{ fontWeight: "600", color: "#005a9e" }}>Select Target Project for Overrides</label><br/>
                    <select value={selectedProjectId} onChange={handleProjectChange} style={{ width: "100%", padding: "8px", marginTop: "5px", fontWeight: "bold" }}>
                        <option value="">-- Choose a Project --</option>
                        {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                    </select>
                </div>
            )}

            {!hideForm && (
                <>
                    <h3>1. Core API Credentials</h3>
                    {renderInput("DAST API URL", apiUrl, setApiUrl, "https://platform.invicti.com", "The target base URL endpoint for your corporate vulnerability management platform.")}
                    {renderInput("DAST API Key", apiKey, setApiKey, "Enter API Key", "Secret authorization token utilized to authenticate automated background actions.", "password")}

                    <h3>2. Pipeline Injection Targets (Gatekeeper Filter)</h3>
                    {renderInput("Target Git Branches (Comma-separated)", enabledBranches, setEnabledBranches, "refs/heads/main, refs/heads/master", "Specifies the target execution branches. Supports wildcards.")}
                    {renderInput("Monitored Environments (Comma-separated)", enabledEnvironments, setEnabledEnvironments, "Staging, UAT", "Deployment contexts that require DAST coverage checks.")}

                    <div style={{ marginBottom: "15px" }}>
                        <label style={{ fontWeight: "600" }}>Environment Metadata Detection Strategy</label>
                        <p style={{ margin: "4px 0 8px 0", fontSize: "12px", color: "#666" }}>Configure where the engine checks to discover environmental tracking fields.</p>
                        
                        <div style={{ border: "1px solid #ccc", padding: "12px", borderRadius: "4px", backgroundColor: "#fff" }}>
                            {isProjectTabActive && (
                                <label style={{ display: "block", marginBottom: "15px", color: "#005a9e", fontWeight: "bold", borderBottom: "1px solid #eee", paddingBottom: "10px" }}>
                                    <input type="checkbox" checked={overrideDetection} onChange={e => setOverrideDetection(e.target.checked)} style={{ marginRight: "8px" }} />
                                    Override Global Detection Strategy
                                </label>
                            )}
                            
                            <div style={{ opacity: (!isProjectTabActive || overrideDetection) ? 1 : 0.5, pointerEvents: (!isProjectTabActive || overrideDetection) ? "auto" : "none" }}>
                                {["deployment_job", "native_env_object", "pipeline_variable"].map(method => (
                                    <div key={method} style={{ marginBottom: "8px" }}>
                                        <label style={{ cursor: "pointer", fontSize: "14px" }}>
                                            <input type="checkbox" checked={detectionMethods.includes(method)} onChange={() => handleToggleMethod(method)} style={{ marginRight: "8px" }} />
                                            <strong>{method.replace(/_/g, ' ').toUpperCase()}</strong>
                                        </label>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>

                    {renderSelect("Enforce Strict Context Mode (Fail-Secure Gate)", strictModeEnabled, setStrictModeEnabled, 
                        [{val: "true", lbl: "Enabled (Break builds missing environments)"}, {val: "false", lbl: "Disabled (Scan regardless)"}], 
                        "When enabled, pipelines failing to supply environment labels are instantly failed.")}

                    <h3>3. Advanced Domain & Context Guardrails</h3>
                    {renderInput("Allowed Target Domain Scope (RegEx)", allowedDomainRegex, setAllowedDomainRegex, "^https:\\/\\/.*\\.staging\\.company\\.com", "Prevents scanning of unauthorized or production endpoints. Evaluated against target.url.")}
                    
                    {renderSelect("Mandatory Authentication Enforcement", requireAuth, setRequireAuth, 
                        [{val: "true", lbl: "True (Block Unauthenticated Scans)"}, {val: "false", lbl: "False (Allow Unauthenticated Scans)"}], 
                        "If True, breaks the build if developers fail to supply valid authentication blocks in their .dast-config.yml.")}
                    
                    {renderSelect("API Specification Lockdown", restrictApiScans, setRestrictApiScans, 
                        [{val: "true", lbl: "True (Restrict to Uploaded Specs)"}, {val: "false", lbl: "False (Allow Standard Crawling)"}], 
                        "When Target Type is 'api', this forces 'restrict_scans_to_import_files' to true, isolating the scanner to explicit swagger paths only.")}

                    <h3>4. Automated Pipeline Tagging</h3>
                    <p style={{ margin: "4px 0 8px 0", fontSize: "12px", color: "#666" }}>Select which Azure DevOps runtime context variables should be automatically appended to targets and scans.</p>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px", marginBottom: "15px" }}>
                        {renderSelect("Tag ADO Project", tagProject, setTagProject, [{val: "true", lbl: "Inject Tag"}, {val: "false", lbl: "Do Not Inject"}], "")}
                        {renderSelect("Tag ADO Repository", tagRepo, setTagRepo, [{val: "true", lbl: "Inject Tag"}, {val: "false", lbl: "Do Not Inject"}], "")}
                        {renderSelect("Tag ADO Build User", tagUser, setTagUser, [{val: "true", lbl: "Inject Tag"}, {val: "false", lbl: "Do Not Inject"}], "")}
                        {renderSelect("Tag ADO Commit SHA", tagCommit, setTagCommit, [{val: "true", lbl: "Inject Tag"}, {val: "false", lbl: "Do Not Inject"}], "")}
                    </div>
                    {renderInput("Custom Organizational Tags (Comma-separated)", customTags, setCustomTags, "Billing:SecOps, Audit:2026-Q3", "Static tags applied to all assets under this policy scope.")}

                    <h3>5. Padlocked Developer Guardrails</h3>
                    
                    {renderSelect("Enforced Scan Speed", scanSpeed, setScanSpeed, 
                        [
                            {val: "slow", lbl: "Slow (Thorough)"}, 
                            {val: "moderate", lbl: "Moderate"}, 
                            {val: "fast", lbl: "Fast"},
                            {val: "sequential", lbl: "Sequential"}
                        ], 
                        "Hardlocks the execution performance metrics. Prevents developers from forcing throttling speeds.")}

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "10px", marginBottom: "15px" }}>
                        {renderInput("Critical Ceiling", criticalThreshold, setCriticalThreshold, "1", "", "number")}
                        {renderInput("High Ceiling", highThreshold, setHighThreshold, "3", "", "number")}
                        {renderInput("Medium Ceiling", mediumThreshold, setMediumThreshold, "5", "", "number")}
                    </div>

                    {renderSelect("Fail Pipeline Build on Threshold Breach", failBuild, setFailBuild, 
                        [{val: "true", lbl: "True (Break Pipeline)"}, {val: "false", lbl: "False (Warn Only)"}], 
                        "Automatically breaks the runner lifecycle state to block risky deployments.")}

                    {renderSelect("Abort Scan Immediately on Threshold Breach", abortScan, setAbortScan, 
                        [{val: "true", lbl: "True (Terminate Active Scan)"}, {val: "false", lbl: "False (Let Scan Finish)"}], 
                        "Actively terminate running scanners the moment compliance limits are broken to save engine compute hours.")}

                    <button onClick={handleSave} style={{ backgroundColor: "#005a9e", color: "white", padding: "10px 20px", border: "none", cursor: "pointer", marginTop: "15px", fontWeight: "600", borderRadius: "4px" }}>
                        Save {activeTab === "global" ? "Global Baseline" : "Project Overrides"}
                    </button>
                </>
            )}
        </div>
    );
}