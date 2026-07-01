import * as React from "react";
import * as SDK from "azure-devops-extension-sdk";
import { CommonServiceIds, IExtensionDataService, getClient } from "azure-devops-extension-api";
import { CoreRestClient, TeamProjectReference } from "azure-devops-extension-api/Core";

export default function App() {
    const [status, setStatus] = React.useState<string>("Initializing SDK...");
    const [activeTab, setActiveTab] = React.useState<"global" | "project">("global");
    const [projects, setProjects] = React.useState<TeamProjectReference[]>([]);
    const [selectedProjectId, setSelectedProjectId] = React.useState<string>("");

    // Form State 
    const [apiUrl, setApiUrl] = React.useState<string>("");
    const [apiKey, setApiKey] = React.useState<string>("");
    const [scanSpeed, setScanSpeed] = React.useState<string>("");
    const [criticalThreshold, setCriticalThreshold] = React.useState<string>("");
    const [highThreshold, setHighThreshold] = React.useState<string>("");
    const [mediumThreshold, setMediumThreshold] = React.useState<string>("");
    const [failBuild, setFailBuild] = React.useState<boolean>(true);
    const [abortScan, setAbortScan] = React.useState<boolean>(false);
    
    // Constraints State
    const [enabledBranches, setEnabledBranches] = React.useState<string>("");
    const [enabledEnvironments, setEnabledEnvironments] = React.useState<string>("");
    const [strictModeEnabled, setStrictModeEnabled] = React.useState<boolean>(false);
    const [detectionMethods, setDetectionMethods] = React.useState<string[]>([]);
    const [overrideDetection, setOverrideDetection] = React.useState<boolean>(false);

    // NEW GUARDRAILS STATE
    const [allowedDomainRegex, setAllowedDomainRegex] = React.useState<string>("");
    const [requireAuth, setRequireAuth] = React.useState<boolean>(false);
    const [restrictApiScans, setRestrictApiScans] = React.useState<boolean>(false);
    const [tagProject, setTagProject] = React.useState<boolean>(true);
    const [tagRepo, setTagRepo] = React.useState<boolean>(true);
    const [tagUser, setTagUser] = React.useState<boolean>(true);
    const [tagCommit, setTagCommit] = React.useState<boolean>(true);
    const [customTags, setCustomTags] = React.useState<string>("");
    
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
        setFailBuild(isGlobal ? true : false);
        setAbortScan(isGlobal ? false : false);
        setEnabledBranches(isGlobal ? "refs/heads/main, refs/heads/master, refs/heads/release/*" : "");
        setEnabledEnvironments(isGlobal ? "Staging, UAT" : "");
        setStrictModeEnabled(isGlobal ? false : false);
        setDetectionMethods(isGlobal ? ["deployment_job", "native_env_object", "pipeline_variable"] : []);
        setOverrideDetection(isGlobal);
        
        // Reset New Guardrails
        setAllowedDomainRegex(isGlobal ? "^https:\\/\\/.*\\.staging\\.company\\.com" : "");
        setRequireAuth(isGlobal ? false : false);
        setRestrictApiScans(isGlobal ? false : false);
        setTagProject(isGlobal ? true : false);
        setTagRepo(isGlobal ? true : false);
        setTagUser(isGlobal ? true : false);
        setTagCommit(isGlobal ? true : false);
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
                        if (doc.padlocks.fail_build_on_findings !== undefined) setFailBuild(doc.padlocks.fail_build_on_findings === "true" || doc.padlocks.fail_build_on_findings === true);
                        if (doc.padlocks.abort_scan_on_findings !== undefined) setAbortScan(doc.padlocks.abort_scan_on_findings === "true" || doc.padlocks.abort_scan_on_findings === true);
                        
                        // Load New Guardrails
                        if (doc.padlocks.allowed_domain_regex !== undefined) setAllowedDomainRegex(doc.padlocks.allowed_domain_regex);
                        if (doc.padlocks.require_auth !== undefined) setRequireAuth(doc.padlocks.require_auth === "true" || doc.padlocks.require_auth === true);
                        if (doc.padlocks.restrict_api_scans !== undefined) setRestrictApiScans(doc.padlocks.restrict_api_scans === "true" || doc.padlocks.restrict_api_scans === true);
                        if (doc.padlocks.tag_project !== undefined) setTagProject(doc.padlocks.tag_project === "true" || doc.padlocks.tag_project === true);
                        if (doc.padlocks.tag_repo !== undefined) setTagRepo(doc.padlocks.tag_repo === "true" || doc.padlocks.tag_repo === true);
                        if (doc.padlocks.tag_user !== undefined) setTagUser(doc.padlocks.tag_user === "true" || doc.padlocks.tag_user === true);
                        if (doc.padlocks.tag_commit !== undefined) setTagCommit(doc.padlocks.tag_commit === "true" || doc.padlocks.tag_commit === true);
                        if (doc.padlocks.custom_tags !== undefined) setCustomTags(doc.padlocks.custom_tags);
                    }

                    if (doc.injection_constraints) {
                        if (doc.injection_constraints.enabled_branches !== undefined) setEnabledBranches(doc.injection_constraints.enabled_branches.join(", "));
                        if (doc.injection_constraints.enabled_environments !== undefined) setEnabledEnvironments(doc.injection_constraints.enabled_environments.join(", "));
                        if (doc.injection_constraints.strict_mode_enabled !== undefined) setStrictModeEnabled(doc.injection_constraints.strict_mode_enabled === "true" || doc.injection_constraints.strict_mode_enabled === true);
                        
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
                    strict_mode_enabled: strictModeEnabled,
                    detection_methods: overrideDetection ? detectionMethods : undefined
                }),
                padlocks: cleanObj({
                    scan_speed: scanSpeed,
                    critical_threshold: criticalThreshold,
                    high_threshold: highThreshold,
                    medium_threshold: mediumThreshold,
                    fail_build_on_findings: failBuild,
                    abort_scan_on_findings: abortScan,
                    // New Guardrails saved to DB
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

            if (etag !== undefined) {
                policyDocument.__etag = etag;
            }

            const savedDoc = await dataManager.setDocument(collection, policyDocument);
            
            if (savedDoc && savedDoc.__etag) {
                setEtag(savedDoc.__etag);
            }
            
            setStatus(`Success! ${isGlobal ? 'Global policies' : 'Project overrides'} saved.`);
        } catch (err: any) {
            console.error("[Admin Hub] Save failed:", err);
            setStatus(`Failed to save policies: ${err.message || err.toString()}`);
        }
    };

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
                    <p><em>These credentials will be injected into the pipeline decorator silently.</em></p>
                    
                    <div style={{ marginBottom: "15px" }}>
                        <label style={{ fontWeight: "600" }}>DAST API URL</label><br/>
                        <input type="text" value={apiUrl} onChange={e => setApiUrl(e.target.value)} placeholder={isProjectTabActive ? "Leave blank to Inherit from Global" : "https://platform.invicti.com"} style={{ width: "100%", padding: "6px", marginTop: "5px" }} />
                        <p style={{ margin: "4px 0 0 0", fontSize: "12px", color: "#666" }}>
                            The target base URL endpoint for your corporate vulnerability management tenant platform backend interface.
                        </p>
                    </div>
                    
                    <div style={{ marginBottom: "15px" }}>
                        <label style={{ fontWeight: "600" }}>DAST API Key</label><br/>
                        <input type="password" value={apiKey} onChange={e => setApiKey(e.target.value)} placeholder={isProjectTabActive ? "Leave blank to Inherit from Global" : "Enter API Key"} style={{ width: "100%", padding: "6px", marginTop: "5px" }} />
                        <p style={{ margin: "4px 0 0 0", fontSize: "12px", color: "#666" }}>
                            Secret authorization token credentials utilized to authenticate automated background actions. Enforced silently during pipeline run configurations.
                        </p>
                    </div>

                    <h3>2. Pipeline Injection Targets (Gatekeeper Filter)</h3>
                    <p><em>Define exactly which branches or environment declarations invoke mandatory execution boundaries.</em></p>
                    
                    <div style={{ marginBottom: "15px" }}>
                        <label style={{ fontWeight: "600" }}>Target Git Branches (Comma-separated)</label><br/>
                        <input
                            type="text"
                            value={enabledBranches}
                            onChange={e => setEnabledBranches(e.target.value)}
                            placeholder={isProjectTabActive ? "Leave blank to Inherit from Global" : "refs/heads/main, refs/heads/master"}
                            style={{ width: "100%", padding: "6px", marginTop: "5px" }}
                        />
                        <p style={{ margin: "4px 0 0 0", fontSize: "12px", color: "#666" }}>
                            Specifies the target execution branches. You can utilize wildcards to catch entire structures (e.g., <code>refs/heads/release/*</code> or <code>refs/heads/hotfix/*</code>).
                        </p>
                    </div>
                    
                    <div style={{ marginBottom: "15px" }}>
                        <label style={{ fontWeight: "600" }}>Monitored Environments (Comma-separated)</label><br/>
                        <input
                            type="text"
                            value={enabledEnvironments}
                            onChange={e => setEnabledEnvironments(e.target.value)}
                            placeholder={isProjectTabActive ? "Leave blank to Inherit from Global" : "Staging, UAT, Production"}
                            style={{ width: "100%", padding: "6px", marginTop: "5px" }}
                        />
                        <p style={{ margin: "4px 0 0 0", fontSize: "12px", color: "#666" }}>
                            The case-insensitive names of deployment contexts that require DAST coverage checks. Bypasses other pipelines cleanly to save runner time.
                        </p>
                    </div>

                    <div style={{ marginBottom: "15px" }}>
                        <label style={{ fontWeight: "600" }}>Environment Metadata Detection Strategy</label>
                        <p style={{ margin: "4px 0 8px 0", fontSize: "12px", color: "#666" }}>
                            Configure where the engine checks to discover environmental tracking fields. If multiple areas match, the engine falls through the selected filters sequentially.
                        </p>
                        <div style={{ border: "1px solid #ccc", padding: "12px", borderRadius: "4px", backgroundColor: "#fff" }}>
                            {isProjectTabActive && (
                                <label style={{ display: "block", marginBottom: "15px", color: "#005a9e", fontWeight: "bold", borderBottom: "1px solid #eee", paddingBottom: "10px" }}>
                                    <input type="checkbox" checked={overrideDetection} onChange={e => setOverrideDetection(e.target.checked)} style={{ marginRight: "8px" }} />
                                    Override Global Detection Strategy
                                </label>
                            )}
                            <div style={{ opacity: (!isProjectTabActive || overrideDetection) ? 1 : 0.5, pointerEvents: (!isProjectTabActive || overrideDetection) ? "auto" : "none" }}>
                                <div style={{ marginBottom: "10px" }}>
                                    <label style={{ cursor: "pointer", fontSize: "14px" }}>
                                        <input
                                            type="checkbox"
                                            checked={detectionMethods.includes("deployment_job")}
                                            onChange={() => handleToggleMethod("deployment_job")}
                                            style={{ marginRight: "8px" }}
                                        />
                                        <strong>Deployment Job Standard</strong> (Reads <code>ENVIRONMENT_RESOURCE_NAME</code>)
                                    </label>
                                    <p style={{ margin: "2px 0 0 22px", fontSize: "11px", color: "#666" }}>
                                        Evaluates native Azure DevOps deployment job environments automatically. Highly secure, tamper-proof option.
                                    </p>
                                </div>
                                <div style={{ marginBottom: "10px" }}>
                                    <label style={{ cursor: "pointer", fontSize: "14px" }}>
                                        <input
                                            type="checkbox"
                                            checked={detectionMethods.includes("native_env_object")}
                                            onChange={() => handleToggleMethod("native_env_object")}
                                            style={{ marginRight: "8px" }}
                                        />
                                        <strong>Resource/Environment Object</strong> (Reads <code>ENVIRONMENT_NAME</code>)
                                    </label>
                                    <p style={{ margin: "2px 0 0 22px", fontSize: "11px", color: "#666" }}>
                                        Intercepts standard contextual parameters declared inside native platform infrastructure blocks.
                                    </p>
                                </div>
                                <div>
                                    <label style={{ cursor: "pointer", fontSize: "14px" }}>
                                        <input
                                            type="checkbox"
                                            checked={detectionMethods.includes("pipeline_variable")}
                                            onChange={() => handleToggleMethod("pipeline_variable")}
                                            style={{ marginRight: "8px" }}
                                        />
                                        <strong>Manual Pipeline Variable</strong> (Reads <code>Environment.Name</code> / <code>ENVIRONMENT.NAME</code>)
                                    </label>
                                    <p style={{ margin: "2px 0 0 22px", fontSize: "11px", color: "#666" }}>
                                        Fallback strategy supporting traditional, manually declared custom YAML pipeline string variable structures.
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div style={{ marginBottom: "15px", backgroundColor: "#f4f4f4", padding: "10px", borderRadius: "4px" }}>
                        <label style={{ cursor: "pointer" }}>
                            <input
                                type="checkbox"
                                checked={strictModeEnabled}
                                onChange={e => setStrictModeEnabled(e.target.checked)}
                                style={{ marginRight: "8px" }}
                            />
                            <strong>Enforce Strict Context Mode (Fail-Secure Gate)</strong>
                        </label>
                        <p style={{ margin: "5px 0 0 22px", fontSize: "12px", color: "#555" }}>
                            When checked, any build pipeline failing to supply environment labels via selected strategies will be **instantly failed** to eliminate unmonitored blind spots.
                        </p>
                    </div>

                    {/* NEW SECTION: Advanced Security Guardrails */}
                    <h3>3. Advanced Domain & Context Guardrails</h3>
                    <p><em>Enforce restrictions on target locations, authentication presence, and API definitions.</em></p>

                    <div style={{ marginBottom: "15px", padding: "15px", border: "1px solid #ddd", borderRadius: "5px", backgroundColor: "#fafafa" }}>
                        <label style={{ fontWeight: "600" }}>Allowed Target Domain Scope (JavaScript RegEx)</label><br/>
                        <input 
                            type="text" 
                            value={allowedDomainRegex} 
                            onChange={e => setAllowedDomainRegex(e.target.value)} 
                            placeholder={isProjectTabActive ? "Leave blank to Inherit from Global" : "^https:\\/\\/.*\\.staging\\.company\\.com"} 
                            style={{ width: "100%", padding: "8px", marginTop: "5px", fontFamily: "monospace" }} 
                        />
                        <div style={{ margin: "8px 0 0 0", fontSize: "12px", color: "#444" }}>
                            <strong>Prevents scanning of unauthorized or production endpoints.</strong> Evaluated against the developer's <code>target.url</code>.
                            <ul style={{ margin: "4px 0", paddingLeft: "20px" }}>
                                <li><code>^https:\/\/.*\.staging\.company\.com</code> (Allows any subdomain under staging)</li>
                                <li><code>^https:\/\/(api-test|dev)\.company\.com</code> (Allows specific subdomains)</li>
                            </ul>
                        </div>
                    </div>

                    <div style={{ marginBottom: "15px" }}>
                        <label style={{ cursor: "pointer" }}>
                            <input type="checkbox" checked={requireAuth} onChange={e => setRequireAuth(e.target.checked)} style={{ marginRight: "6px" }} />
                            <strong>Mandatory Authentication Enforcement</strong>
                        </label>
                        <p style={{ margin: "4px 0 0 20px", fontSize: "12px", color: "#666" }}>
                            If enabled, the orchestrator breaks the build if developers fail to supply valid authentication blocks in their <code>.dast-config.yml</code> (Prevents "shallow" scans).
                        </p>
                    </div>

                    <div style={{ marginBottom: "15px" }}>
                        <label style={{ cursor: "pointer" }}>
                            <input type="checkbox" checked={restrictApiScans} onChange={e => setRestrictApiScans(e.target.checked)} style={{ marginRight: "6px" }} />
                            <strong>API Specification Lockdown</strong>
                        </label>
                        <p style={{ margin: "4px 0 0 20px", fontSize: "12px", color: "#666" }}>
                            When Target Type is set to <code>api</code>, this overrides Invicti configurations, forcing the crawler to stay strictly within the paths defined in the uploaded OpenAPI/Swagger file.
                        </p>
                    </div>

                    <div style={{ marginBottom: "15px", padding: "15px", border: "1px solid #ccc", borderRadius: "4px" }}>
                        <label style={{ fontWeight: "600" }}>Automated Organizational Tagging</label>
                        <p style={{ margin: "4px 0 8px 0", fontSize: "12px", color: "#666" }}>
                            Select which Azure DevOps runtime context variables should be automatically appended to targets and scans for compliance tracking and billing.
                        </p>
                        <div style={{ display: "flex", gap: "15px", marginBottom: "10px" }}>
                            <label