import * as React from "react";
import * as SDK from "azure-devops-extension-sdk";
import { CommonServiceIds, IExtensionDataService, getClient } from "azure-devops-extension-api";
import { CoreRestClient, TeamProjectReference } from "azure-devops-extension-api/Core";

const ALL_FRAMEWORKS = ["SOC2", "PCI-DSS", "DORA", "ISO27001", "OWASP"];
const FRAMEWORK_REFS: Record<string, string> = {
    "SOC2": "CC6.1 Logical Access, CC6.6 External Access, CC7.1 System Monitoring",
    "PCI-DSS": "Req 6.4.1 Authenticated Scanning, Req 8.2 Auth, Req 11.3.1 Penetration Testing",
    "DORA": "Art.9.4(d) ICT Security Testing, Art.25.1 Threat-Led Pen Testing (TLPT)",
    "ISO27001": "A.9.4 Access Control, A.12.6.1 Vulnerability Mgmt, A.14.2.8 Security Testing",
    "OWASP": "WSTG-ATHN Authentication Testing, WSTG-SESS Session Management",
};

// ---- Tentacle / Invicti design tokens (mirrors colors_and_type.css) ----
const T = {
    font: "'CircularXX', -apple-system, 'Segoe UI', Roboto, sans-serif",
    surface0: "#ffffff",
    surface50: "#faf9fb",
    surface100: "#f4f3f5",
    surface200: "#e7e6e6",
    surface400: "#d9d8d6",
    surface500: "#a5a8ab",
    surface600: "#84878a",
    surface700: "#636569",
    surface800: "#3a3f45",
    surface900: "#101721",
    accent50: "#f3f2fd",
    accent100: "#ece9fa",
    accent300: "#c8c1e9",
    accent800: "#5d40bd",
    accent900: "#422991",
    green100: "#d4eadd",
    green900: "#0d6451",
    blue100: "#e7ecfc",
    blue900: "#2c51bd",
    red100: "#f4cecd",
    red900: "#8e181d",
    yellow100: "#fdedcd",
    yellow900: "#886724",
    gradientPlum: "linear-gradient(180deg, #3c104b 0%, #4d195e 60%, #320c3e 100%)",
};

type Defaults = {
    apiUrl: string; apiKey: string;
    scanSpeed: string; criticalThreshold: string; highThreshold: string; mediumThreshold: string; failBuild: string; abortScan: string;
    enabledBranches: string; enabledEnvironments: string; strictModeEnabled: string; detectionMethods: string[]; overrideDetection: boolean;
    allowedDomainRegex: string; requireAuth: string; restrictApiScans: string;
    tagProject: string; tagRepo: string; tagUser: string; tagCommit: string; customTags: string;
    complianceFrameworks: string[];
    targetNameOverride: string; targetNamePrefix: string; targetNameIncludeProject: string; targetNameIncludeUser: string; targetNameIncludeDevName: string;
    profileId: string; incrementalMode: string;
};

const GLOBAL_DEFAULTS: Defaults = {
    apiUrl: "https://platform.invicti.com", apiKey: "",
    scanSpeed: "fast", criticalThreshold: "1", highThreshold: "3", mediumThreshold: "5", failBuild: "true", abortScan: "false",
    enabledBranches: "refs/heads/main, refs/heads/master, refs/heads/release/*", enabledEnvironments: "Staging, UAT",
    strictModeEnabled: "false", detectionMethods: ["deployment_job", "native_env_object", "pipeline_variable"], overrideDetection: true,
    allowedDomainRegex: "^https:\\/\\/.*\\.staging\\.company\\.com", requireAuth: "false", restrictApiScans: "false",
    tagProject: "true", tagRepo: "true", tagUser: "true", tagCommit: "true", customTags: "",
    complianceFrameworks: [],
    targetNameOverride: "false", targetNamePrefix: "", targetNameIncludeProject: "true", targetNameIncludeUser: "false", targetNameIncludeDevName: "true",
    profileId: "11111111-1111-1111-1111-111111111111", incrementalMode: "false",
};

const PROJECT_DEFAULTS: Defaults = {
    apiUrl: "", apiKey: "",
    scanSpeed: "", criticalThreshold: "", highThreshold: "", mediumThreshold: "", failBuild: "", abortScan: "",
    enabledBranches: "", enabledEnvironments: "", strictModeEnabled: "", detectionMethods: [], overrideDetection: false,
    allowedDomainRegex: "", requireAuth: "", restrictApiScans: "",
    tagProject: "", tagRepo: "", tagUser: "", tagCommit: "", customTags: "",
    complianceFrameworks: [],
    targetNameOverride: "", targetNamePrefix: "", targetNameIncludeProject: "", targetNameIncludeUser: "", targetNameIncludeDevName: "",
    profileId: "", incrementalMode: "",
};

type SectionKey = "connection" | "trigger" | "guardrails" | "thresholds" | "tagging" | "compliance";
const SECTION_ORDER: SectionKey[] = ["connection", "trigger", "guardrails", "thresholds", "tagging", "compliance"];

type FieldState = "normal" | "inherited" | "overridden";
const fieldStateOf = (isProjectTabActive: boolean, value: string): FieldState => {
    if (!isProjectTabActive) return "normal";
    return value ? "overridden" : "inherited";
};

// ---- Shared styles (module-level: pure functions of state, safe to reuse across renders) ----
const rowWrapperStyle = (state: FieldState): React.CSSProperties => ({
    display: "flex", alignItems: "flex-start", gap: 16, padding: "16px 20px",
    borderBottom: `1px solid ${T.surface200}`,
    background: state === "overridden" ? "#faf9ff" : T.surface0,
});
const inputBoxStyle = (state: FieldState): React.CSSProperties => {
    const base: React.CSSProperties = {
        width: "100%", boxSizing: "border-box", padding: "8px 12px", borderRadius: 6,
        fontFamily: T.font, fontSize: 14, height: 36,
    };
    if (state === "overridden") return { ...base, border: `1px solid ${T.surface400}`, borderLeft: `3px solid ${T.accent800}`, background: "#faf9ff", color: T.surface900, fontWeight: 500 };
    if (state === "inherited") return { ...base, border: `1px solid ${T.surface200}`, background: T.surface50, color: T.surface900, fontStyle: "italic" };
    return { ...base, border: `1px solid ${T.surface400}`, background: T.surface0, color: T.surface900 };
};
const labelStyle: React.CSSProperties = { fontSize: 14, fontWeight: 600, color: T.surface900 };
const descStyle: React.CSSProperties = { margin: 0, fontSize: 12, color: T.surface700, lineHeight: 1.5 };
const badgeStyle: React.CSSProperties = { background: T.accent100, color: T.accent800, fontSize: 10, fontWeight: 600, padding: "2px 7px", borderRadius: 9999 };
const noteStyle = (state: FieldState): React.CSSProperties => ({
    margin: "4px 0 0", fontSize: 12,
    color: state === "overridden" ? T.accent800 : T.surface500,
    fontWeight: state === "overridden" ? 500 : 400,
});

// ---- Reusable field components (module-level so identity is stable across App re-renders —
// defining these inside App() would remount inputs on every keystroke and eat focus) ----

function TextField(props: {
    label: string; value: string; setter: (v: string) => void; placeholder: string;
    desc?: string; type?: string; hint?: string; isProjectTabActive: boolean; min?: number;
}) {
    const state = fieldStateOf(props.isProjectTabActive, props.value);
    const isNumber = props.type === "number";
    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        let v = e.target.value;
        if (isNumber && v !== "" && v !== "-") {
            const n = Number(v);
            if (!Number.isNaN(n) && n < 0) v = "0";
        }
        props.setter(v);
    };
    return (
        <div style={rowWrapperStyle(state)}>
            <div style={{ width: 280, flexShrink: 0, paddingRight: 24 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                    <label style={labelStyle}>{props.label}</label>
                    {state === "overridden" && <span style={badgeStyle}>Custom</span>}
                </div>
                {props.desc && <p style={descStyle}>{props.desc}</p>}
                {state === "inherited" && <p style={noteStyle(state)}>Inherited from global{props.hint ? ` — ${props.hint}` : ""}</p>}
                {state === "overridden" && <p style={noteStyle(state)}>Set at project level</p>}
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
                <input type={props.type || "text"} value={props.value} onChange={handleChange}
                       min={isNumber ? (props.min ?? 0) : undefined}
                       placeholder={props.isProjectTabActive ? "Inherit from global" : props.placeholder}
                       style={inputBoxStyle(state)} />
            </div>
        </div>
    );
}

function SelectField(props: {
    label: string; value: string; setter: (v: string) => void; options: { val: string; lbl: string }[];
    desc?: string; isProjectTabActive: boolean;
}) {
    const state = fieldStateOf(props.isProjectTabActive, props.value);
    return (
        <div style={rowWrapperStyle(state)}>
            <div style={{ width: 280, flexShrink: 0, paddingRight: 24 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                    <label style={labelStyle}>{props.label}</label>
                    {state === "overridden" && <span style={badgeStyle}>Custom</span>}
                </div>
                {props.desc && <p style={descStyle}>{props.desc}</p>}
                {state === "inherited" && <p style={noteStyle(state)}>Inherited from global</p>}
                {state === "overridden" && <p style={noteStyle(state)}>Set at project level</p>}
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
                <select value={props.value} onChange={e => props.setter(e.target.value)} style={inputBoxStyle(state)}>
                    {props.isProjectTabActive && <option value="">— Inherit from global —</option>}
                    {props.options.map(o => <option key={o.val} value={o.val}>{o.lbl}</option>)}
                </select>
            </div>
        </div>
    );
}

function SectionHeader(props: { title: string; collapsed: boolean; onToggle: () => void }) {
    return (
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4, cursor: "pointer" }}
             onClick={props.onToggle}>
            <h6 style={{ margin: 0, fontFamily: T.font, fontWeight: 500, fontSize: 18, color: T.surface900 }}>{props.title}</h6>
            <span style={{ color: T.surface600, fontSize: 14 }}>{props.collapsed ? "⌄" : "⌃"}</span>
        </div>
    );
}

export default function App() {
    const [status, setStatus] = React.useState<string>("Initializing SDK...");
    const [activeTab, setActiveTab] = React.useState<"global" | "project">("global");
    const [projects, setProjects] = React.useState<TeamProjectReference[]>([]);
    const [selectedProjectId, setSelectedProjectId] = React.useState<string>("");
    const [collapsed, setCollapsed] = React.useState<Record<string, boolean>>({});
    const [lockedMinHeight, setLockedMinHeight] = React.useState<number>(0);
    const containerRef = React.useRef<HTMLDivElement>(null);

    // Snapshot of the resolved Global Baseline — used only to show "inherited from global" hints
    // while editing Project Overrides. Never sent back on save.
    const [globalSnapshot, setGlobalSnapshot] = React.useState<Defaults>(GLOBAL_DEFAULTS);

    const [apiUrl, setApiUrl] = React.useState<string>(GLOBAL_DEFAULTS.apiUrl);
    const [apiKey, setApiKey] = React.useState<string>(GLOBAL_DEFAULTS.apiKey);
    const [scanSpeed, setScanSpeed] = React.useState<string>(GLOBAL_DEFAULTS.scanSpeed);
    const [criticalThreshold, setCriticalThreshold] = React.useState<string>(GLOBAL_DEFAULTS.criticalThreshold);
    const [highThreshold, setHighThreshold] = React.useState<string>(GLOBAL_DEFAULTS.highThreshold);
    const [mediumThreshold, setMediumThreshold] = React.useState<string>(GLOBAL_DEFAULTS.mediumThreshold);
    const [failBuild, setFailBuild] = React.useState<string>(GLOBAL_DEFAULTS.failBuild);
    const [abortScan, setAbortScan] = React.useState<string>(GLOBAL_DEFAULTS.abortScan);
    const [enabledBranches, setEnabledBranches] = React.useState<string>(GLOBAL_DEFAULTS.enabledBranches);
    const [enabledEnvironments, setEnabledEnvironments] = React.useState<string>(GLOBAL_DEFAULTS.enabledEnvironments);
    const [strictModeEnabled, setStrictModeEnabled] = React.useState<string>(GLOBAL_DEFAULTS.strictModeEnabled);
    const [detectionMethods, setDetectionMethods] = React.useState<string[]>(GLOBAL_DEFAULTS.detectionMethods);
    const [overrideDetection, setOverrideDetection] = React.useState<boolean>(GLOBAL_DEFAULTS.overrideDetection);
    const [allowedDomainRegex, setAllowedDomainRegex] = React.useState<string>(GLOBAL_DEFAULTS.allowedDomainRegex);
    const [requireAuth, setRequireAuth] = React.useState<string>(GLOBAL_DEFAULTS.requireAuth);
    const [restrictApiScans, setRestrictApiScans] = React.useState<string>(GLOBAL_DEFAULTS.restrictApiScans);
    const [tagProject, setTagProject] = React.useState<string>(GLOBAL_DEFAULTS.tagProject);
    const [tagRepo, setTagRepo] = React.useState<string>(GLOBAL_DEFAULTS.tagRepo);
    const [tagUser, setTagUser] = React.useState<string>(GLOBAL_DEFAULTS.tagUser);
    const [tagCommit, setTagCommit] = React.useState<string>(GLOBAL_DEFAULTS.tagCommit);
    const [customTags, setCustomTags] = React.useState<string>(GLOBAL_DEFAULTS.customTags);
    const [complianceFrameworks, setComplianceFrameworks] = React.useState<string[]>(GLOBAL_DEFAULTS.complianceFrameworks);
    const [targetNameOverride, setTargetNameOverride] = React.useState<string>(GLOBAL_DEFAULTS.targetNameOverride);
    const [targetNamePrefix, setTargetNamePrefix] = React.useState<string>(GLOBAL_DEFAULTS.targetNamePrefix);
    const [targetNameIncludeProject, setTargetNameIncludeProject] = React.useState<string>(GLOBAL_DEFAULTS.targetNameIncludeProject);
    const [targetNameIncludeUser, setTargetNameIncludeUser] = React.useState<string>(GLOBAL_DEFAULTS.targetNameIncludeUser);
    const [targetNameIncludeDevName, setTargetNameIncludeDevName] = React.useState<string>(GLOBAL_DEFAULTS.targetNameIncludeDevName);
    const [profileId, setProfileId] = React.useState<string>(GLOBAL_DEFAULTS.profileId);
    const [incrementalMode, setIncrementalMode] = React.useState<string>(GLOBAL_DEFAULTS.incrementalMode);

    // FQDN to RegEx builder state (local UI only, never persisted)
    const [fqdnSample, setFqdnSample] = React.useState<string>("");
    const [fqdnWildcardSub, setFqdnWildcardSub] = React.useState<boolean>(true);
    const [fqdnAllowHttp, setFqdnAllowHttp] = React.useState<boolean>(false);
    const [fqdnIncludePath, setFqdnIncludePath] = React.useState<boolean>(false);

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

    const applyDefaults = (d: Defaults) => {
        setApiUrl(d.apiUrl); setApiKey(d.apiKey);
        setScanSpeed(d.scanSpeed); setCriticalThreshold(d.criticalThreshold); setHighThreshold(d.highThreshold);
        setMediumThreshold(d.mediumThreshold); setFailBuild(d.failBuild); setAbortScan(d.abortScan);
        setEnabledBranches(d.enabledBranches); setEnabledEnvironments(d.enabledEnvironments);
        setStrictModeEnabled(d.strictModeEnabled); setDetectionMethods(d.detectionMethods); setOverrideDetection(d.overrideDetection);
        setAllowedDomainRegex(d.allowedDomainRegex); setRequireAuth(d.requireAuth); setRestrictApiScans(d.restrictApiScans);
        setTagProject(d.tagProject); setTagRepo(d.tagRepo); setTagUser(d.tagUser); setTagCommit(d.tagCommit); setCustomTags(d.customTags);
        setComplianceFrameworks(d.complianceFrameworks);
        setTargetNameOverride(d.targetNameOverride); setTargetNamePrefix(d.targetNamePrefix);
        setTargetNameIncludeProject(d.targetNameIncludeProject); setTargetNameIncludeUser(d.targetNameIncludeUser); setTargetNameIncludeDevName(d.targetNameIncludeDevName);
        setProfileId(d.profileId); setIncrementalMode(d.incrementalMode);
        setEtag(undefined);
    };

    const loadPolicy = async (tab: "global" | "project", projId?: string) => {
        try {
            setStatus(`Loading ${tab} policies...`);
            const defaults = tab === "global" ? GLOBAL_DEFAULTS : PROJECT_DEFAULTS;
            applyDefaults(defaults);
            const resolved: Defaults = { ...defaults };

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
                    if (doc.apiUrl !== undefined) { setApiUrl(doc.apiUrl); resolved.apiUrl = doc.apiUrl; }
                    if (doc.apiKey !== undefined) { setApiKey(doc.apiKey); resolved.apiKey = doc.apiKey; }

                    if (doc.padlocks) {
                        if (doc.padlocks.scan_speed !== undefined) { setScanSpeed(doc.padlocks.scan_speed); resolved.scanSpeed = doc.padlocks.scan_speed; }
                        if (doc.padlocks.critical_threshold !== undefined) { const v = String(doc.padlocks.critical_threshold); setCriticalThreshold(v); resolved.criticalThreshold = v; }
                        if (doc.padlocks.high_threshold !== undefined) { const v = String(doc.padlocks.high_threshold); setHighThreshold(v); resolved.highThreshold = v; }
                        if (doc.padlocks.medium_threshold !== undefined) { const v = String(doc.padlocks.medium_threshold); setMediumThreshold(v); resolved.mediumThreshold = v; }
                        if (doc.padlocks.fail_build_on_findings !== undefined) { setFailBuild(doc.padlocks.fail_build_on_findings); resolved.failBuild = doc.padlocks.fail_build_on_findings; }
                        if (doc.padlocks.abort_scan_on_findings !== undefined) { setAbortScan(doc.padlocks.abort_scan_on_findings); resolved.abortScan = doc.padlocks.abort_scan_on_findings; }
                        if (doc.padlocks.allowed_domain_regex !== undefined) { setAllowedDomainRegex(doc.padlocks.allowed_domain_regex); resolved.allowedDomainRegex = doc.padlocks.allowed_domain_regex; }
                        if (doc.padlocks.require_auth !== undefined) { setRequireAuth(doc.padlocks.require_auth); resolved.requireAuth = doc.padlocks.require_auth; }
                        if (doc.padlocks.restrict_api_scans !== undefined) { setRestrictApiScans(doc.padlocks.restrict_api_scans); resolved.restrictApiScans = doc.padlocks.restrict_api_scans; }
                        if (doc.padlocks.tag_project !== undefined) { setTagProject(doc.padlocks.tag_project); resolved.tagProject = doc.padlocks.tag_project; }
                        if (doc.padlocks.tag_repo !== undefined) { setTagRepo(doc.padlocks.tag_repo); resolved.tagRepo = doc.padlocks.tag_repo; }
                        if (doc.padlocks.tag_user !== undefined) { setTagUser(doc.padlocks.tag_user); resolved.tagUser = doc.padlocks.tag_user; }
                        if (doc.padlocks.tag_commit !== undefined) { setTagCommit(doc.padlocks.tag_commit); resolved.tagCommit = doc.padlocks.tag_commit; }
                        if (doc.padlocks.custom_tags !== undefined) { setCustomTags(doc.padlocks.custom_tags); resolved.customTags = doc.padlocks.custom_tags; }
                        if (Array.isArray(doc.padlocks.compliance_frameworks)) { setComplianceFrameworks(doc.padlocks.compliance_frameworks); resolved.complianceFrameworks = doc.padlocks.compliance_frameworks; }
                        if (doc.padlocks.target_name_override !== undefined) { setTargetNameOverride(doc.padlocks.target_name_override); resolved.targetNameOverride = doc.padlocks.target_name_override; }
                        if (doc.padlocks.target_name_prefix !== undefined) { setTargetNamePrefix(doc.padlocks.target_name_prefix); resolved.targetNamePrefix = doc.padlocks.target_name_prefix; }
                        if (doc.padlocks.target_name_include_project !== undefined) { setTargetNameIncludeProject(doc.padlocks.target_name_include_project); resolved.targetNameIncludeProject = doc.padlocks.target_name_include_project; }
                        if (doc.padlocks.target_name_include_user !== undefined) { setTargetNameIncludeUser(doc.padlocks.target_name_include_user); resolved.targetNameIncludeUser = doc.padlocks.target_name_include_user; }
                        if (doc.padlocks.target_name_include_dev_name !== undefined) { setTargetNameIncludeDevName(doc.padlocks.target_name_include_dev_name); resolved.targetNameIncludeDevName = doc.padlocks.target_name_include_dev_name; }
                        if (doc.padlocks.profile_id !== undefined) { setProfileId(doc.padlocks.profile_id); resolved.profileId = doc.padlocks.profile_id; }
                        if (doc.padlocks.incremental_mode !== undefined) { setIncrementalMode(doc.padlocks.incremental_mode); resolved.incrementalMode = doc.padlocks.incremental_mode; }
                    }

                    if (doc.injection_constraints) {
                        if (doc.injection_constraints.enabled_branches !== undefined) { const v = doc.injection_constraints.enabled_branches.join(", "); setEnabledBranches(v); resolved.enabledBranches = v; }
                        if (doc.injection_constraints.enabled_environments !== undefined) { const v = doc.injection_constraints.enabled_environments.join(", "); setEnabledEnvironments(v); resolved.enabledEnvironments = v; }
                        if (doc.injection_constraints.strict_mode_enabled !== undefined) { const v = String(doc.injection_constraints.strict_mode_enabled); setStrictModeEnabled(v); resolved.strictModeEnabled = v; }
                        if (doc.injection_constraints.detection_methods !== undefined) {
                            setDetectionMethods(doc.injection_constraints.detection_methods);
                            setOverrideDetection(true);
                            resolved.detectionMethods = doc.injection_constraints.detection_methods;
                            resolved.overrideDetection = true;
                        }
                    }
                    setEtag(doc.__etag);
                }
            } catch (e) {
                // Document missing — fine for projects
            }

            if (tab === "global") setGlobalSnapshot(resolved);
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
            applyDefaults(PROJECT_DEFAULTS);
            setStatus("Please select a project to configure overrides.");
        }
    };

    const handleProjectChange = async (e: React.ChangeEvent<HTMLSelectElement>) => {
        const pId = e.target.value;
        setSelectedProjectId(pId);
        if (!pId) { applyDefaults(PROJECT_DEFAULTS); setStatus("Please select a project to configure overrides."); return; }
        await loadPolicy("project", pId);
    };

    const handleToggleMethod = (methodId: string) => {
        setDetectionMethods(prev => prev.includes(methodId) ? prev.filter(m => m !== methodId) : [...prev, methodId]);
    };

    const handleToggleFramework = (fw: string) => {
        setComplianceFrameworks(prev => prev.includes(fw) ? prev.filter(f => f !== fw) : [...prev, fw]);
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
                ...cleanObj({ apiUrl, apiKey }),
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
                    allowed_domain_regex: allowedDomainRegex,
                    require_auth: requireAuth,
                    restrict_api_scans: restrictApiScans,
                    tag_project: tagProject,
                    tag_repo: tagRepo,
                    tag_user: tagUser,
                    tag_commit: tagCommit,
                    custom_tags: customTags,
                    compliance_frameworks: complianceFrameworks,
                    target_name_override: targetNameOverride,
                    target_name_prefix: targetNamePrefix,
                    target_name_include_project: targetNameIncludeProject,
                    target_name_include_user: targetNameIncludeUser,
                    target_name_include_dev_name: targetNameIncludeDevName,
                    profile_id: profileId,
                    incremental_mode: incrementalMode
                })
            };

            if (Object.keys(policyDocument.injection_constraints).length === 0) delete policyDocument.injection_constraints;
            if (Object.keys(policyDocument.padlocks).length === 0) delete policyDocument.padlocks;

            console.log(`[Admin Hub] Saving ${isGlobal ? 'Global' : 'Project'} Payload:`, JSON.stringify(policyDocument, null, 2));

            if (etag !== undefined) policyDocument.__etag = etag;

            const savedDoc = await dataManager.setDocument(collection, policyDocument);
            if (savedDoc && savedDoc.__etag) setEtag(savedDoc.__etag);

            setStatus(`Success. ${isGlobal ? 'Global policies' : 'Project overrides'} saved.`);
        } catch (err: any) {
            console.error("[Admin Hub] Save failed:", err);
            setStatus(`Failed to save policies: ${err.message || err.toString()}`);
        }
    };

    const handleDiscard = () => {
        if (activeTab === "global") loadPolicy("global");
        else if (selectedProjectId) loadPolicy("project", selectedProjectId);
    };

    // Clamp threshold fields so they can never go negative, even via the number spinner.
    const clampedSetCritical = (v: string) => setCriticalThreshold(v === "" || v === "-" ? v : String(Math.max(0, Number(v))));
    const clampedSetHigh = (v: string) => setHighThreshold(v === "" || v === "-" ? v : String(Math.max(0, Number(v))));
    const clampedSetMedium = (v: string) => setMediumThreshold(v === "" || v === "-" ? v : String(Math.max(0, Number(v))));

    // ---- Derived state ----
    const isProjectTabActive = activeTab === "project";
    const hideForm = isProjectTabActive && !selectedProjectId;

    const buildNamePreview = () => {
        if (targetNameOverride !== "true") return null;
        const parts: string[] = [];
        if (targetNamePrefix.trim()) parts.push(targetNamePrefix.trim());
        if (targetNameIncludeProject === "true") parts.push("<ADO_Project>");
        if (targetNameIncludeUser === "true") parts.push("<ADO_User>");
        if (targetNameIncludeDevName === "true") parts.push("<dev target name>");
        return parts.length > 0 ? parts.join(" | ") : "(no components selected)";
    };


    // Converts a sample URL to an escaped regex string (stored value, fed to new RegExp() in index.js).
    const buildFqdnRegex = (): string => {
        if (!fqdnSample.trim()) return "";
        let input = fqdnSample.trim();
        try {
            if (!/^https?:\/\//i.test(input)) input = "https://" + input;
            const parsed = new URL(input);
            const proto = fqdnAllowHttp ? "https?" : parsed.protocol.replace(":", "");
            const hostname = parsed.hostname;
            const parts = hostname.split(".");
            let hostPart: string;
            if (fqdnWildcardSub && parts.length > 2) {
                const base = parts.slice(-2).map(p => p.replace(/\./g, "\\.")).join("\\.");
                hostPart = `.*\\.${base}`;
            } else if (fqdnWildcardSub && parts.length === 2) {
                const escaped = parts.map(p => p.replace(/\./g, "\\.")).join("\\.");
                hostPart = `(.*\\.)?${escaped}`;
            } else {
                hostPart = hostname.replace(/\./g, "\\.");
            }
            const portPart = parsed.port ? `\\:${parsed.port}` : "";
            let pathPart = "";
            if (fqdnIncludePath && parsed.pathname && parsed.pathname !== "/") {
                pathPart = parsed.pathname.replace(/\//g, "\\/");
            }
            return `^${proto}:\\/\\/${hostPart}${portPart}${pathPart}`;
        } catch {
            return "(invalid URL)";
        }
    };

    const toggleSection = (key: SectionKey) => setCollapsed(prev => ({ ...prev, [key]: !prev[key] }));
    const allCollapsed = SECTION_ORDER.every(k => collapsed[k]);
    const toggleAllSections = () => {
        if (allCollapsed) setCollapsed({});
        else {
            const next: Record<string, boolean> = {};
            SECTION_ORDER.forEach(k => { next[k] = true; });
            setCollapsed(next);
        }
    };

    const statusIsError = /fail/i.test(status);
    const statusIsSuccess = /success/i.test(status);
    const statusBoxStyle: React.CSSProperties = {
        display: "flex", gap: 8, alignItems: "flex-start", borderRadius: 8, padding: "12px 14px", fontSize: 13, marginBottom: 20,
        background: statusIsError ? T.red100 : statusIsSuccess ? T.green100 : T.blue100,
        color: statusIsError ? T.red900 : statusIsSuccess ? T.green900 : T.blue900,
    };

    const fqdnGenerated = buildFqdnRegex();
    const fqdnIsError = fqdnGenerated.startsWith("(");

    // Lock the container to the tallest rendered height — prevents the ADO iframe
    // from shrinking when sections are collapsed.
    React.useLayoutEffect(() => {
        if (containerRef.current) {
            const h = containerRef.current.scrollHeight;
            if (h > lockedMinHeight) setLockedMinHeight(h);
        }
    });

    return (
        <div ref={containerRef} style={{ fontFamily: T.font, maxWidth: "920px", padding: "32px 36px 40px", background: T.surface0, color: T.surface900, minHeight: lockedMinHeight > 0 ? lockedMinHeight : undefined }}>

            {/* Header */}
            <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 20 }}>
                <span style={{ width: 36, height: 36, borderRadius: 10, background: T.gradientPlum, color: "#fff", flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center" }}>
                    <svg width="18" height="18" viewBox="0 0 18.005 18.040" fill="none">
                        <path d="M 9.299 12.079 L 9.299 7.839 C 9.299 7.59 9.098 7.388 8.849 7.388 L 7.794 7.388 C 7.545 7.388 7.343 7.59 7.343 7.839 L 7.343 12.334 C 7.343 12.989 7.541 13.537 7.922 13.922 C 8.304 14.307 8.844 14.503 9.48 14.503 C 9.885 14.503 10.163 14.447 10.336 14.396 C 10.53 14.337 10.634 14.157 10.634 13.983 L 10.634 13.119 C 10.634 12.831 10.376 12.632 10.113 12.659 C 10.037 12.666 9.957 12.672 9.886 12.672 C 9.63 12.672 9.499 12.616 9.428 12.545 C 9.356 12.474 9.299 12.341 9.299 12.079 Z" fill="currentColor" />
                        <path d="M 7.16 4.692 C 7.16 5.347 7.679 5.869 8.315 5.869 C 8.946 5.869 9.482 5.351 9.482 4.692 C 9.482 4.039 8.964 3.503 8.315 3.503 C 7.661 3.503 7.16 4.044 7.16 4.692 Z" fill="currentColor" />
                        <path d="M 2.77 0 C 1.24 0 0 1.24 0 2.77 L 0 15.27 C 0 16.8 1.24 18.04 2.77 18.04 L 15.235 18.04 C 16.765 18.04 18.005 16.8 18.005 15.27 L 18.005 2.77 C 18.005 1.24 16.765 0 15.235 0 L 2.77 0 Z M 1.385 2.77 C 1.385 2.005 2.005 1.385 2.77 1.385 L 15.235 1.385 C 16 1.385 16.62 2.005 16.62 2.77 L 16.62 15.27 C 16.62 16.035 16 16.655 15.235 16.655 L 2.77 16.655 C 2.005 16.655 1.385 16.035 1.385 15.27 L 1.385 2.77 Z" fill="currentColor" fillRule="evenodd" />
                    </svg>
                </span>
                <div>
                    <div style={{ fontSize: 12, fontWeight: 400, color: T.surface600, textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 4 }}>AppSec Governance</div>
                    <h3 style={{ margin: 0, fontFamily: T.font, fontWeight: 700, fontSize: 24, color: T.surface900 }}>Invicti DAST Governance Policy</h3>
                </div>
            </div>

            {/* Tabs + collapse-all */}
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 18 }}>
                <div style={{ display: "inline-flex", background: T.surface100, padding: 3, borderRadius: 8 }}>
                    {(["global", "project"] as const).map(t => (
                        <button key={t} onClick={() => handleTabChange(t)} style={{
                            border: 0, padding: "7px 16px", borderRadius: 6, fontFamily: T.font, fontSize: 13, fontWeight: 600, cursor: "pointer",
                            background: activeTab === t ? T.surface0 : "transparent",
                            color: activeTab === t ? T.accent800 : T.surface700,
                            boxShadow: activeTab === t ? "0 1px 2px rgba(16,23,33,.1)" : "none",
                        }}>
                            {t === "global" ? "Global baseline" : "Project overrides"}
                        </button>
                    ))}
                </div>
                {!hideForm && (
                    <button onClick={toggleAllSections} style={{
                        background: "transparent", border: `1px solid ${T.surface400}`, color: T.surface800, padding: "7px 14px",
                        borderRadius: 6, fontFamily: T.font, fontSize: 13, fontWeight: 500, cursor: "pointer", whiteSpace: "nowrap",
                    }}>
                        {allCollapsed ? "Expand all" : "Collapse all"}
                    </button>
                )}
            </div>

            {/* Status */}
            <div style={statusBoxStyle}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round" width={16} height={16} style={{ flexShrink: 0, marginTop: 2 }}>
                    <circle cx="12" cy="12" r="9" /><path d="M12 8h.01M11 12h1v4h1" />
                </svg>
                <span>{status}</span>
            </div>

            {/* Project selector */}
            {isProjectTabActive && (
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16, border: `1px solid ${T.accent300}`, background: T.accent50, borderRadius: 8, padding: "12px 16px", marginBottom: 24 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0, flex: 1 }}>
                        <span style={{ fontSize: 13, fontWeight: 600, color: T.accent900, whiteSpace: "nowrap" }}>Configuring overrides for</span>
                        <select value={selectedProjectId} onChange={handleProjectChange} style={{
                            fontSize: 14, fontWeight: 600, color: T.surface900, background: T.surface0, border: `1px solid ${T.accent300}`,
                            borderRadius: 6, padding: "6px 10px", fontFamily: T.font, flex: 1, minWidth: 0,
                        }}>
                            <option value="">— Choose a project —</option>
                            {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                        </select>
                    </div>
                </div>
            )}

            {!hideForm && (
                <>
                    {/* Connection */}
                    <div style={{ marginBottom: 28 }}>
                        <SectionHeader title="Connection" collapsed={!!collapsed.connection} onToggle={() => toggleSection("connection")} />
                        {!collapsed.connection && (
                            <div style={{ border: `1px solid ${T.surface200}`, borderRadius: 8, overflow: "hidden" }}>
                                <TextField label="DAST API URL" value={apiUrl} setter={setApiUrl} placeholder="https://platform.invicti.com"
                                           desc="Base URL for your corporate vulnerability management platform." hint={globalSnapshot.apiUrl} isProjectTabActive={isProjectTabActive} />
                                <TextField label="DAST API key" value={apiKey} setter={setApiKey} placeholder="Enter API key" type="password"
                                           desc="Secret token for authenticated background actions." hint="inherits the global API key" isProjectTabActive={isProjectTabActive} />
                            </div>
                        )}
                    </div>

                    {/* Scan Trigger Conditions */}
                    <div style={{ marginBottom: 28 }}>
                        <SectionHeader title="Scan Trigger Conditions" collapsed={!!collapsed.trigger} onToggle={() => toggleSection("trigger")} />
                        {!collapsed.trigger && (
                            <div style={{ border: `1px solid ${T.surface200}`, borderRadius: 8, overflow: "hidden" }}>
                                <TextField label="Target git branches" value={enabledBranches} setter={setEnabledBranches} placeholder="refs/heads/main, refs/heads/master"
                                           desc="Supports wildcards, e.g. refs/heads/release/*" hint={globalSnapshot.enabledBranches} isProjectTabActive={isProjectTabActive} />
                                <TextField label="Monitored environments" value={enabledEnvironments} setter={setEnabledEnvironments} placeholder="Staging, UAT"
                                           desc="Deployment contexts that require DAST coverage." hint={globalSnapshot.enabledEnvironments} isProjectTabActive={isProjectTabActive} />

                                <div style={rowWrapperStyle("normal")}>
                                    <div style={{ width: 280, flexShrink: 0, paddingRight: 24 }}>
                                        <label style={labelStyle}>Environment detection strategy</label>
                                        <p style={descStyle}>Pipelines missing environment labels fail instantly when strict mode is enabled.</p>
                                    </div>
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        {isProjectTabActive && (
                                            <label style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10, color: T.accent800, fontWeight: 600, fontSize: 13, cursor: "pointer" }}>
                                                <input type="checkbox" checked={overrideDetection} onChange={e => setOverrideDetection(e.target.checked)} />
                                                Override global detection strategy
                                            </label>
                                        )}
                                        <div style={{ opacity: (!isProjectTabActive || overrideDetection) ? 1 : 0.4, pointerEvents: (!isProjectTabActive || overrideDetection) ? "auto" : "none", display: "flex", flexDirection: "column", gap: 8 }}>
                                            {["deployment_job", "native_env_object", "pipeline_variable"].map(m => (
                                                <label key={m} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 14, cursor: "pointer", color: T.surface900 }}>
                                                    <input type="checkbox" checked={detectionMethods.includes(m)} onChange={() => handleToggleMethod(m)} />
                                                    {m.replace(/_/g, " ")}
                                                </label>
                                            ))}
                                        </div>
                                    </div>
                                </div>

                                <SelectField label="Strict context mode" value={strictModeEnabled} setter={setStrictModeEnabled}
                                             options={[{ val: "true", lbl: "Enabled — break builds missing environments" }, { val: "false", lbl: "Disabled — scan regardless" }]}
                                             desc="Fail-secure gate for missing environment metadata." isProjectTabActive={isProjectTabActive} />
                            </div>
                        )}
                    </div>

                    {/* Domain & Auth Guardrails */}
                    <div style={{ marginBottom: 28 }}>
                        <SectionHeader title="Domain & Auth Guardrails" collapsed={!!collapsed.guardrails} onToggle={() => toggleSection("guardrails")} />
                        {!collapsed.guardrails && (
                            <div style={{ border: `1px solid ${T.surface200}`, borderRadius: 8, overflow: "hidden" }}>
                                <TextField label="Allowed domain scope (RegEx)" value={allowedDomainRegex} setter={setAllowedDomainRegex}
                                           placeholder="^https:\/\/.*\.staging\.company\.com"
                                           desc="Prevents scanning of unauthorized or production endpoints." hint={globalSnapshot.allowedDomainRegex} isProjectTabActive={isProjectTabActive} />

                                {/* RegEx builder helper */}
                                <div style={{ padding: "14px 20px", borderBottom: `1px solid ${T.surface200}`, background: T.surface50 }}>
                                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                                        <span style={{ fontSize: 11, fontWeight: 700, color: T.accent800, textTransform: "uppercase", letterSpacing: "0.06em", background: T.accent100, padding: "2px 8px", borderRadius: 9999 }}>RegEx builder</span>
                                        <span style={{ fontSize: 12, color: T.surface600 }}>Type a sample URL — we generate the pattern for you</span>
                                    </div>
                                    <div style={{ marginBottom: 10 }}>
                                        <input
                                            value={fqdnSample}
                                            onChange={e => setFqdnSample(e.target.value)}
                                            placeholder="https://staging.testinvicti.com"
                                            style={{
                                                width: "100%", boxSizing: "border-box", padding: "7px 12px",
                                                border: `1px solid ${T.surface400}`, borderRadius: 6,
                                                fontFamily: T.font, fontSize: 13, color: T.surface900, background: T.surface0,
                                            }}
                                        />
                                    </div>
                                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 10 }}>
                                        {[
                                            { key: "sub",  label: "Wildcard subdomains", tip: "staging.company.com -> .*\\.company\\.com", val: fqdnWildcardSub,  set: setFqdnWildcardSub  },
                                            { key: "http", label: "Allow HTTP too",       tip: "https -> https?",                              val: fqdnAllowHttp,    set: setFqdnAllowHttp    },
                                            { key: "path", label: "Include path",         tip: "Locks pattern to the exact URL path",          val: fqdnIncludePath,  set: setFqdnIncludePath  },
                                        ].map(opt => (
                                            <button key={opt.key} title={opt.tip} onClick={() => opt.set(!opt.val)} style={{
                                                border: 0, cursor: "pointer", fontFamily: T.font, fontSize: 12, fontWeight: 600,
                                                padding: "4px 12px", borderRadius: 9999,
                                                background: opt.val ? T.accent100 : T.surface200,
                                                color:      opt.val ? T.accent800 : T.surface600,
                                            }}>
                                                {opt.val ? "✓" : "○"} {opt.label}
                                            </button>
                                        ))}
                                    </div>
                                    {fqdnSample.trim() ? (
                                        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                                            <code style={{
                                                flex: 1, display: "block", padding: "8px 12px",
                                                background: fqdnIsError ? T.red100 : T.surface0,
                                                border: `1px solid ${fqdnIsError ? T.red900 : T.surface400}`,
                                                borderRadius: 6, fontFamily: "monospace", fontSize: 13,
                                                color: fqdnIsError ? T.red900 : T.surface900,
                                                wordBreak: "break-all", lineHeight: 1.5,
                                            }}>
                                                {fqdnGenerated}
                                            </code>
                                            {!fqdnIsError && (
                                                <button
                                                    onClick={() => setAllowedDomainRegex(fqdnGenerated)}
                                                    style={{
                                                        flexShrink: 0, border: 0, cursor: "pointer", fontFamily: T.font,
                                                        fontSize: 13, fontWeight: 600, padding: "8px 16px", borderRadius: 6,
                                                        background: T.accent800, color: "#fff", whiteSpace: "nowrap",
                                                    }}
                                                >
                                                    Apply
                                                </button>
                                            )}
                                        </div>
                                    ) : (
                                        <p style={{ margin: 0, fontSize: 12, color: T.surface500, fontStyle: "italic" }}>
                                            Enter a sample URL above to preview the generated regex.
                                        </p>
                                    )}
                                </div>

                                <SelectField label="Mandatory authentication" value={requireAuth} setter={setRequireAuth}
                                             options={[{ val: "true", lbl: "Enabled — block unauthenticated scans" }, { val: "false", lbl: "Disabled — allow unauthenticated scans" }]}
                                             desc="Breaks the build if devs fail to supply auth config." isProjectTabActive={isProjectTabActive} />
                                <SelectField label="API specification lockdown" value={restrictApiScans} setter={setRestrictApiScans}
                                             options={[{ val: "true", lbl: "Enabled — restrict to uploaded specs" }, { val: "false", lbl: "Disabled — allow standard crawling" }]}
                                             desc="Restricts API-type targets to uploaded specs only." isProjectTabActive={isProjectTabActive} />
                            </div>
                        )}
                    </div>

                    {/* Risk Thresholds & Enforcement */}
                    <div style={{ marginBottom: 28 }}>
                        <SectionHeader title="Risk Thresholds & Enforcement" collapsed={!!collapsed.thresholds} onToggle={() => toggleSection("thresholds")} />
                        {!collapsed.thresholds && (
                            <div style={{ border: `1px solid ${T.surface200}`, borderRadius: 8, overflow: "hidden" }}>
                                <SelectField label="Enforced scan speed" value={scanSpeed} setter={setScanSpeed}
                                             options={[{ val: "slow", lbl: "Slow — thorough" }, { val: "moderate", lbl: "Moderate" }, { val: "fast", lbl: "Fast" }, { val: "sequential", lbl: "Sequential" }]}
                                             desc="Hardlocks execution speed; prevents dev throttling bypass." isProjectTabActive={isProjectTabActive} />
                                <TextField label="Scan profile ID" value={profileId} setter={setProfileId}
                                           placeholder="11111111-1111-1111-1111-111111111111"
                                           desc="Invicti scan profile UUID. Defaults to Full Scan (all-ones UUID). Copy the profile ID from Invicti under Scans > Profiles."
                                           hint={globalSnapshot.profileId} isProjectTabActive={isProjectTabActive} />
                                <SelectField label="Incremental scan mode" value={incrementalMode} setter={setIncrementalMode}
                                             options={[{ val: "true", lbl: "Enabled — scan only changed areas" }, { val: "false", lbl: "Disabled — full scan every time" }]}
                                             desc="When enabled, Invicti re-tests only areas that changed since the last scan. Requires a prior scan baseline." isProjectTabActive={isProjectTabActive} />
                                <TextField label="Critical ceiling" value={criticalThreshold} setter={clampedSetCritical} placeholder="1" type="number" min={0} hint={globalSnapshot.criticalThreshold} isProjectTabActive={isProjectTabActive} />
                                <TextField label="High ceiling" value={highThreshold} setter={clampedSetHigh} placeholder="3" type="number" min={0} hint={globalSnapshot.highThreshold} isProjectTabActive={isProjectTabActive} />
                                <TextField label="Medium ceiling" value={mediumThreshold} setter={clampedSetMedium} placeholder="5" type="number" min={0} hint={globalSnapshot.mediumThreshold} isProjectTabActive={isProjectTabActive} />
                                <SelectField label="Fail build on threshold breach" value={failBuild} setter={setFailBuild}
                                             options={[{ val: "true", lbl: "Enabled — break pipeline" }, { val: "false", lbl: "Disabled — warn only" }]}
                                             desc="Blocks risky deployments automatically." isProjectTabActive={isProjectTabActive} />
                                <SelectField label="Abort scan on threshold breach" value={abortScan} setter={setAbortScan}
                                             options={[{ val: "true", lbl: "Enabled — terminate active scan" }, { val: "false", lbl: "Disabled — let scan finish" }]}
                                             desc="Terminates active scanners the moment limits are broken." isProjectTabActive={isProjectTabActive} />
                            </div>
                        )}
                    </div>

                    {/* Tagging & Naming */}
                    <div style={{ marginBottom: 28 }}>
                        <SectionHeader title="Tagging & Naming" collapsed={!!collapsed.tagging} onToggle={() => toggleSection("tagging")} />
                        {!collapsed.tagging && (
                            <div style={{ border: `1px solid ${T.surface200}`, borderRadius: 8, overflow: "hidden" }}>
                                <SelectField label="Tag ADO project" value={tagProject} setter={setTagProject}
                                             options={[{ val: "true", lbl: "Inject tag" }, { val: "false", lbl: "Do not inject" }]} isProjectTabActive={isProjectTabActive} />
                                <SelectField label="Tag ADO repository" value={tagRepo} setter={setTagRepo}
                                             options={[{ val: "true", lbl: "Inject tag" }, { val: "false", lbl: "Do not inject" }]} isProjectTabActive={isProjectTabActive} />
                                <SelectField label="Tag ADO build user" value={tagUser} setter={setTagUser}
                                             options={[{ val: "true", lbl: "Inject tag" }, { val: "false", lbl: "Do not inject" }]} isProjectTabActive={isProjectTabActive} />
                                <SelectField label="Tag ADO commit SHA" value={tagCommit} setter={setTagCommit}
                                             options={[{ val: "true", lbl: "Inject tag" }, { val: "false", lbl: "Do not inject" }]} isProjectTabActive={isProjectTabActive} />
                                <TextField label="Custom organizational tags" value={customTags} setter={setCustomTags} placeholder="Billing:SecOps, Audit:2026-Q3"
                                           desc="Static tags applied to all assets under this scope." hint={globalSnapshot.customTags || "(none)"} isProjectTabActive={isProjectTabActive} />
                                <SelectField label="Target name override" value={targetNameOverride} setter={setTargetNameOverride}
                                             options={[{ val: "true", lbl: "Enabled — admin controls naming" }, { val: "false", lbl: "Disabled — developer controls naming" }]}
                                             desc="When enabled, admins control target naming instead of dast-config.yml." isProjectTabActive={isProjectTabActive} />

                                {targetNameOverride === "true" && (
                                    <div style={{ padding: "18px 20px", borderTop: `1px solid ${T.surface200}`, background: "#faf9ff" }}>
                                        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
                                            <span style={{ fontSize: 13, fontWeight: 600, color: T.accent800 }}>Target name override — configured</span>
                                        </div>
                                        <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 20, marginBottom: 14 }}>
                                            <div>
                                                <label style={{ display: "block", fontSize: 12, fontWeight: 600, color: T.surface700, marginBottom: 6 }}>Static prefix</label>
                                                <input value={targetNamePrefix} onChange={e => setTargetNamePrefix(e.target.value)} placeholder="e.g. [PROD] or MyOrg"
                                                       style={{ width: "100%", boxSizing: "border-box", border: `1px solid ${T.surface400}`, borderRadius: 6, padding: "8px 12px", fontFamily: T.font, fontSize: 13, color: T.surface900 }} />
                                            </div>
                                            <div>
                                                <label style={{ display: "block", fontSize: 12, fontWeight: 600, color: T.surface700, marginBottom: 6 }}>Name components</label>
                                                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                                                    {[
                                                        { lbl: "ADO project", val: targetNameIncludeProject, setter: setTargetNameIncludeProject },
                                                        { lbl: "ADO user", val: targetNameIncludeUser, setter: setTargetNameIncludeUser },
                                                        { lbl: "Dev target name", val: targetNameIncludeDevName, setter: setTargetNameIncludeDevName },
                                                    ].map(c => {
                                                        const on = c.val === "true";
                                                        return (
                                                            <button key={c.lbl} onClick={() => c.setter(on ? "false" : "true")} style={{
                                                                border: 0, cursor: "pointer", fontFamily: T.font,
                                                                background: on ? T.green100 : T.surface100, color: on ? T.green900 : T.surface600,
                                                                fontSize: 12, fontWeight: 600, padding: "4px 10px", borderRadius: 9999,
                                                            }}>
                                                                {on ? "✓" : "✕"} {c.lbl}
                                                            </button>
                                                        );
                                                    })}
                                                </div>
                                            </div>
                                        </div>
                                        <div style={{ border: `1px dashed ${T.accent300}`, borderRadius: 6, padding: "10px 12px", background: T.surface0 }}>
                                            <div style={{ fontSize: 11, fontWeight: 600, color: T.accent800, textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 4 }}>Constructed name preview</div>
                                            <code style={{ fontSize: 13, color: T.surface900 }}>{buildNamePreview()}</code>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>

                    {/* Compliance Tracking */}
                    <div style={{ marginBottom: 8 }}>
                        <SectionHeader title="Compliance Tracking" collapsed={!!collapsed.compliance} onToggle={() => toggleSection("compliance")} />
                        {!collapsed.compliance && (
                            <div style={{ border: `1px solid ${T.surface200}`, borderRadius: 8, padding: "16px 20px" }}>
                                <p style={{ margin: "0 0 10px", fontSize: 12, color: T.surface700 }}>Active frameworks annotate every scan event with control references in the pipeline log.</p>
                                <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                                    {ALL_FRAMEWORKS.map(fw => {
                                        const on = complianceFrameworks.includes(fw);
                                        return (
                                            <label key={fw} onClick={() => handleToggleFramework(fw)} style={{ display: "flex", gap: 12, padding: "10px 8px", borderRadius: 6, cursor: "pointer" }}>
                                                <span style={{
                                                    width: 18, height: 18, borderRadius: 4, flexShrink: 0, marginTop: 2, display: "flex", alignItems: "center", justifyContent: "center",
                                                    fontSize: 12, fontWeight: 700,
                                                    background: on ? T.accent800 : T.surface0, color: "#fff",
                                                    border: on ? "none" : `1.5px solid ${T.surface500}`,
                                                }}>{on ? "✓" : ""}</span>
                                                <div style={{ flex: 1, minWidth: 0 }}>
                                                    <strong style={{ fontSize: 14, color: T.surface900, fontWeight: 600 }}>{fw}</strong>
                                                    <div style={{ fontSize: 12, color: T.surface600, marginTop: 2 }}>{FRAMEWORK_REFS[fw]}</div>
                                                </div>
                                            </label>
                                        );
                                    })}
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Actions */}
                    <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, paddingTop: 20 }}>
                        <button onClick={handleDiscard} style={{
                            background: T.surface0, color: T.surface800, border: `1px solid ${T.surface400}`, padding: "9px 18px",
                            borderRadius: 6, fontFamily: T.font, fontSize: 14, fontWeight: 500, cursor: "pointer",
                        }}>
                            Discard
                        </button>
                        <button onClick={handleSave} style={{
                            background: T.accent800, color: "#fff", border: 0, padding: "9px 20px",
                            borderRadius: 6, fontFamily: T.font, fontSize: 14, fontWeight: 600, cursor: "pointer",
                        }}>
                            Save {activeTab === "global" ? "global baseline" : "project overrides"}
                        </button>
                    </div>
                </>
            )}
        </div>
    );
}
