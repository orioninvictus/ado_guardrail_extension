import * as React from "react";
import * as SDK from "azure-devops-extension-sdk";
import { getClient } from "azure-devops-extension-api";
import { BuildRestClient } from "azure-devops-extension-api/Build";

export default function App() {
    const [htmlContent, setHtmlContent] = React.useState<string>("Waiting for build context...");

    React.useEffect(() => {
        const fetchReport = async (build: any) => {
            try {
                setHtmlContent("Loading DAST Report attachment from pipeline...");
                const buildClient = getClient(BuildRestClient);
                const projectId = build.project.id;
                const buildId = build.id;

                // Query ADO for our specific hidden attachment type defined in moduleC.js
                const attachments = await buildClient.getAttachments(projectId, buildId, "invicti-dast-report");

                if (attachments && attachments.length > 0) {
                    const att = attachments[0]; // Get the first report generated
                    
                    setHtmlContent("Downloading report bytes...");
                    
                    // Safely extract the direct download URL from the attachment's _links object
                    const downloadUrl = (att as any)._links?.self?.href;
                    
                    if (!downloadUrl) {
                        throw new Error("Unable to resolve attachment download URL from Azure DevOps.");
                    }

                    // Fetch the raw bytes of the HTML file using the extension's native Auth Token
                    const token = await SDK.getAccessToken();
                    const response = await fetch(downloadUrl, {
                        headers: {
                            Authorization: `Bearer ${token}`
                        }
                    });

                    if (!response.ok) {
                        throw new Error(`Secure download failed with status ${response.status}`);
                    }

                    const arrayBuffer = await response.arrayBuffer();
                    
                    // Decode bytes back into an HTML string
                    const text = new TextDecoder("utf-8").decode(arrayBuffer);
                    setHtmlContent(text);
                } else {
                    setHtmlContent("<h3 style='color: #555; font-family: sans-serif; padding: 20px;'>No DAST scan report was generated or attached for this pipeline run.</h3>");
                }
            } catch (err: any) {
                setHtmlContent(`<h3 style='color: red; font-family: sans-serif; padding: 20px;'>Failed to load report: ${err.message}</h3>`);
            }
        };

        SDK.init().then(() => {
            SDK.ready().then(() => {
                const config = SDK.getConfiguration();
                
                // If the tab loads and already has the build data
                if (config.build) {
                    fetchReport(config.build);
                }
                
                // If Azure DevOps updates the build state dynamically while the tab is open
                if (config.onBuildChanged) {
                    config.onBuildChanged((build: any) => {
                        fetchReport(build);
                    });
                }
            });
        });
    }, []);

    // Render loading/error states natively
    if (htmlContent.startsWith("Wait") || htmlContent.startsWith("Load") || htmlContent.startsWith("<h3")) {
        return <div dangerouslySetInnerHTML={{ __html: htmlContent }} />;
    }

    // Render the final HTML string seamlessly inside an iframe (Bypasses CORS and Sandboxing issues perfectly)
    return (
        <iframe 
            srcDoc={htmlContent} 
            style={{ width: "100%", height: "100vh", border: "none", margin: 0, padding: 0 }} 
            title="Invicti DAST Report"
        />
    );
}