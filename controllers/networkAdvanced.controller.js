import { exec } from "child_process";
import { parseString } from "xml2js";
import fs from "fs/promises";
import { promisify } from "util";
import path from "path";
import fetch from "node-fetch";
import cron from "node-cron";
import puppeteer from "puppeteer";
import ApiError from "../utils/ApiError.js";
import ApiResponse from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { createReadStream } from "fs";

const execPromise = promisify(exec);
const scanResults = new Map();
const tempDir = path.join(process.cwd(), "temp");

// Ensure temp directory exists
try {
    await fs.mkdir(tempDir, { recursive: true });
} catch (error) {
    console.error("Failed to create temp directory:", error);
}

// Enhanced vulnerability scanning with NSE scripts
const runEnhancedVulnerabilityScan = async (target) => {
    const outputFile = path.join(tempDir, `vuln_scan_${Date.now()}.xml`);
    const command = `nmap -sV --script=http-vuln-cve2017-5638,vulners,vuln -oX "${outputFile}" ${target}`;

    try {
        await execPromise(command);
        const xmlData = await fs.readFile(outputFile, "utf8");
        await fs.unlink(outputFile);

        return new Promise((resolve, reject) => {
            parseString(xmlData, (err, result) => err ? reject(err) : resolve(result));
        });
    } catch (error) {
        throw new ApiError(500, `Enhanced vulnerability scan failed: ${error.message}`);
    }
};

// IP Reputation Check
const checkIPReputation = async (ip) => {
    if (!process.env.ABUSE_IPDB_API_KEY) {
        console.warn("AbuseIPDB API key not configured");
        return null;
    }

    const baseUrl = 'https://api.abuseipdb.com/api/v2';
    const headers = {
        'Key': process.env.ABUSE_IPDB_API_KEY,
        'Accept': 'application/json'
    };

    try {
        // 1. Check IP
        const checkResponse = await fetch(`${baseUrl}/check?ipAddress=${ip}&maxAgeInDays=90&verbose`, {
            headers
        });
        const checkData = await checkResponse.json();

        // Only proceed with additional checks if initial check is successful
        if (!checkResponse.ok) {
            throw new Error(`AbuseIPDB API error: ${checkResponse.statusText}`);
        }

        // Compile basic results first
        const compiledResults = {
            ipDetails: {
                ip: ip,
                isPublic: checkData.data?.isPublic,
                ipVersion: checkData.data?.ipVersion,
                isWhitelisted: checkData.data?.isWhitelisted,
                abuseConfidenceScore: checkData.data?.abuseConfidenceScore,
                countryCode: checkData.data?.countryCode,
                usageType: checkData.data?.usageType,
                isp: checkData.data?.isp,
                domain: checkData.data?.domain,
                totalReports: checkData.data?.totalReports,
                lastReportedAt: checkData.data?.lastReportedAt
            },
            reports: [],
            quotaStatus: {
                check: checkResponse.headers.get('X-RateLimit-Remaining') + ' / ' + checkResponse.headers.get('X-RateLimit-Limit')
            }
        };

        try {
            // 2. Get Reports (if available)
            const reportsResponse = await fetch(`${baseUrl}/reports?ipAddress=${ip}&maxAgeInDays=90&page=1&perPage=100`, {
                headers
            });
            
            if (reportsResponse.ok) {
                const reportsData = await reportsResponse.json();
                if (reportsData && Array.isArray(reportsData.data)) {
                    compiledResults.reports = reportsData.data.map(report => ({
                        reportedAt: report.reportedAt,
                        comment: report.comment,
                        categories: report.categories,
                        reporterId: report.reporterId,
                        confidence: report.confidence
                    }));
                }
                compiledResults.quotaStatus.reports = 
                    reportsResponse.headers.get('X-RateLimit-Remaining') + ' / ' + 
                    reportsResponse.headers.get('X-RateLimit-Limit');
            }
        } catch (reportError) {
            console.error("Failed to fetch reports:", reportError);
            compiledResults.reports = { error: "Failed to fetch reports" };
        }

        // Add summary information
        compiledResults.summary = {
            totalReports: compiledResults.reports.length,
            confidenceScore: checkData.data?.abuseConfidenceScore || 0,
            lastReported: checkData.data?.lastReportedAt || 'Never',
            riskLevel: getRiskLevel(checkData.data?.abuseConfidenceScore || 0)
        };

        return compiledResults;

    } catch (error) {
        console.error("IP reputation check failed:", error);
        return {
            error: error.message,
            status: 'failed',
            timestamp: new Date().toISOString()
        };
    }
};

// Helper function to determine risk level
const getRiskLevel = (confidenceScore) => {
    if (confidenceScore >= 80) return 'High Risk';
    if (confidenceScore >= 50) return 'Medium Risk';
    if (confidenceScore >= 20) return 'Low Risk';
    return 'Safe';
};

// Dark Web Monitoring
const checkDarkWebLeaks = async (email) => {
    if (!process.env.HIBP_API_KEY) {
        console.warn("HIBP API key not configured");
        return [];
    }

    try {
        const response = await fetch(
            `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}`,
            {
                headers: { 
                    "hibp-api-key": process.env.HIBP_API_KEY,
                    "user-agent": "NetworkSecurityTool"
                }
            }
        );

        if (response.status === 404) return [];
        if (!response.ok) throw new Error(`HIBP API error: ${response.statusText}`);

        return await response.json();
    } catch (error) {
        console.error("Dark web check failed:", error);
        return [];
    }
};

// Advanced Network Analysis
const analyzeNetworkSecurity = asyncHandler(async (req, res) => {
    const { ipRange } = req.params;
    if (!ipRange) throw new ApiError(400, "IP range is required");

    try {
        // Run enhanced vulnerability scan
        const scanResult = await runEnhancedVulnerabilityScan(ipRange);
        
        // Process vulnerabilities
        const vulnerabilities = [];
        const hosts = scanResult.nmaprun?.host || [];

        for (const host of hosts) {
            const ip = host.address?.find(addr => addr.$?.addrtype === "ipv4")?.$?.addr;
            if (!ip) continue;

            // Check IP reputation
            const reputation = await checkIPReputation(ip);

            // Process ports and vulnerabilities
            const ports = host.ports?.[0]?.port || [];
            for (const port of ports) {
                const scripts = port.script || [];
                for (const script of scripts) {
                    vulnerabilities.push({
                        ip,
                        port: port.$?.portid,
                        service: port.service?.[0]?.$?.name,
                        vulnerability: script.$?.id,
                        severity: script.$?.output?.includes("VULNERABLE") ? "High" : "Low",
                        description: script.$?.output,
                        threatScore: reputation?.abuseConfidenceScore || 0
                    });
                }
            }
        }

        return res.status(200).json(
            new ApiResponse(200, { vulnerabilities }, "Security analysis completed")
        );

    } catch (error) {
        throw new ApiError(500, `Security analysis failed: ${error.message}`);
    }
});

// Schedule automated scans
const scheduledScans = new Map();

const scheduleNetworkScan = asyncHandler(async (req, res) => {
    const { target, frequency } = req.body;
    if (!target || !frequency) {
        throw new ApiError(400, "Target and frequency are required");
    }

    const scanId = `scan_${Date.now()}`;
    const job = cron.schedule(frequency, async () => {
        try {
            console.log(`Running scheduled scan for ${target}`);
            const result = await runEnhancedVulnerabilityScan(target);
            console.log(`Scheduled scan completed for ${target}`);
            scanResults.set(scanId, {
                target,
                timestamp: new Date().toISOString(),
                result
            });
        } catch (error) {
            console.error(`Scheduled scan failed for ${target}:`, error);
            scanResults.set(scanId, {
                target,
                timestamp: new Date().toISOString(),
                error: error.message
            });
        }
    });

    scheduledScans.set(scanId, { target, frequency, job });

    return res.status(200).json(
        new ApiResponse(200, { scanId, target, frequency }, "Scan scheduled successfully")
    );
});

// Helper function to generate HTML report
const generateReportHtml = (scanResult) => {
    const hosts = scanResult.nmaprun?.host || [];
    let html = `
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; padding: 20px; }
                .header { text-align: center; margin-bottom: 30px; }
                .section { margin-bottom: 20px; }
                .vulnerability { margin: 10px 0; padding: 10px; border: 1px solid #ddd; }
                .high-severity { border-left: 5px solid #ff4444; }
                .low-severity { border-left: 5px solid #ffbb33; }
                table { width: 100%; border-collapse: collapse; }
                th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Network Security Scan Report</h1>
                <p>Generated on: ${new Date().toLocaleString()}</p>
            </div>`;

    hosts.forEach(host => {
        const ip = host.address?.find(addr => addr.$?.addrtype === "ipv4")?.$?.addr;
        if (!ip) return;

        html += `
            <div class="section">
                <h2>Host: ${ip}</h2>
                <table>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Vulnerability</th>
                        <th>Severity</th>
                    </tr>`;

        const ports = host.ports?.[0]?.port || [];
        ports.forEach(port => {
            const scripts = port.script || [];
            scripts.forEach(script => {
                const severity = script.$?.output?.includes("VULNERABLE") ? "High" : "Low";
                html += `
                    <tr class="${severity.toLowerCase()}-severity">
                        <td>${port.$?.portid}</td>
                        <td>${port.service?.[0]?.$?.name || 'Unknown'}</td>
                        <td>${script.$?.id}</td>
                        <td>${severity}</td>
                    </tr>`;
            });
        });

        html += `</table></div>`;
    });

    html += `
            <div class="section">
                <h3>Summary</h3>
                <p>Total hosts scanned: ${hosts.length}</p>
            </div>
        </body>
        </html>`;

    return html;
};

// Generate PDF Security Report
const generateSecurityReport = asyncHandler(async (req, res) => {
    const { ipRange } = req.params;
    let pdfPath;
    
    try {
        const scanResult = await runEnhancedVulnerabilityScan(ipRange);
        const browser = await puppeteer.launch({
            headless: 'new',
            args: ['--no-sandbox', '--disable-setuid-sandbox']
        });
        const page = await browser.newPage();

        // Generate HTML report
        const reportHtml = generateReportHtml(scanResult);
        await page.setContent(reportHtml);

        pdfPath = path.join(tempDir, `security_report_${Date.now()}.pdf`);
        await page.pdf({
            path: pdfPath,
            format: 'A4',
            margin: { top: '20px', right: '20px', bottom: '20px', left: '20px' }
        });

        await browser.close();

        // Read the PDF file
        const pdfBuffer = await fs.readFile(pdfPath);

        // Set headers and send the PDF
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=Security_Report_${ipRange.replace(/[\/\\]/g, '_')}.pdf`);
        res.send(pdfBuffer);

        // Clean up the temporary file
        await fs.unlink(pdfPath);

    } catch (error) {
        // Clean up the file if it exists and there was an error
        if (pdfPath) {
            try {
                await fs.unlink(pdfPath);
            } catch (unlinkError) {
                console.error('Error deleting temporary PDF:', unlinkError);
            }
        }
        throw new ApiError(500, `Failed to generate report: ${error.message}`);
    }
});

export const networkAdvancedController = {
    analyzeNetworkSecurity,
    checkIPReputation,
    checkDarkWebLeaks,
    scheduleNetworkScan,
    generateSecurityReport
}; 