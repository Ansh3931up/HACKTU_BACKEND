import { exec } from 'child_process';
import { parseString } from 'xml2js';
import fs from 'fs/promises';
import { promisify } from 'util';
import os from 'os';
import ApiError from '../utils/ApiError.js';
import ApiResponse from '../utils/ApiResponse.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import path from 'path';
import { initializeModel,analyzeNetwork } from '../LLMmodels/generateRecommendations.js';




const execPromise = promisify(exec);

// State management
let scanResults = new Map();
let trafficData = {
    inbound: [0, 0, 0, 0, 0, 0], // 6 data points for the chart
    outbound: [0, 0, 0, 0, 0, 0]
};

// Helper functions
const updateTrafficData = () => {
    trafficData.inbound.shift();
    trafficData.outbound.shift();
    trafficData.inbound.push(Math.floor(Math.random() * 1000));
    trafficData.outbound.push(Math.floor(Math.random() * 1000));
};

// Start monitoring on module load
setInterval(updateTrafficData, 5000);

const runNmapScan = async (target) => {
    const outputFile = `scan_${Date.now()}.xml`;
    const command = `nmap -sS -sV -O -T4 ${target} -oX ${outputFile}`;
    
    try {
        console.log(`Executing nmap scan: ${command}`);
        await execPromise(command);
        const xmlData = await fs.readFile(outputFile, 'utf8');
        await fs.unlink(outputFile);
        
        return new Promise((resolve, reject) => {
            parseString(xmlData, (err, result) => {
                if (err) reject(err);
                else resolve(result);
            });
        });
    } catch (error) {
        console.error('Nmap scan error:', error);
        throw new ApiError(500, `Nmap scan failed: ${error.message}`);
    }
};

const processHostData = (host) => {
    try {
        const address = host.address?.find(addr => addr.$?.addrtype === 'ipv4');
        const hostname = host.hostnames?.[0]?.hostname?.[0]?.$?.name || 'Unknown';
        const ip = address?.$?.addr;
        const status = host.status?.[0]?.$?.state;
        
        const ports = host.ports?.[0]?.port?.map(port => ({
            portId: port.$?.portid,
            state: port.state?.[0]?.$?.state,
            service: port.service?.[0]?.$?.name,
            version: port.service?.[0]?.$?.version
        })) || [];

        const osInfo = host.os?.[0]?.osmatch?.[0] || {};
        const os = osInfo.$?.name || 'Unknown';

        return {
            name: hostname,
            ip,
            status: status === 'up' ? 'Online' : 'Offline',
            lastSeen: new Date().toISOString(),
            ports: ports.filter(port => port.state === 'open')
                .map(port => `${port.portId}/${port.service}`),
            os
        };
    } catch (error) {
        console.error('Error processing host:', error);
        return {
            name: 'Error processing host',
            ip: 'Unknown',
            status: 'Error',
            lastSeen: new Date().toISOString(),
            ports: [],
            os: 'Unknown'
        };
    }
};

// Main controller functions
const scanNetwork = asyncHandler(async (req, res) => {
    const { ipRange } = req.params;
    
    if (!ipRange) {
        throw new ApiError(400, "IP range is required");
    }

    try {
        const nmapResult = await runNmapScan(ipRange);
        const hosts = nmapResult.nmaprun?.host || [];
        const devices = hosts.map(processHostData)
                           .filter(host => host.status === 'Online');

        const response = {
            devices,
            networkData: {
                trafficData
            },
            summary: {
                totalDevices: devices.length,
                totalPorts: devices.reduce((sum, device) => sum + (device.ports?.length || 0), 0),
                lastScan: new Date().toISOString()
            }
        };

        scanResults.set(ipRange, response);

        return res.status(200).json(
            new ApiResponse(200, response, "Network scan completed successfully")
        );

    } catch (error) {
        console.error('Scan error:', error);
        throw new ApiError(500, `Network scan failed: ${error.message}`);
    }
});

const getTrafficAnalysis = asyncHandler(async (req, res) => {
    return res.status(200).json(
        new ApiResponse(200, { networkData: { trafficData } }, "Traffic analysis retrieved successfully")
    );
});

const runVulnerabilityScan = async (target) => {
    try {
        const tempDir = path.join(process.cwd(), 'temp');
        await fs.mkdir(tempDir, { recursive: true });

        const outputFile = path.join(tempDir, `vuln_scan_${Date.now()}.xml`);
        // Using NSE scripts for vulnerability detection
        const nmapCommand = `nmap -sV --script vuln ${target} -oX "${outputFile}"`;

        console.log('Executing vulnerability scan:', nmapCommand);
        await execPromise(nmapCommand);

        const xmlData = await fs.readFile(outputFile, 'utf8');

        // Clean up
        try {
            await fs.unlink(outputFile);
        } catch (error) {
            console.warn('Failed to delete temp file:', error);
        }

        return new Promise((resolve, reject) => {
            parseString(xmlData, (err, result) => {
                if (err) reject(err);
                else resolve(result);
            });
        });
    } catch (error) {
        console.error('Vulnerability scan error:', error);
        throw new Error(`Vulnerability scan failed: ${error.message}`);
    }
};

const analyzeSecurityResults = (scanResult) => {
    const vulnerabilities = [];
    const hosts = scanResult.nmaprun?.host || [];

    hosts.forEach(host => {
        const address = host.address?.find(addr => addr.$?.addrtype === 'ipv4')?.$?.addr;
        const ports = host.ports?.[0]?.port || [];

        ports.forEach(port => {
            const portId = port.$?.portid;
            const service = port.service?.[0]?.$?.name;
            const scripts = port.script || [];

            scripts.forEach(script => {
                const scriptData = script.$;
                if (scriptData) {
                    const vulnData = {
                        host: address,
                        port: portId,
                        service: service,
                        vulnerability: scriptData.id,
                        description: scriptData.output,
                        severity: determineSeverity(scriptData.output),
                        cve: extractCVEs(scriptData.output)
                    };
                    vulnerabilities.push(vulnData);
                }
            });
        });
    });

    return {
        vulnerabilities,
        summary: {
            totalVulnerabilities: vulnerabilities.length,
            criticalCount: vulnerabilities.filter(v => v.severity === 'Critical').length,
            highCount: vulnerabilities.filter(v => v.severity === 'High').length,
            mediumCount: vulnerabilities.filter(v => v.severity === 'Medium').length,
            lowCount: vulnerabilities.filter(v => v.severity === 'Low').length
        }
    };
};

const determineSeverity = (output) => {
    const lowercaseOutput = output.toLowerCase();
    if (lowercaseOutput.includes('critical')) return 'Critical';
    if (lowercaseOutput.includes('high')) return 'High';
    if (lowercaseOutput.includes('medium')) return 'Medium';
    if (lowercaseOutput.includes('low')) return 'Low';
    return 'Info';
};

const extractCVEs = (output) => {
    const cveRegex = /CVE-\d{4}-\d{4,7}/g;
    return output.match(cveRegex) || [];
};

const analyzeNetworkSecurity = asyncHandler(async (req, res) => {
    const { ipRange } = req.params;
    
    if (!ipRange) {
        throw new ApiError(400, "IP range is required");
    }

    try {
        console.log('Starting vulnerability scan for:', ipRange);
        const scanResult = await runVulnerabilityScan(ipRange);
        const analysis = analyzeSecurityResults(scanResult);

        // Add recommendations based on findings
        const recommendations = await generateRecommendations(analysis.vulnerabilities);

        const response = {
            ...analysis,
            recommendations,
            timestamp: new Date().toISOString()
        };

        return res.status(200).json(
            new ApiResponse(200, response, "Security analysis completed successfully")
        );

    } catch (error) {
        console.error('Security analysis error:', error);
        throw new ApiError(500, `Security analysis failed: ${error.message}`);
    }
});

const generateRecommendations = async(vulnerabilities) => {
    const model = initializeModel();
    let recommendations = [];

    // Group vulnerabilities by service
    const serviceVulns = vulnerabilities.reduce((acc, vuln) => {
        if (!acc[vuln.service]) {
            acc[vuln.service] = [];
        }
        acc[vuln.service].push(vuln);
        return acc;
    }, {});

    try {
        // Process service-specific vulnerabilities
        const servicePromises = Object.entries(serviceVulns).map(async ([service, vulns]) => {
            let serviceRecs = [];
            
            // Handle critical vulnerabilities
            const criticalVulns = vulns.filter(v => v.severity === 'Critical');
            if (criticalVulns.length > 0) {
                const {success, data} = await analyzeNetwork(criticalVulns);
                if (success && data) {
                    serviceRecs.push(data);
                }
            }

            // Handle high vulnerabilities
            const highVulns = vulns.filter(v => v.severity === 'High');
            if (highVulns.length > 0) {
                const {success, data} = await analyzeNetwork(highVulns);
                if (success && data) {
                    serviceRecs.push(data);
                }
            }

            return serviceRecs;
        });

        // Wait for all service-specific recommendations
        const serviceResults = await Promise.all(servicePromises);
        recommendations = serviceResults.flat();

        // Add general recommendations for all vulnerabilities
        if (vulnerabilities.length > 0) {
            const {success, data} = await analyzeNetwork(vulnerabilities);
            if (success && data) {
                recommendations.push(data);
            }
        }

        // Flatten and deduplicate recommendations
        recommendations = recommendations.flat().filter(Boolean);
        recommendations = Array.from(new Set(recommendations.map(JSON.stringify)))
            .map(str => JSON.parse(str));

        console.log("Final Recommendations:", recommendations);
        return recommendations;

    } catch (error) {
        console.error("Error generating recommendations:", error);
        return [];
    }
};

// Export all functions
export const networkController = {
    scanNetwork,
    getTrafficAnalysis,
    analyzeNetworkSecurity,
    // ... export other functions ...
};