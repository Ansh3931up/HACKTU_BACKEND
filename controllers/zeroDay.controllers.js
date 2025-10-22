import { exec } from 'child_process';
import { promisify } from 'util';
import os from 'os';
import axios from 'axios';
import { asyncHandler } from '../utils/asyncHandler.js';
import ApiError from '../utils/ApiError.js';
import ApiResponse from '../utils/ApiResponse.js';
import dns from 'dns';

const execAsync = promisify(exec);

class ZeroDayController {
    constructor() {
        this.scanResults = new Map();
        this.responseStorage = {
            vulnerabilityScans: null,
            systemPatches: null,
            networkActivity: null,
            malwareScans: null,
            systemLogs: null,
            lastUpdated: null
        };
        this.isScanning = false;
        this.startPeriodicScanning();
    }

    // Periodic scanning function
    startPeriodicScanning = () => {
        setInterval(async () => {
            try {
                await this.updateSystemStatus();
            } catch (error) {
                console.error('Periodic scanning failed:', error);
            }
        }, 300000); // Update every 5 minutes
    };

    // Update system status
    updateSystemStatus = async () => {
        const systemStats = {
            cpuLoad: os.loadavg(),
            totalMemory: os.totalmem(),
            freeMemory: os.freemem(),
            uptime: os.uptime(),
            platform: os.platform(),
            timestamp: new Date().toISOString()
        };
        this.responseStorage.systemStatus = systemStats;
        this.responseStorage.lastUpdated = new Date().toISOString();
    };

    // Get all security data
    getAllSecurityData = asyncHandler(async (req, res) => {
        try {
            const results = {
                timestamp: new Date().toISOString(),
                systemAnalysis: null,
                networkAnalysis: null,
                vulnerabilityAnalysis: null,
                riskAssessment: {
                    overall: 'low',
                    factors: [],
                    recommendations: []
                },
                status: {
                    isScanning: this.isScanning,
                    lastUpdated: this.responseStorage.lastUpdated,
                    scanDuration: null
                }
            };

            const scanStart = Date.now();

            // System Analysis
            try {
                const [systemInfo, patchStatus] = await Promise.all([
                    this.getSystemInfo(),
                    this.checkSystemPatches()
                ]);

                results.systemAnalysis = {
                    info: systemInfo,
                    patches: patchStatus,
                    processes: await this.getRunningProcesses(),
                    services: await this.getRunningServices()
                };
            } catch (error) {
                console.error('System analysis error:', error);
                results.systemAnalysis = { error: error.message };
            }

            // Network Analysis
            try {
                const [connections, ports] = await Promise.all([
                    this.getNetworkConnections(),
                    this.scanOpenPorts()
                ]);

                results.networkAnalysis = {
                    connections,
                    ports,
                    analysis: this.analyzeNetworkActivity(connections, ports)
                };
            } catch (error) {
                console.error('Network analysis error:', error);
                results.networkAnalysis = { error: error.message };
            }

            // Vulnerability Analysis
            try {
                const vulnerabilities = await this.scanVulnerabilities();
                results.vulnerabilityAnalysis = {
                    findings: vulnerabilities,
                    analysis: this.analyzeVulnerabilities(vulnerabilities)
                };
            } catch (error) {
                console.error('Vulnerability analysis error:', error);
                results.vulnerabilityAnalysis = { error: error.message };
            }

            // Calculate risk assessment
            results.riskAssessment = this.calculateOverallRisk(results);
            results.status.scanDuration = Date.now() - scanStart;

            // Update response storage
            this.responseStorage = {
                ...this.responseStorage,
                lastUpdated: results.timestamp,
                lastFullScan: results
            };

            return res.status(200).json(
                new ApiResponse(
                    200,
                    results,
                    "Security analysis completed successfully"
                )
            );
        } catch (error) {
            throw new ApiError(500, `Security analysis failed: ${error.message}`);
        }
    });

    // Add this method to your ZeroDayController class
    getAllZeroDayData = asyncHandler(async (req, res) => {
        try {
            const results = {
                timestamp: new Date().toISOString(),
                systemHealth: null,
                vulnerabilities: null,
                networkSecurity: null,
                malwareAnalysis: null,
                riskAssessment: {
                    overall: 'low',
                    factors: [],
                    recommendations: []
                },
                status: {
                    isScanning: this.isScanning,
                    lastUpdated: this.responseStorage.lastUpdated,
                    scanDuration: null
                }
            };

            const scanStart = Date.now();

            // System Health Check
            try {
                const [systemInfo, patchStatus, processes, services] = await Promise.all([
                    this.getSystemInfo(),
                    this.checkSystemPatches(),
                    this.getRunningProcesses(),
                    this.getRunningServices()
                ]);

                results.systemHealth = {
                    info: systemInfo,
                    patches: patchStatus,
                    processes,
                    services,
                    analysis: {
                        outdatedPatches: patchStatus.error ? true : false,
                        suspiciousProcesses: this.analyzeSuspiciousProcesses(processes),
                        criticalServices: this.analyzeServices(services)
                    }
                };
            } catch (error) {
                console.error('System health check error:', error);
                results.systemHealth = { error: error.message };
            }

            // Network Security Analysis
            try {
                const [connections, ports, firewallStatus] = await Promise.all([
                    this.getNetworkConnections(),
                    this.scanOpenPorts(),
                    this.checkFirewallStatus()
                ]);

                results.networkSecurity = {
                    connections,
                    ports,
                    firewall: firewallStatus,
                    analysis: this.analyzeNetworkActivity(connections, ports)
                };
            } catch (error) {
                console.error('Network security analysis error:', error);
                results.networkSecurity = { error: error.message };
            }

            // Vulnerability Assessment
            try {
                const vulnerabilities = await this.scanVulnerabilities();
                results.vulnerabilities = {
                    findings: vulnerabilities,
                    analysis: this.analyzeVulnerabilities(vulnerabilities)
                };
            } catch (error) {
                console.error('Vulnerability assessment error:', error);
                results.vulnerabilities = { error: error.message };
            }

            // Malware Analysis
            try {
                const [antivirusStatus, malwareScans] = await Promise.all([
                    this.checkAntivirusStatus(),
                    this.scanForMalware()
                ]);

                results.malwareAnalysis = {
                    antivirusStatus,
                    malwareScans,
                    analysis: this.analyzeMalwareThreats(malwareScans)
                };
            } catch (error) {
                console.error('Malware analysis error:', error);
                results.malwareAnalysis = { error: error.message };
            }

            // Calculate overall risk assessment
            results.riskAssessment = this.calculateOverallRisk(results);
            results.status.scanDuration = Date.now() - scanStart;

            // Update response storage
            this.responseStorage = {
                ...this.responseStorage,
                lastUpdated: results.timestamp,
                lastFullScan: results
            };

            return res.status(200).json(
                new ApiResponse(
                    200,
                    results,
                    "Zero-day vulnerability analysis completed successfully"
                )
            );
        } catch (error) {
            throw new ApiError(500, `Zero-day analysis failed: ${error.message}`);
        }
    });

    // Helper methods
    async getSystemInfo() {
        const { stdout: osInfo } = await execAsync('systeminfo');
        return {
            os: {
                platform: os.platform(),
                release: os.release(),
                type: os.type()
            },
            cpu: {
                model: os.cpus()[0].model,
                cores: os.cpus().length,
                load: os.loadavg()
            },
            memory: {
                total: os.totalmem(),
                free: os.freemem(),
                usage: ((os.totalmem() - os.freemem()) / os.totalmem() * 100).toFixed(2)
            },
            uptime: os.uptime(),
            systemDetails: this.parseSystemInfo(osInfo)
        };
    }

    async checkSystemPatches() {
        try {
            if (process.platform === 'win32') {
                const { stdout } = await execAsync('wmic qfe list brief');
                return this.parseUpdateHistory(stdout);
            } else {
                return { message: 'Patch checking is only available on Windows systems' };
            }
        } catch (error) {
            console.error('Patch check error:', error);
            return { error: 'Could not check system patches' };
        }
    }

    async getRunningProcesses() {
        try {
            const { stdout } = await execAsync('tasklist /fo csv /nh');
            return this.parseProcessList(stdout);
        } catch (error) {
            console.error('Process list error:', error);
            return [];
        }
    }

    async getRunningServices() {
        try {
            const { stdout } = await execAsync('net start');
            return stdout.split('\n')
                .filter(line => line.trim())
                .map(service => service.trim());
        } catch (error) {
            console.error('Service list error:', error);
            return [];
        }
    }

    async getNetworkConnections() {
        try {
            const { stdout } = await execAsync('netstat -n');
            return this.parseNetstatOutput(stdout);
        } catch (error) {
            console.error('Network connections error:', error);
            return [];
        }
    }

    async scanOpenPorts() {
        try {
            const { stdout } = await execAsync('netstat -an | findstr LISTENING');
            return this.parsePortScan(stdout);
        } catch (error) {
            console.error('Port scan error:', error);
            return [];
        }
    }

    async scanVulnerabilities() {
        const vulnerabilities = [];
        
        try {
            // Check Windows Defender status using PowerShell
            const { stdout: defenderStatus } = await execAsync('powershell Get-MpComputerStatus')
                .catch(() => ({ stdout: '' }));
            
            if (!defenderStatus.includes('AMServiceEnabled                : True')) {
                vulnerabilities.push({
                    type: 'antivirus',
                    severity: 'high',
                    description: 'Windows Defender service is not running'
                });
            }

            // Check firewall status
            const { stdout: firewallStatus } = await execAsync('netsh advfirewall show currentprofile')
                .catch(() => ({ stdout: '' }));
            
            if (!firewallStatus.includes('State                                 ON')) {
                vulnerabilities.push({
                    type: 'firewall',
                    severity: 'high',
                    description: 'Windows Firewall is disabled'
                });
            }

            // Check system updates
            const { stdout: updateStatus } = await execAsync('powershell Get-HotFix')
                .catch(() => ({ stdout: '' }));
            
            if (!updateStatus) {
                vulnerabilities.push({
                    type: 'updates',
                    severity: 'medium',
                    description: 'Unable to verify system updates'
                });
            }

            // Add basic system checks
            const systemChecks = [
                {
                    check: 'Memory Usage',
                    value: (os.totalmem() - os.freemem()) / os.totalmem() * 100,
                    threshold: 90,
                    severity: 'medium'
                },
                {
                    check: 'CPU Load',
                    value: os.loadavg()[0],
                    threshold: 80,
                    severity: 'medium'
                }
            ];

            systemChecks.forEach(check => {
                if (check.value > check.threshold) {
                    vulnerabilities.push({
                        type: 'system',
                        severity: check.severity,
                        description: `High ${check.check}: ${check.value.toFixed(2)}%`
                    });
                }
            });

            return vulnerabilities;
        } catch (error) {
            console.error('Vulnerability scan error:', error);
            return [{
                type: 'system',
                severity: 'medium',
                description: 'Could not complete vulnerability scan',
                error: error.message
            }];
        }
    }

    // Analysis methods
    parseSystemInfo(info) {
        const details = {};
        const lines = info.split('\n');
        let currentSection = '';

        lines.forEach(line => {
            if (line.trim()) {
                if (!line.includes(':')) {
                    currentSection = line.trim();
                    details[currentSection] = {};
                } else {
                    const [key, value] = line.split(':').map(item => item.trim());
                    if (currentSection) {
                        details[currentSection][key] = value;
                    } else {
                        details[key] = value;
                    }
                }
            }
        });

        return details;
    }

    parseUpdateHistory(history) {
        return history.split('\n')
            .slice(1) // Skip header
            .filter(line => line.trim())
            .map(line => {
                const parts = line.split(',');
                return {
                    updateId: parts[0],
                    installedOn: parts[1],
                    description: parts[2]
                };
            });
    }

    parseProcessList(list) {
        return list.split('\n')
            .filter(line => line.trim())
            .map(line => {
                const [name, pid, type, sessions, memory] = line.split(',');
                return { name, pid, type, sessions, memory };
            });
    }

    parseNetstatOutput(output) {
        return output.split('\n')
            .slice(4) // Skip headers
            .filter(line => line.trim())
            .map(line => {
                const parts = line.trim().split(/\s+/);
                return {
                    protocol: parts[0],
                    localAddress: parts[1],
                    foreignAddress: parts[2],
                    state: parts[3],
                    pid: parts[4]
                };
            });
    }

    parsePortScan(output) {
        const ports = new Set();
        output.split('\n').forEach(line => {
            const match = line.match(/:(\d+)/);
            if (match) {
                ports.add(parseInt(match[1]));
            }
        });
        return Array.from(ports);
    }

    analyzeNetworkActivity(connections, ports) {
        const analysis = {
            totalConnections: connections?.length || 0,
            uniquePorts: new Set(ports || []).size,
            states: {},
            suspiciousConnections: [],
            riskLevel: 'low',
            lastChecked: new Date().toISOString()
        };

        if (!connections || !ports) {
            analysis.riskLevel = 'unknown';
            return analysis;
        }

        // Analyze connections
        connections.forEach(conn => {
            if (conn && conn.state) {
                analysis.states[conn.state] = (analysis.states[conn.state] || 0) + 1;

                // Check for suspicious ports
                const suspiciousPorts = [4444, 5555, 666, 1337, 31337];
                const localPort = parseInt(conn.localAddress?.split(':')[1]);
                const foreignPort = parseInt(conn.foreignAddress?.split(':')[1]);

                if (suspiciousPorts.includes(localPort) || suspiciousPorts.includes(foreignPort)) {
                    analysis.suspiciousConnections.push(conn);
                    analysis.riskLevel = 'high';
                }
            }
        });

        return analysis;
    }

    analyzeVulnerabilities(vulnerabilities) {
        return {
            total: vulnerabilities.length,
            bySeverity: {
                high: vulnerabilities.filter(v => v.severity === 'high').length,
                medium: vulnerabilities.filter(v => v.severity === 'medium').length,
                low: vulnerabilities.filter(v => v.severity === 'low').length
            },
            criticalFindings: vulnerabilities.filter(v => v.severity === 'high')
        };
    }

    calculateOverallRisk(results) {
        const riskFactors = [];
        let riskLevel = 'low';

        // Check system patches
        if (results.systemAnalysis?.patches?.error) {
            riskFactors.push('Unable to verify system patches');
            riskLevel = 'medium';
        }

        // Check network activity
        if (results.networkAnalysis?.analysis?.suspiciousConnections.length > 0) {
            riskFactors.push('Suspicious network connections detected');
            riskLevel = 'high';
        }

        // Check vulnerabilities
        if (results.vulnerabilityAnalysis?.analysis?.bySeverity.high > 0) {
            riskFactors.push('Critical vulnerabilities detected');
            riskLevel = 'high';
        }

        return {
            level: riskLevel,
            factors: riskFactors,
            recommendations: this.generateRecommendations(riskFactors)
        };
    }

    generateRecommendations(riskFactors) {
        const recommendations = [];
        
        if (riskFactors.includes('Unable to verify system patches')) {
            recommendations.push('Run Windows Update and verify system patch status');
        }
        if (riskFactors.includes('Suspicious network connections detected')) {
            recommendations.push('Investigate suspicious network connections and block if necessary');
        }
        if (riskFactors.includes('Critical vulnerabilities detected')) {
            recommendations.push('Address critical security vulnerabilities immediately');
        }

        return recommendations;
    }

    // Add these methods to your ZeroDayController class

    getNetworkSecurity = asyncHandler(async (req, res) => {
        try {
            // Get network connections
            const connections = await this.getNetworkConnections().catch(() => []);
            
            // Get open ports
            const ports = await this.scanOpenPorts().catch(() => []);
            
            // Get firewall status
            const firewallStatus = await this.checkFirewallStatus().catch(() => ({
                enabled: false,
                profiles: {}
            }));

            const networkAnalysis = this.analyzeNetworkActivity(connections, ports);

            const response = {
                connections: connections || [],
                ports: ports || [],
                firewall: firewallStatus,
                analysis: networkAnalysis,
                lastChecked: new Date().toISOString()
            };

            return res.status(200).json(
                new ApiResponse(
                    200,
                    response,
                    "Network security analysis completed successfully"
                )
            );
        } catch (error) {
            console.error('Network security analysis error:', error);
            return res.status(500).json(
                new ApiResponse(
                    500,
                    {
                        error: error.message || "Network security analysis failed",
                        connections: [],
                        ports: [],
                        firewall: { enabled: false, profiles: {} },
                        analysis: {
                            totalConnections: 0,
                            uniquePorts: 0,
                            states: {},
                            suspiciousConnections: [],
                            riskLevel: 'unknown'
                        }
                    },
                    "Network security analysis failed"
                )
            );
        }
    });

    getVulnerabilities = asyncHandler(async (req, res) => {
        try {
            const vulnerabilities = await this.scanVulnerabilities();
            const analysis = this.analyzeVulnerabilities(vulnerabilities);

            return res.status(200).json(
                new ApiResponse(
                    200,
                    {
                        findings: vulnerabilities,
                        analysis
                    },
                    "Vulnerability scan completed successfully"
                )
            );
        } catch (error) {
            throw new ApiError(500, `Vulnerability scan failed: ${error.message}`);
        }
    });

    getMalwareAnalysis = asyncHandler(async (req, res) => {
        try {
            const [antivirusStatus, malwareScans] = await Promise.all([
                this.checkAntivirusStatus(),
                this.scanForMalware()
            ]);

            const analysis = {
                antivirusStatus,
                malwareScans,
                analysis: {
                    threatCount: malwareScans.findings?.length || 0,
                    riskLevel: malwareScans.findings?.length > 0 ? 'high' : 'low',
                    lastScanTime: malwareScans.timestamp,
                    status: malwareScans.status
                }
            };

            return res.status(200).json(
                new ApiResponse(
                    200,
                    analysis,
                    "Malware analysis completed successfully"
                )
            );
        } catch (error) {
            console.error('Malware analysis error:', error);
            return res.status(500).json(
                new ApiResponse(
                    500,
                    {
                        error: error.message,
                        antivirusStatus: { enabled: false, realTimeProtection: false },
                        malwareScans: { findings: [], status: 'error' },
                        analysis: { threatCount: 0, riskLevel: 'unknown' }
                    },
                    "Malware analysis failed"
                )
            );
        }
    });

    checkFirewallStatus = asyncHandler(async (req, res) => {
        try {
            const { stdout } = await execAsync('netsh advfirewall show allprofiles');
            const profiles = this.parseFirewallStatus(stdout);
            return {
                enabled: Object.values(profiles).some(profile => profile.enabled),
                profiles
            };
        } catch (error) {
            console.error('Firewall status error:', error);
            return {
                enabled: false,
                profiles: {
                    domain: { enabled: false },
                    private: { enabled: false },
                    public: { enabled: false }
                }
            };
        }
    });

    // Add these helper methods as well
    async checkAntivirusStatus() {
        try {
            if (process.platform === 'win32') {
                const { stdout } = await execAsync('powershell Get-MpComputerStatus');
                return this.parseDefenderStatus(stdout);
            } else {
                return { message: 'Antivirus status checking is only available on Windows systems' };
            }
        } catch (error) {
            console.error('Antivirus status check error:', error);
            return { error: 'Could not check antivirus status' };
        }
    }

    async scanForMalware() {
        try {
            // First check if a scan is already running
            const { stdout: scanStatus } = await execAsync('powershell -Command "Get-MpComputerStatus | Select-Object QuickScanInProgress"')
                .catch(() => ({ stdout: 'False' }));

            if (scanStatus.includes('True')) {
                return {
                    scanCompleted: false,
                    status: 'scan_in_progress',
                    findings: [],
                    timestamp: new Date().toISOString(),
                    message: 'A scan is already in progress'
                };
            }

            // Try to get last scan results instead of starting a new scan
            const { stdout: lastScan } = await execAsync('powershell -Command "Get-MpThreatDetection | Select-Object ThreatID, InitialDetectionTime, ProcessName"')
                .catch(() => ({ stdout: '' }));

            // Check antivirus status
            const { stdout: defenderStatus } = await execAsync('powershell -Command "Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled, AntivirusEnabled"')
                .catch(() => ({ stdout: '' }));

            return {
                scanCompleted: true,
                status: 'completed',
                findings: this.parseMalwareResults(lastScan),
                antivirusStatus: this.parseDefenderStatus(defenderStatus),
                timestamp: new Date().toISOString(),
                message: 'Retrieved last scan results'
            };
        } catch (error) {
            console.error('Malware scan error:', error);
            return {
                scanCompleted: false,
                status: 'error',
                findings: [],
                timestamp: new Date().toISOString(),
                message: 'Could not complete malware scan',
                error: error.message
            };
        }
    }

    parseMalwareResults(output) {
        if (!output) return [];
        
        return output.split('\n')
            .filter(line => line.trim())
            .map(line => {
                const [threatId, detectionTime, processName] = line.split(',').map(s => s.trim());
                return {
                    threatId,
                    detectionTime,
                    processName,
                    severity: 'unknown'
                };
            });
    }

    parseDefenderStatus(output) {
        const status = {
            enabled: false,
            realTimeProtection: false,
            antivirusEnabled: false
        };

        if (output) {
            status.enabled = output.includes('AMServiceEnabled                : True');
            status.realTimeProtection = output.includes('RealTimeProtectionEnabled        : True');
            status.antivirusEnabled = output.includes('AntivirusEnabled               : True');
        }

        return status;
    }

    analyzeMalwareThreats(scanResults) {
        return {
            threatCount: scanResults.findings?.length || 0,
            lastScan: scanResults.timestamp,
            riskLevel: scanResults.findings?.length > 0 ? 'high' : 'low'
        };
    }

    parseFirewallStatus(output) {
        const profiles = {};
        let currentProfile = '';

        output.split('\n').forEach(line => {
            const profileMatch = line.match(/^(Domain|Private|Public) Profile Settings:/);
            if (profileMatch) {
                currentProfile = profileMatch[1].toLowerCase();
                profiles[currentProfile] = { enabled: false };
            }
            if (currentProfile && line.includes('State')) {
                profiles[currentProfile].enabled = line.includes('ON');
            }
        });

        return profiles;
    }

    analyzeSuspiciousProcesses(processes) {
        const suspiciousProcesses = processes.filter(process => {
            // Add your suspicious process detection logic here
            const suspiciousNames = ['cmd.exe', 'powershell.exe', 'psexec.exe'];
            return suspiciousNames.includes(process.name.toLowerCase());
        });

        return {
            total: suspiciousProcesses.length,
            processes: suspiciousProcesses,
            riskLevel: suspiciousProcesses.length > 0 ? 'medium' : 'low'
        };
    }

    analyzeServices(services) {
        const criticalServices = ['Windows Defender', 'Windows Firewall'];
        const missingCritical = criticalServices.filter(service => 
            !services.some(s => s.toLowerCase().includes(service.toLowerCase()))
        );

        return {
            total: services.length,
            missingCritical,
            riskLevel: missingCritical.length > 0 ? 'high' : 'low'
        };
    }

    async getDomainAge(domain) {
        try {
            // Use DNS lookup instead of whois
            const [aRecords, nsRecords, mxRecords, txtRecords] = await Promise.all([
                dns.promises.resolve(domain, 'A').catch(() => []),
                dns.promises.resolve(domain, 'NS').catch(() => []),
                dns.promises.resolve(domain, 'MX').catch(() => []),
                dns.promises.resolve(domain, 'TXT').catch(() => [])
            ]);

            return {
                dnsInfo: {
                    aRecords,
                    nsRecords,
                    mxRecords,
                    txtRecords
                },
                lastChecked: new Date().toISOString(),
                status: 'active',
                note: 'Age information not available via DNS lookup'
            };
        } catch (error) {
            console.error('Domain lookup error:', error);
            return {
                error: 'Could not perform DNS lookup',
                lastChecked: new Date().toISOString(),
                status: 'unknown'
            };
        }
    }

    async getRegistrarInfo(domain) {
        try {
            // Use DNS lookup instead of whois
            const [aRecords, nsRecords, mxRecords, txtRecords, soaRecord] = await Promise.all([
                dns.promises.resolve(domain, 'A').catch(() => []),
                dns.promises.resolve(domain, 'NS').catch(() => []),
                dns.promises.resolve(domain, 'MX').catch(() => []),
                dns.promises.resolve(domain, 'TXT').catch(() => []),
                dns.promises.resolve(domain, 'SOA').catch(() => null)
            ]);

            return {
                domain,
                dnsRecords: {
                    a: aRecords,
                    ns: nsRecords,
                    mx: mxRecords,
                    txt: txtRecords,
                    soa: soaRecord
                },
                nameservers: nsRecords,
                mailServers: mxRecords.map(mx => ({
                    exchange: mx.exchange,
                    priority: mx.priority
                })),
                lastChecked: new Date().toISOString(),
                status: 'active'
            };
        } catch (error) {
            console.error('DNS lookup error:', error);
            return {
                domain,
                error: 'Could not fetch DNS information',
                lastChecked: new Date().toISOString(),
                status: 'unknown'
            };
        }
    }

    // Add a helper method for analyzing DNS records
    analyzeDNSRecords(records) {
        return {
            hasValidRecords: records.a?.length > 0 || false,
            totalNameservers: records.ns?.length || 0,
            totalMailServers: records.mx?.length || 0,
            hasTXT: records.txt?.length > 0 || false,
            hasSOA: records.soa !== null,
            riskLevel: this.calculateDNSRiskLevel(records),
            lastChecked: new Date().toISOString()
        };
    }

    calculateDNSRiskLevel(records) {
        if (!records.a?.length) return 'high';
        if (!records.ns?.length) return 'high';
        if (!records.soa) return 'medium';
        return 'low';
    }
}

export const zeroDayController = new ZeroDayController();
