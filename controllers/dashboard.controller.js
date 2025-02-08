import { asyncHandler } from '../utils/asyncHandler.js';
import ApiResponse from '../utils/ApiResponse.js';
import ApiError from '../utils/ApiError.js';
import os from 'os';
import si from 'systeminformation';
import FastSpeedtest from 'fast-speedtest-api';

// Simulated data storage (replace with actual database in production)
let networkHealthData = {
    uptime: 99.9,
    latency: 15,
    packetLoss: 0.1,
    bandwidthUsage: 65,
    timestamp: new Date().toISOString()
};

let threatData = {
    lowRisk: 85,
    mediumRisk: 12,
    highRisk: 3,
};

let alertsData = [
    {
        id: 1,
        type: "Unauthorized Access Attempt",
        severity: "High",
        source: "192.168.1.100",
        timestamp: new Date().toISOString()
    },
    {
        id: 2,
        type: "Unusual Network Traffic",
        severity: "Medium",
        source: "192.168.1.150",
        timestamp: new Date().toISOString()
    }
];

let securityScoreData = {
    secure: 85,
    atRisk: 15
};

// Initialize speed test
const speedtest = new FastSpeedtest({
    token: 'YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm', // This is a default token, you might want to get your own from Fast.com
    verbose: false,
    timeout: 10000,
    https: true,
    urlCount: 5,
    bufferSize: 8,
    unit: FastSpeedtest.UNITS.Mbps
});

// Update simulated data periodically
const updateSimulatedData = () => {
    networkHealthData = {
        ...networkHealthData,
        latency: Math.floor(Math.random() * 30) + 5,
        bandwidthUsage: Math.floor(Math.random() * 40) + 40,
        timestamp: new Date().toISOString()
    };
    
    threatData = {
        lowRisk: Math.floor(Math.random() * 20) + 70,
        mediumRisk: Math.floor(Math.random() * 15) + 5,
        highRisk: Math.floor(Math.random() * 5) + 1
    };
};

// Update data every 30 seconds
setInterval(updateSimulatedData, 30000);

// Replace the dummy data with real monitoring functions
const getRealTimeNetworkHealth = async () => {
    try {
        // Get all metrics in parallel for better performance
        const [
            networkStats,
            latencyCheck,
            networkInterfaces,
            networkConnections
        ] = await Promise.all([
            si.networkStats(),
            si.inetLatency(),
            si.networkInterfaces(),
            si.networkConnections()
        ]);

        // Get system uptime
        const uptimeInDays = os.uptime() / (60 * 60 * 24);
        
        // Get main interface
        const mainInterface = networkStats[0];
        const primaryInterface = networkInterfaces.find(iface => 
            iface.default && !iface.internal
        );

        // Measure speed (this is optional as it might take a few seconds)
        let speedTestResult = null;
        try {
            speedTestResult = await speedtest.getSpeed();
        } catch (speedError) {
            console.warn('Speed test failed:', speedError);
        }

        // Calculate metrics
        const activeConnections = networkConnections.filter(conn => 
            conn.state === 'ESTABLISHED'
        ).length;

        const networkHealth = {
            uptime: {
                days: uptimeInDays.toFixed(1),
                percentage: ((uptimeInDays / 30) * 100).toFixed(1),
                lastReboot: new Date(Date.now() - (os.uptime() * 1000)).toISOString()
            },
            latency: {
                current: latencyCheck || 0,
                min: Math.max(0, latencyCheck - 10) || 0,
                max: latencyCheck + 15 || 30,
                average: latencyCheck || 0
            },
            network: {
                bytesReceived: mainInterface?.rx_bytes || 0,
                bytesSent: mainInterface?.tx_bytes || 0,
                packetsReceived: mainInterface?.rx_packets || 0,
                packetsSent: mainInterface?.tx_packets || 0,
                errors: (mainInterface?.rx_errors || 0) + (mainInterface?.tx_errors || 0),
                dropped: (mainInterface?.rx_dropped || 0) + (mainInterface?.tx_dropped || 0)
            },
            speed: {
                download: speedTestResult || 0, // in Mbps
                interface: primaryInterface?.speed || 0,
                duplex: primaryInterface?.duplex || 'unknown'
            },
            connections: {
                active: activeConnections,
                total: networkConnections.length
            },
            interface: {
                name: primaryInterface?.iface || 'unknown',
                ip: primaryInterface?.ip4 || 'unknown',
                mac: primaryInterface?.mac || 'unknown',
                type: primaryInterface?.type || 'unknown',
                mtu: primaryInterface?.mtu || 0
            },
            status: {
                isOnline: latencyCheck !== undefined && latencyCheck < 1000,
                health: calculateHealthScore({
                    latency: latencyCheck,
                    errors: mainInterface?.rx_errors + mainInterface?.tx_errors,
                    dropped: mainInterface?.rx_dropped + mainInterface?.tx_dropped
                }),
                lastChecked: new Date().toISOString()
            }
        };

        return networkHealth;

    } catch (error) {
        console.error('Network monitoring error:', error);
        throw error;
    }
};

const calculateHealthScore = ({ latency, errors = 0, dropped = 0 }) => {
    let score = 100;
    
    // Reduce score based on latency
    if (latency > 100) score -= 20;
    else if (latency > 50) score -= 10;
    else if (latency > 20) score -= 5;

    // Reduce score based on errors
    if (errors > 0) score -= Math.min(20, errors);

    // Reduce score based on dropped packets
    if (dropped > 0) score -= Math.min(20, dropped);

    return {
        score: Math.max(0, score),
        label: score > 90 ? 'Excellent' :
               score > 80 ? 'Good' :
               score > 60 ? 'Fair' :
               'Poor'
    };
};

// Real-time security monitoring
const getRealTimeThreats = async () => {
    try {
        // Get system and network information with more detailed stats
        const [
            processes,
            networkStats,
            networkInterfaces,
            wifiConnections
        ] = await Promise.all([
            si.processes(),
            si.networkStats(),
            si.networkInterfaces(),
            si.wifiNetworks().catch(err => {
                console.warn('WiFi detection error:', err);
                return [];
            })
        ]);

        // Perform latency check with error handling and timeout
        let latencyCheck;
        try {
            latencyCheck = await Promise.race([
                si.inetLatency('8.8.8.8'), // Use Google's DNS instead
                new Promise((_, reject) => 
                    setTimeout(() => reject(new Error('Latency check timeout')), 5000)
                )
            ]);
        } catch (latencyError) {
            console.warn('Latency check error:', latencyError);
            latencyCheck = 0;
        }

        // Get Bluetooth devices with error handling
        let bluetoothDevices = [];
        try {
            bluetoothDevices = await si.bluetoothDevices();
        } catch (btError) {
            console.warn('Bluetooth detection error:', btError);
            bluetoothDevices = networkInterfaces
                .filter(iface => 
                    iface.type === 'bluetooth' || 
                    iface.iface.toLowerCase().includes('bt') ||
                    iface.iface.toLowerCase().includes('bluetooth')
                )
                .map(iface => ({
                    name: iface.iface,
                    address: iface.mac,
                    connected: iface.operstate === 'up',
                    paired: true
                }));
        }

        // Initialize threats object
        const threats = {
            lowRisk: 0,
            mediumRisk: 0,
            highRisk: 0,
            details: {
                connections: [],
                processes: [],
                wireless: []
            }
        };

        // Analyze active network interfaces
        const activeInterfaces = networkInterfaces.filter(iface => 
            iface.operstate === 'up' && !iface.internal
        );

        // Log network interfaces for debugging
        console.log('Network Interfaces:', networkInterfaces);
        console.log('Active Interfaces:', activeInterfaces);

        // Count different types of interfaces
        const ethernetInterfaces = activeInterfaces.filter(iface => 
            iface.type === 'wired' || 
            iface.iface.toLowerCase().includes('ethernet') ||
            iface.iface.toLowerCase().includes('eth')
        ).length;

        const wifiInterfaces = activeInterfaces.filter(iface =>
            iface.type === 'wireless' ||
            iface.iface.toLowerCase().includes('wlan') ||
            iface.iface.toLowerCase().includes('wifi')
        ).length;

        // Analyze WiFi connections if available
        if (wifiConnections && wifiConnections.length > 0) {
            wifiConnections.forEach(wifi => {
                const risk = assessWifiSecurity(wifi);
                threats[`${risk}Risk`]++;
                threats.details.wireless.push({
                    type: 'WiFi',
                    name: wifi.ssid || 'Unknown Network',
                    signal: wifi.signalLevel,
                    security: wifi.security,
                    risk: risk
                });
            });
        }

        // Analyze Bluetooth connections
        bluetoothDevices.forEach(device => {
            const risk = assessBluetoothSecurity(device);
            threats[`${risk}Risk`]++;
            threats.details.wireless.push({
                type: 'Bluetooth',
                name: device.name || 'Unknown Device',
                address: device.address,
                connected: device.connected || true,
                risk: risk
            });
        });

        // Analyze network traffic
        networkStats.forEach(stat => {
            if (stat.rx_errors > 0 || stat.tx_errors > 0) {
                const risk = assessNetworkRisk(stat);
                threats[`${risk}Risk`]++;
                threats.details.connections.push({
                    interface: stat.iface,
                    errors: stat.rx_errors + stat.tx_errors,
                    dropped: stat.rx_dropped + stat.tx_dropped,
                    traffic: {
                        received: stat.rx_sec,
                        sent: stat.tx_sec
                    },
                    risk: risk
                });
            }
        });

        // Analyze processes
        if (processes && processes.list) {
            const suspiciousProcesses = processes.list.filter(proc => {
                return (
                    proc.cpu > 90 || 
                    proc.memRss > (os.totalmem() * 0.5) || 
                    isKnownMaliciousProcess(proc.name)
                );
            });

            suspiciousProcesses.forEach(proc => {
                const risk = assessProcessRisk(proc);
                threats[`${risk}Risk`]++;
                threats.details.processes.push({
                    name: proc.name,
                    cpu: proc.cpu,
                    memory: proc.memRss,
                    risk: risk
                });
            });
        }

        return {
            summary: {
                lowRisk: threats.lowRisk || 0,
                mediumRisk: threats.mediumRisk || 0,
                highRisk: threats.highRisk || 0,
                total: (threats.lowRisk + threats.mediumRisk + threats.highRisk) || 0
            },
            details: threats.details,
            connections: {
                ethernet: ethernetInterfaces,
                wifi: Math.max(wifiInterfaces, wifiConnections?.length || 0),
                bluetooth: bluetoothDevices.length || 0
            },
            networkInterfaces: activeInterfaces.map(iface => ({
                name: iface.iface,
                type: iface.type,
                state: iface.operstate,
                speed: iface.speed,
                ip: iface.ip4 || iface.ip6,
                mac: iface.mac
            })),
            timestamp: new Date().toISOString()
        };

    } catch (error) {
        console.error('Threat monitoring error:', error);
        // Return a default response instead of throwing
        return {
            summary: { lowRisk: 0, mediumRisk: 0, highRisk: 0, total: 0 },
            details: { connections: [], processes: [], wireless: [] },
            connections: { ethernet: 0, wifi: 0, bluetooth: 0 },
            networkInterfaces: [],
            timestamp: new Date().toISOString()
        };
    }
};

// New helper functions for wireless security assessment
const assessWifiSecurity = (wifi) => {
    if (!wifi.security || wifi.security === 'none') {
        return 'high';
    }
    if (wifi.security === 'wep' || wifi.signalLevel < 40) {
        return 'medium';
    }
    return 'low';
};

const assessBluetoothSecurity = (device) => {
    if (!device.paired && device.connected) {
        return 'high';
    }
    if (device.connected && !device.trusted) {
        return 'medium';
    }
    return 'low';
};

const assessNetworkRisk = (stat) => {
    const errorRate = (stat.rx_errors + stat.tx_errors) / 
                     (stat.rx_packets + stat.tx_packets);
    
    if (errorRate > 0.01) return 'high';
    if (errorRate > 0.001) return 'medium';
    return 'low';
};

// Existing helper functions remain the same
const assessProcessRisk = (process) => {
    if (!process) return 'low';
    
    if (isKnownMaliciousProcess(process.name)) {
        return 'high';
    }
    if (process.cpu > 90) {
        return 'medium';
    }
    if (process.memRss > (os.totalmem() * 0.5)) {
        return 'medium';
    }
    return 'low';
};

const isKnownMaliciousProcess = (processName) => {
    if (!processName) return false;
    
    const maliciousProcesses = ['malware', 'cryptominer', 'suspicious'];
    return maliciousProcesses.some(name => 
        processName.toLowerCase().includes(name)
    );
};

// Real-time alerts monitoring
const getRealTimeAlerts = async () => {
    try {
        // Integrate with your logging system (e.g., ELK Stack, Splunk)
        // or security tools (SIEM, IDS/IPS)
        const alerts = await fetchSecurityAlerts();
        return alerts.map(alert => ({
            id: alert.id,
            type: alert.eventType,
            severity: alert.severity,
            source: alert.sourceIP,
            timestamp: alert.timestamp
        }));
    } catch (error) {
        console.error('Alerts monitoring error:', error);
        throw error;
    }
};

// Update the controller endpoints
const getNetworkHealth = asyncHandler(async (req, res) => {
    try {
        const networkData = await getRealTimeNetworkHealth();
        return res.status(200).json(
            new ApiResponse(200, networkData, "Network health data retrieved successfully")
        );
    } catch (error) {
        throw new ApiError(500, "Failed to fetch network health data");
    }
});

const getThreats = asyncHandler(async (req, res) => {
    try {
        const threatData = await getRealTimeThreats();
        return res.status(200).json(
            new ApiResponse(200, threatData, "Threat data retrieved successfully")
        );
    } catch (error) {
        console.error('Controller error:', error);
        throw new ApiError(500, "Failed to fetch threat data");
    }
});

const getAlerts = asyncHandler(async (req, res) => {
    try {
        return res.status(200).json(
            new ApiResponse(200, alertsData, "Alerts retrieved successfully")
        );
    } catch (error) {
        throw new ApiError(500, "Failed to fetch alerts");
    }
});

const getSecurityScore = asyncHandler(async (req, res) => {
    try {
        // Gather system security metrics
        const [
            processes,
            networkStats,
            networkInterfaces,
            fsSize,
            services,
            firewallRules
        ] = await Promise.all([
            si.processes(),
            si.networkStats(),
            si.networkInterfaces(),
            si.fsSize(),
            si.services('*'),
            si.networkConnections()
        ]);

        // Initialize security metrics
        const securityMetrics = {
            system: { score: 0, checks: 0 },
            network: { score: 0, checks: 0 },
            storage: { score: 0, checks: 0 }
        };

        // 1. System Security Checks
        if (processes && processes.list) {
            securityMetrics.system.checks++;
            const suspiciousProcesses = processes.list.filter(proc => 
                isKnownMaliciousProcess(proc.name) || proc.cpu > 90
            ).length;
            securityMetrics.system.score += calculateProcessScore(suspiciousProcesses, processes.all);
        }

        // 2. Network Security Checks
        if (networkStats && networkStats.length > 0) {
            securityMetrics.network.checks++;
            const networkErrors = networkStats.reduce((total, stat) => 
                total + stat.rx_errors + stat.tx_errors, 0
            );
            securityMetrics.network.score += calculateNetworkScore(networkErrors);
        }

        // Check open ports and connections
        if (firewallRules && firewallRules.length > 0) {
            securityMetrics.network.checks++;
            const openPorts = firewallRules.filter(conn => 
                conn.state === 'LISTEN'
            ).length;
            securityMetrics.network.score += calculatePortScore(openPorts);
        }

        // 3. Storage Security Checks
        if (fsSize && fsSize.length > 0) {
            securityMetrics.storage.checks++;
            const criticalSpace = fsSize.some(fs => 
                fs.use > 90
            );
            securityMetrics.storage.score += criticalSpace ? 50 : 100;
        }

        // Calculate final scores
        const calculateFinalScore = (metric) => 
            metric.checks > 0 ? Math.round(metric.score / metric.checks) : 0;

        const systemScore = calculateFinalScore(securityMetrics.system);
        const networkScore = calculateFinalScore(securityMetrics.network);
        const storageScore = calculateFinalScore(securityMetrics.storage);

        // Calculate overall security score
        const overallScore = Math.round(
            (systemScore + networkScore + storageScore) / 3
        );

        const securityData = {
            score: overallScore,
            secure: overallScore,
            atRisk: 100 - overallScore,
            details: {
                system: {
                    score: systemScore,
                    status: getScoreStatus(systemScore),
                    issues: processes?.list.filter(proc => 
                        isKnownMaliciousProcess(proc.name)
                    ).length || 0
                },
                network: {
                    score: networkScore,
                    status: getScoreStatus(networkScore),
                    openPorts: firewallRules?.filter(conn => 
                        conn.state === 'LISTEN'
                    ).length || 0,
                    activeConnections: firewallRules?.filter(conn => 
                        conn.state === 'ESTABLISHED'
                    ).length || 0
                },
                storage: {
                    score: storageScore,
                    status: getScoreStatus(storageScore),
                    criticalDisks: fsSize?.filter(fs => 
                        fs.use > 90
                    ).length || 0
                }
            },
            recommendations: generateSecurityRecommendations({
                systemScore,
                networkScore,
                storageScore,
                processes,
                networkStats,
                fsSize
            }),
            timestamp: new Date().toISOString()
        };

        return res.status(200).json(
            new ApiResponse(200, securityData, "Security score retrieved successfully")
        );
    } catch (error) {
        console.error('Security score error:', error);
        throw new ApiError(500, "Failed to fetch security score");
    }
});

// Helper functions for security score calculation
const calculateProcessScore = (suspicious, total) => {
    if (total === 0) return 100;
    const ratio = suspicious / total;
    return Math.max(0, Math.round(100 - (ratio * 1000)));
};

const calculateNetworkScore = (errors) => {
    if (errors === 0) return 100;
    return Math.max(0, Math.round(100 - (errors * 5)));
};

const calculatePortScore = (openPorts) => {
    if (openPorts === 0) return 100;
    return Math.max(0, Math.round(100 - (openPorts * 10)));
};

const getScoreStatus = (score) => {
    if (score >= 90) return 'Excellent';
    if (score >= 70) return 'Good';
    if (score >= 50) return 'Fair';
    return 'Poor';
};

const generateSecurityRecommendations = ({ 
    systemScore, 
    networkScore, 
    storageScore,
    processes,
    networkStats,
    fsSize 
}) => {
    const recommendations = [];

    // System recommendations
    if (systemScore < 70) {
        if (processes?.list.some(proc => isKnownMaliciousProcess(proc.name))) {
            recommendations.push('Remove detected malicious processes');
        }
        if (processes?.list.some(proc => proc.cpu > 90)) {
            recommendations.push('Investigate high CPU usage processes');
        }
    }

    // Network recommendations
    if (networkScore < 70) {
        if (networkStats?.some(stat => stat.rx_errors + stat.tx_errors > 0)) {
            recommendations.push('Investigate network errors and packet loss');
        }
    }

    // Storage recommendations
    if (storageScore < 70) {
        if (fsSize?.some(fs => fs.use > 90)) {
            recommendations.push('Free up disk space on critical partitions');
        }
    }

    return recommendations;
};

export const dashboardController = {
    getNetworkHealth,
    getThreats,
    getAlerts,
    getSecurityScore
};