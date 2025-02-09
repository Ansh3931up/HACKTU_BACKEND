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

// Add retry utility function
const retryOperation = async (operation, retries = 3, delay = 1000) => {
    for (let i = 0; i < retries; i++) {
        try {
            return await operation();
        } catch (err) {
            if (i === retries - 1) throw err;
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }
};

// Replace the dummy data with real monitoring functions
const getRealTimeNetworkHealth = async () => {
    try {
        // Wrap the Promise.all with retry logic and better error handling
        const [
            networkStats,
            latencyCheck,
            networkInterfaces,
            networkConnections
        ] = await retryOperation(async () => {
            try {
                return await Promise.all([
                    si.networkStats().catch(err => ({ error: err })),
                    si.inetLatency().catch(() => 0),  // Default to 0 if latency check fails
                    si.networkInterfaces().catch(err => ({ error: err })),
                    si.networkConnections().catch(err => ({ error: err }))
                ]);
            } catch (error) {
                console.error('Network data collection error:', error);
                // Return default values if all fails
                return [[], 0, [], []];
            }
        });

        // Safely handle potentially failed network stats
        const safeNetworkStats = Array.isArray(networkStats) ? networkStats : [];
        const safeNetworkInterfaces = Array.isArray(networkInterfaces) ? networkInterfaces : [];

        // Get active interfaces with proper filtering and error handling
        const activeInterfaces = safeNetworkInterfaces.filter(iface => {
            try {
                return iface && 
                       iface.operstate === 'up' && 
                       !iface.internal &&
                       (iface.ip4 || iface.ip6);
            } catch (err) {
                console.warn('Interface filtering error:', err);
                return false;
            }
        });

        // Rest of the code remains the same but with added error handling
        const primaryInterface = activeInterfaces.find(iface => {
            try {
                return (iface.default || iface.type === 'wired' || iface.type === 'wireless') &&
                       (iface.ip4 || iface.ip6);
            } catch (err) {
                console.warn('Primary interface detection error:', err);
                return false;
            }
        });

        const mainInterface = safeNetworkStats.find(stat => 
            stat && stat.iface === primaryInterface?.iface
        ) || safeNetworkStats[0] || { rx_sec: 0, tx_sec: 0 };

        // Safe bandwidth calculation
        let bandwidthUsage = 0;
        try {
            if (primaryInterface?.speed && mainInterface) {
                const rxBits = mainInterface.rx_sec * 8;
                const txBits = mainInterface.tx_sec * 8;
                const interfaceCapacity = primaryInterface.speed * 1e6;
                bandwidthUsage = Number(((rxBits + txBits) / interfaceCapacity * 100).toFixed(1));
            }
        } catch (err) {
            console.warn('Bandwidth calculation error:', err);
        }

        // Speed test with timeout and error handling
        let speedTestResult = null;
        try {
            speedTestResult = await Promise.race([
                speedtest.getSpeed().catch(() => null),
                new Promise(resolve => setTimeout(() => resolve(null), 5000))
            ]);
        } catch (error) {
            console.warn('Speed test failed:', error);
        }

        const networkHealth = {
            latency: {
                current: latencyCheck || 0,
                historicalAverage: 22.4
            },
            bandwidth: {
                usagePercentage: bandwidthUsage || 0,
                currentUsage: {
                    upload: mainInterface?.tx_sec || 0,
                    download: mainInterface?.rx_sec || 0
                },
                capacity: primaryInterface?.speed || 0
            },
            speedTest: {
                download: speedTestResult || 'Unavailable',
                units: 'Mbps'
            },
            interfaceStatus: {
                name: primaryInterface?.iface || 'unknown',
                ip: primaryInterface?.ip4 || 'unknown',
                connectionType: primaryInterface?.type || 'unknown',
                duplex: primaryInterface?.duplex || 'unknown',
                isConnected: !!(primaryInterface?.ip4 || primaryInterface?.ip6)
            },
            connections: {
                ethernet: activeInterfaces.filter(iface => {
                    try {
                        return (iface.type === 'wired' || 
                               iface.iface.toLowerCase().includes('eth') ||
                               iface.iface.toLowerCase().includes('ethernet')) &&
                               iface.operstate === 'up' &&
                               (iface.ip4 || iface.ip6);
                    } catch (err) {
                        return false;
                    }
                }).length,
                wifi: activeInterfaces.filter(iface => {
                    try {
                        return (iface.type === 'wireless' ||
                               iface.iface.toLowerCase().includes('wlan') ||
                               iface.iface.toLowerCase().includes('wifi')) &&
                               iface.operstate === 'up' &&
                               (iface.ip4 || iface.ip6);
                    } catch (err) {
                        return false;
                    }
                }).length
            },
            healthStatus: calculateHealthScore({
                latency: latencyCheck || 0,
                bandwidthUsage: bandwidthUsage || 0
            })
        };

        return networkHealth;

    } catch (error) {
        console.error('Network monitoring error:', error);
        // Return a minimal response instead of throwing
        return {
            error: 'Network monitoring temporarily unavailable',
            timestamp: new Date().toISOString(),
            healthStatus: {
                score: 0,
                components: { latency: 0, bandwidth: 0 },
                label: 'Error'
            }
        };
    }
};

const calculateHealthScore = ({ latency, bandwidthUsage }) => {
    let score = 100;
    
    // Latency impact (60% weight)
    if (latency > 100) score -= 60;
    else if (latency > 50) score -= 30;
    else if (latency > 20) score -= 15;

    // Bandwidth impact (40% weight)
    if (bandwidthUsage > 90) score -= 40;
    else if (bandwidthUsage > 75) score -= 20;
    else if (bandwidthUsage > 50) score -= 10;

    return {
        score: Math.max(0, score),
        components: {
            latency: 100 - Math.min(60, (latency > 100 ? 60 : latency/1.67)), // Adjusted for new weight
            bandwidth: 100 - Math.min(40, (bandwidthUsage - 50) * 1.33)  // Adjusted for new weight
        },
        label: score >= 90 ? 'Excellent' :
               score >= 75 ? 'Good' :
               score >= 60 ? 'Fair' : 'Poor'
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

        // Analyze active network interfaces - Updated logic
        const activeInterfaces = networkInterfaces.filter(iface => {
            // Only count interfaces that are:
            // 1. Up (operational)
            // 2. Not internal/loopback
            // 3. Have an IPv4 or IPv6 address assigned
            return iface.operstate === 'up' && 
                   !iface.internal &&
                   (iface.ip4 || iface.ip6);
        });

        // More accurate interface type detection
        const ethernetInterfaces = activeInterfaces.filter(iface => {
            // Check if it's actually a wired ethernet connection
            return (iface.type === 'wired' || 
                   iface.iface.toLowerCase().includes('eth') ||
                   iface.iface.toLowerCase().includes('ethernet')) &&
                   iface.operstate === 'up' &&
                   (iface.ip4 || iface.ip6);  // Must have an IP address
        }).length;

        const wifiInterfaces = activeInterfaces.filter(iface => {
            // Check if it's actually a wireless connection
            return (iface.type === 'wireless' ||
                   iface.iface.toLowerCase().includes('wlan') ||
                   iface.iface.toLowerCase().includes('wifi')) &&
                   iface.operstate === 'up' &&
                   (iface.ip4 || iface.ip6);  // Must have an IP address
        }).length;

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
                wifi: wifiInterfaces,
                bluetooth: bluetoothDevices.length || 0
            },
            networkInterfaces: activeInterfaces.map(iface => ({
                name: iface.iface,
                type: iface.type,
                state: iface.operstate,
                speed: iface.speed,
                ip: iface.ip4 || iface.ip6,
                mac: iface.mac,
                isConnected: !!(iface.ip4 || iface.ip6)  // Added this flag
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

// Add this helper function at the top with other helper functions
const isKnownService = (port) => {
    // List of common legitimate service ports
    const commonPorts = [
        20, 21,     // FTP
        22,         // SSH
        23,         // Telnet
        25,         // SMTP
        53,         // DNS
        80, 443,    // HTTP/HTTPS
        110,        // POP3
        143,        // IMAP
        389,        // LDAP
        445,        // SMB
        3306,       // MySQL
        5432,       // PostgreSQL
        27017,      // MongoDB
        6379,       // Redis
        8080, 8443  // Alternative HTTP/HTTPS
    ];
    
    return commonPorts.includes(Number(port));
};

// Real-time alerts monitoring
const getRealTimeAlerts = async () => {
    try {
        const [
            processes,
            networkStats,
            fsSize,
            networkConnections
        ] = await Promise.all([
            si.processes(),
            si.networkStats(),
            si.fsSize(),
            si.networkConnections()
        ]);

        // Use an object to track unique alerts by their actual content
        const uniqueAlerts = new Map();

        // Helper function to add alert with deduplication
        const addAlert = (key, alert) => {
            if (!uniqueAlerts.has(key)) {
                uniqueAlerts.set(key, {
                    id: `${alert.type.toLowerCase()}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                    ...alert,
                    timestamp: new Date().toISOString()
                });
            }
        };

        // Check CPU intensive processes
        if (processes && processes.list) {
            processes.list.forEach(proc => {
                if (proc.cpu > 90) {
                    const key = `CPU_${proc.name}_${proc.pid}`;
                    addAlert(key, {
                        type: 'SYSTEM',
                        severity: 'WARNING',
                        message: `High CPU usage (${proc.cpu.toFixed(1)}%) by process ${proc.name}`,
                        source: 'Process Monitor',
                        details: {
                            pid: proc.pid,
                            cpu: proc.cpu,
                            name: proc.name
                        }
                    });
                }
                if (proc.memRss > (os.totalmem() * 0.5)) {
                    const key = `MEM_${proc.name}_${proc.pid}`;
                    addAlert(key, {
                        type: 'SYSTEM',
                        severity: 'WARNING',
                        message: `High memory usage by process ${proc.name}`,
                        source: 'Memory Monitor',
                        details: {
                            pid: proc.pid,
                            memory: proc.memRss,
                            name: proc.name
                        }
                    });
                }
            });
        }

        // Check network errors
        if (networkStats) {
            networkStats.forEach(stat => {
                if (stat.rx_errors > 0 || stat.tx_errors > 0) {
                    const key = `NET_ERR_${stat.iface}`;
                    addAlert(key, {
                        type: 'NETWORK',
                        severity: 'ERROR',
                        message: `Network errors detected on interface ${stat.iface}`,
                        source: 'Network Monitor',
                        details: {
                            interface: stat.iface,
                            rxErrors: stat.rx_errors,
                            txErrors: stat.tx_errors
                        }
                    });
                }
                if (stat.rx_dropped > 0 || stat.tx_dropped > 0) {
                    const key = `NET_DROP_${stat.iface}`;
                    addAlert(key, {
                        type: 'NETWORK',
                        severity: 'WARNING',
                        message: `Dropped packets detected on interface ${stat.iface}`,
                        source: 'Network Monitor',
                        details: {
                            interface: stat.iface,
                            rxDropped: stat.rx_dropped,
                            txDropped: stat.tx_dropped
                        }
                    });
                }
            });
        }

        // Check disk space
        if (fsSize) {
            fsSize.forEach(fs => {
                if (fs.use > 90) {
                    const key = `DISK_${fs.mount}`;
                    addAlert(key, {
                        type: 'STORAGE',
                        severity: 'WARNING',
                        message: `Low disk space on ${fs.mount} (${fs.use}% used)`,
                        source: 'Storage Monitor',
                        details: {
                            mount: fs.mount,
                            used: fs.used,
                            size: fs.size,
                            usage: fs.use
                        }
                    });
                }
            });
        }

        // Check suspicious network connections
        if (networkConnections) {
            networkConnections.forEach(conn => {
                if (conn.state === 'LISTEN' && !isKnownService(conn.port)) {
                    const key = `CONN_${conn.port}_${conn.state}`;
                    addAlert(key, {
                        type: 'SECURITY',
                        severity: 'WARNING',
                        message: `Suspicious port ${conn.port || 'unknown'} in ${conn.state} state`,
                        source: 'Security Monitor',
                        details: {
                            port: conn.port || 'unknown',
                            state: conn.state,
                            process: conn.process || 'unknown',
                            protocol: conn.protocol || 'unknown'
                        }
                    });
                }
            });
        }

        // Convert Map to Array and sort by timestamp
        const alertsArray = Array.from(uniqueAlerts.values())
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        return {
            total: alertsArray.length,
            critical: alertsArray.filter(alert => alert.severity === 'ERROR').length,
            warning: alertsArray.filter(alert => alert.severity === 'WARNING').length,
            categories: {
                system: alertsArray.filter(alert => alert.type === 'SYSTEM').length,
                network: alertsArray.filter(alert => alert.type === 'NETWORK').length,
                security: alertsArray.filter(alert => alert.type === 'SECURITY').length,
                storage: alertsArray.filter(alert => alert.type === 'STORAGE').length
            },
            alerts: alertsArray.slice(0, 10) // Return only the 10 most recent alerts
        };

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
        const alertsData = await getRealTimeAlerts();
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