import { exec } from 'child_process';
import { promisify } from 'util';
import os from 'os';
import { asyncHandler } from '../utils/asyncHandler.js';
import ApiError from '../utils/ApiError.js';
import ApiResponse from '../utils/ApiResponse.js';

const execAsync = promisify(exec);

class AptController {
    constructor() {
        this.packetData = [];
        this.scanResults = new Map();
        this.networkData = [];
        this.isMonitoring = false;
        this.monitoringInterval = null;
        this.packetCaptures = [];
        this.isPacketCapturing = false;
        // Initialize response storage
        this.responseStorage = {
            networkCapture: null,
            portScan: null,
            systemLogs: null,
            dnsTunneling: null,
            systemUsage: null,
            lastUpdated: null
        };
        // Start periodic system monitoring
        this.startPeriodicMonitoring();
    }

    // Periodic monitoring function
    startPeriodicMonitoring = () => {
        setInterval(async () => {
            try {
                await this.updateSystemStats();
            } catch (error) {
                console.error('Periodic monitoring failed:', error);
            }
        }, 60000); // Update every minute
    };

    // Update system stats
    updateSystemStats = async () => {
        const systemStats = {
            cpuLoad: os.loadavg(),
            totalMemory: os.totalmem(),
            freeMemory: os.freemem(),
            uptime: os.uptime(),
            platform: os.platform(),
            timestamp: new Date().toISOString()
        };
        this.responseStorage.systemUsage = systemStats;
        this.responseStorage.lastUpdated = new Date().toISOString();
    };

    // Get all monitoring data
    getAllMonitoringData = asyncHandler(async (req, res) => {
        try {
            const latestData = await this.captureNetworkData();
            
            // Get packet data using netstat directly instead of trying to parse as JSON
            const { stdout } = await execAsync('netstat -n');
            const latestPackets = this.parseNetstatOutput(stdout);

            const monitoringData = {
                networkCapture: {
                    current: latestData,
                    history: this.networkData.slice(-10)
                },
                packetCapture: {
                    current: {
                        packets: latestPackets,
                        analysis: this.analyzePackets(latestPackets)
                    },
                    history: this.packetCaptures
                },
                systemUsage: {
                    cpu: os.loadavg(),
                    memory: {
                        total: os.totalmem(),
                        free: os.freemem()
                    },
                    uptime: os.uptime()
                },
                status: {
                    isMonitoring: this.isMonitoring,
                    isPacketCapturing: this.isPacketCapturing,
                    lastUpdated: this.responseStorage.lastUpdated,
                    totalSnapshots: this.networkData.length
                }
            };

            return res.status(200).json(
                new ApiResponse(
                    200,
                    monitoringData,
                    "Monitoring data retrieved successfully"
                )
            );
        } catch (error) {
            throw new ApiError(500, `Failed to get monitoring data: ${error.message}`);
        }
    });

    // 🛜 Capture Network Packets (Detect Suspicious Traffic)
    captureNetworkPackets = asyncHandler(async (req, res) => {
        try {
            const c = new Cap();
            const device = Cap.findDevice("192.168.1.1");
            
            if (!device) {
                throw new ApiError(400, "Network device not found");
            }

            const filter = "tcp or udp";
            const bufSize = 10 * 1024 * 1024;
            const buffer = Buffer.alloc(65535);

            const linkType = c.open(device, filter, bufSize, buffer);
            c.setMinBytes && c.setMinBytes(0);

            c.on("packet", (nbytes, trunc) => {
                if (linkType === "ETHERNET") {
                    const ret = decoders.Ethernet(buffer);
                    if (ret.info.type === PROTOCOL.ETHERNET.IPV4) {
                        const ip = decoders.IPV4(buffer, ret.offset);
                        this.packetData.push({
                            source: ip.info.srcaddr,
                            destination: ip.info.dstaddr,
                            timestamp: new Date().toISOString()
                        });
                    }
                }
            });

            this.responseStorage.networkCapture = {
                recentPackets: this.packetData.slice(-100), // Keep last 100 packets
                timestamp: new Date().toISOString()
            };

            return res.status(200).json(
                new ApiResponse(
                    200,
                    { message: "Network packet capture started" },
                    "Packet capture initialized successfully"
                )
            );
        } catch (error) {
            throw new ApiError(500, `Packet capture failed: ${error.message}`);
        }
    });

    //  Scan Open Ports (Detect Unauthorized Access)
    scanOpenPorts = asyncHandler(async (req, res) => {
        const { target = 'localhost' } = req.body;

        try {
            const scan = new NmapScan(target, "-p 1-65535");
            
            const scanPromise = new Promise((resolve, reject) => {
                scan.on("complete", (data) => {
                    this.scanResults.set(target, data);
                    this.responseStorage.portScan = {
                        target,
                        results: data,
                        timestamp: new Date().toISOString()
                    };
                    resolve(data);
                });

                scan.on("error", reject);
            });

            const results = await scanPromise;
            scan.startScan();

            return res.status(200).json(
                new ApiResponse(
                    200,
                    { ports: results },
                    "Port scan completed successfully"
                )
            );
        } catch (error) {
            throw new ApiError(500, `Port scan failed: ${error.message}`);
        }
    });

    //  Monitor System Logs (Detect Unauthorized Login Attempts)
    monitorSystemLogs = asyncHandler(async (req, res) => {
        try {
            const { stdout, stderr } = await exec('cat /var/log/auth.log | grep "Failed password"');
            
            if (stderr) {
                throw new Error(stderr);
            }

            const failedLogins = stdout.split('\n').filter(Boolean);
            this.responseStorage.systemLogs = {
                failedLogins,
                lastChecked: new Date().toISOString()
            };

            return res.status(200).json(
                new ApiResponse(
                    200,
                    { failedLogins },
                    "Log monitoring completed successfully"
                )
            );
        } catch (error) {
            throw new ApiError(500, `Log monitoring failed: ${error.message}`);
        }
    });

    //  Detect DNS Tunneling (Check for Malicious Domains)
    detectDnsTunneling = asyncHandler(async (req, res) => {
        const { domain = 'malicious-domain.com' } = req.body;

        try {
            const records = await dns.promises.resolve(domain);
            
            const analysis = {
                domain,
                records,
                suspicious: this.analyzeDnsRecords(records)
            };

            this.responseStorage.dnsTunneling = analysis;

            return res.status(200).json(
                new ApiResponse(
                    200,
                    analysis,
                    "DNS analysis completed successfully"
                )
            );
        } catch (error) {
            throw new ApiError(500, `DNS analysis failed: ${error.message}`);
        }
    });

    //  Monitor System Usage (Check for Anomalous Activity)
    monitorSystemUsage = asyncHandler(async (req, res) => {
        try {
            const systemStats = {
                cpuLoad: os.loadavg(),
                totalMemory: os.totalmem(),
                freeMemory: os.freemem(),
                uptime: os.uptime(),
                platform: os.platform(),
                timestamp: new Date().toISOString()
            };

            return res.status(200).json(
                new ApiResponse(
                    200,
                    systemStats,
                    "System monitoring completed successfully"
                )
            );
        } catch (error) {
            throw new ApiError(500, `System monitoring failed: ${error.message}`);
        }
    });

    // Helper method for DNS analysis
    analyzeDnsRecords(records) {
        // Add your DNS analysis logic here
        return records.some(record => 
            record.length > 100 || // Unusually long records
            /base64|hex/.test(record) // Encoded data
        );
    }

    startNetworkMonitoring = asyncHandler(async (req, res) => {
        try {
            if (this.isMonitoring) {
                return res.status(400).json(
                    new ApiResponse(
                        400,
                        null,
                        "Network monitoring is already running"
                    )
                );
            }

            this.isMonitoring = true;
            
            // Initial capture
            await this.captureNetworkData();

            // Set up periodic monitoring
            this.monitoringInterval = setInterval(async () => {
                await this.captureNetworkData();
            }, 10000); // Capture every 10 seconds

            return res.status(200).json(
                new ApiResponse(
                    200,
                    { message: "Network monitoring started" },
                    "Monitoring initialized successfully"
                )
            );
        } catch (error) {
            throw new ApiError(500, `Network monitoring failed: ${error.message}`);
        }
    });

    stopNetworkMonitoring = asyncHandler(async (req, res) => {
        try {
            if (!this.isMonitoring) {
                return res.status(400).json(
                    new ApiResponse(
                        400,
                        null,
                        "No monitoring is running"
                    )
                );
            }

            clearInterval(this.monitoringInterval);
            this.isMonitoring = false;

            return res.status(200).json(
                new ApiResponse(
                    200,
                    { 
                        message: "Network monitoring stopped",
                        collectedDataPoints: this.networkData.length
                    },
                    "Monitoring stopped successfully"
                )
            );
        } catch (error) {
            throw new ApiError(500, `Failed to stop monitoring: ${error.message}`);
        }
    });

    async captureNetworkData() {
        try {
            const { stdout: netstatOutput } = await execAsync('netstat -n');
            const connections = this.parseNetstatOutput(netstatOutput);

            const timestamp = new Date().toISOString();
            const networkSnapshot = {
                timestamp,
                connections,
                stats: {
                    total: connections.length,
                    active: connections.filter(c => c.state === 'ESTABLISHED').length
                }
            };

            this.networkData.push(networkSnapshot);

            if (this.networkData.length > 100) {
                this.networkData = this.networkData.slice(-100);
            }

            this.responseStorage.networkCapture = {
                lastSnapshot: networkSnapshot,
                timestamp
            };

            this.responseStorage.lastUpdated = timestamp;

            return networkSnapshot;
        } catch (error) {
            console.error('Error capturing network data:', error);
            return {
                timestamp: new Date().toISOString(),
                connections: [],
                stats: { total: 0, active: 0 }
            };
        }
    }

    parseNetstatOutput(output) {
        try {
            return output
                .split('\n')
                .filter(line => line.includes('TCP') || line.includes('UDP'))
                .map(line => {
                    const parts = line.trim().split(/\s+/);
                    return {
                        protocol: parts[0] || 'Unknown',
                        localAddress: parts[1] || 'Unknown',
                        remoteAddress: parts[2] || 'Unknown',
                        state: parts[3] || 'Unknown',
                        timestamp: new Date().toISOString()
                    };
                })
                .filter(connection => connection.protocol !== 'Unknown');
        } catch (error) {
            console.error('Error parsing netstat output:', error);
            return [];
        }
    }

    parseNetworkStats(stats) {
        const ipv4Stats = {};
        const tcpStats = {};
        
        try {
            stats.split('\n').forEach(line => {
                if (line.includes('IPv4 Statistics')) {
                    const matches = line.match(/(\d+)/);
                    if (matches) {
                        ipv4Stats.packetsReceived = parseInt(matches[1]);
                    }
                }
                if (line.includes('TCP Statistics')) {
                    const matches = line.match(/(\d+)/);
                    if (matches) {
                        tcpStats.activeConnections = parseInt(matches[1]);
                    }
                }
            });
        } catch (e) {
            console.error('Error parsing network stats:', e);
        }

        return {
            ipv4: ipv4Stats,
            tcp: tcpStats
        };
    }

    capturePackets = asyncHandler(async (req, res) => {
        try {
            if (this.isPacketCapturing) {
                return res.status(400).json(
                    new ApiResponse(400, null, "Packet capture is already running")
                );
            }

            this.isPacketCapturing = true;

            const { stdout } = await execAsync('netstat -n');
            const packets = this.parseNetstatOutput(stdout);

            const captureData = {
                timestamp: new Date().toISOString(),
                packets,
                analysis: this.analyzePackets(packets)
            };

            this.packetCaptures.push(captureData);

            if (this.packetCaptures.length > 10) {
                this.packetCaptures = this.packetCaptures.slice(-10);
            }

            this.isPacketCapturing = false;

            return res.status(200).json(
                new ApiResponse(200, captureData, "Packet capture completed successfully")
            );
        } catch (error) {
            this.isPacketCapturing = false;
            console.error('Packet capture error:', error);
            throw new ApiError(500, `Packet capture failed: ${error.message}`);
        }
    });

    analyzePackets(packets) {
        const analysis = {
            suspiciousConnections: [],
            unusualPorts: [],
            statistics: {
                totalConnections: packets.length,
                byState: {},
                byProtocol: {}
            }
        };

        try {
            packets.forEach(packet => {
                // Count by state
                analysis.statistics.byState[packet.state] = 
                    (analysis.statistics.byState[packet.state] || 0) + 1;

                // Count by protocol
                analysis.statistics.byProtocol[packet.protocol] = 
                    (analysis.statistics.byProtocol[packet.protocol] || 0) + 1;

                // Check for suspicious ports
                const localPort = packet.localAddress.split(':')[1];
                const remotePort = packet.remoteAddress.split(':')[1];
                const suspiciousPorts = [4444, 5555, 666, 1337, 31337];

                if (suspiciousPorts.includes(Number(localPort)) || 
                    suspiciousPorts.includes(Number(remotePort))) {
                    analysis.unusualPorts.push({
                        local: packet.localAddress,
                        remote: packet.remoteAddress,
                        protocol: packet.protocol
                    });
                }
            });
        } catch (error) {
            console.error('Error analyzing packets:', error);
        }

        return analysis;
    }

    // Helper method to get packet capture command
    getPacketCaptureCommand() {
        return 'netstat -n'; // Simple netstat command instead of PowerShell
    }
}

export const aptController = new AptController();
