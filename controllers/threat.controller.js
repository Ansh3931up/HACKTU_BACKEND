import { asyncHandler } from '../utils/asyncHandler.js';
import ApiResponse from '../utils/ApiResponse.js';
import ApiError from '../utils/ApiError.js';

// Simulated data storage with the exact structure
let threatAnalysisData = {
    networkData: {
        threats: [
            {
                id: 1,
                type: 'Malware Detected',
                severity: 'High',
                source: '192.168.1.101',
                timestamp: new Date().toISOString(),
                details: 'Suspicious file detected in system directory',
                status: 'Active'
            },
            {
                id: 2,
                type: 'Suspicious Login',
                severity: 'Medium',
                source: '192.168.1.2',
                timestamp: new Date(Date.now() - 3600000).toISOString(),
                details: 'Multiple failed login attempts',
                status: 'Investigating'
            },
            {
                id: 3,
                type: 'Port Scan',
                severity: 'Low',
                source: '203.0.113.0',
                timestamp: new Date(Date.now() - 7200000).toISOString(),
                details: 'Sequential port scanning detected',
                status: 'Resolved'
            }
        ],
        trafficData: {
            inbound: [40, 59, 80, 81, 56, 55, 40, 45, 60, 70, 65, 50],
            outbound: [33, 48, 50, 79, 70, 45, 35, 40, 55, 65, 60, 45],
            timestamps: Array.from({ length: 12 }, (_, i) => 
                new Date(Date.now() - (11 - i) * 3600000).toISOString()
            )
        }
    },
    devices: [
        {
            id: 1,
            name: 'Main Router',
            ip: '192.168.1.1',
            status: 'Online',
            lastSeen: new Date().toISOString(),
            type: 'Network Device',
            risk: 'Low'
        },
        {
            id: 2,
            name: 'Desktop PC',
            ip: '192.168.1.100',
            status: 'Online',
            lastSeen: new Date().toISOString(),
            type: 'Workstation',
            risk: 'Medium'
        },
        {
            id: 3,
            name: 'Server',
            ip: '192.168.1.50',
            status: 'Online',
            lastSeen: new Date().toISOString(),
            type: 'Server',
            risk: 'High'
        }
    ],
    securityScore: {
        secure: 85,
        atRisk: 15,
        lastUpdated: new Date().toISOString()
    },
    threatMetrics: {
        lowRisk: 71,
        mediumRisk: 8,
        highRisk: 5,
        total: 84,
        trend: {
            daily: '+2',
            weekly: '-5',
            monthly: '+12'
        }
    },
    networkHealth: {
        uptime: 99.9,
        latency: 12,
        packetLoss: 0.1,
        bandwidthUsage: 70,
        timestamp: new Date().toISOString()
    }
};

// Update simulated data periodically
const updateSimulatedData = () => {
    // Update timestamps and generate new random data
    threatAnalysisData = {
        ...threatAnalysisData,
        networkData: {
            threats: threatAnalysisData.networkData.threats.map(threat => ({
                ...threat,
                timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString()
            })),
            trafficData: {
                inbound: [...threatAnalysisData.networkData.trafficData.inbound.slice(1), 
                    Math.floor(Math.random() * 40) + 30],
                outbound: [...threatAnalysisData.networkData.trafficData.outbound.slice(1), 
                    Math.floor(Math.random() * 40) + 30],
                timestamps: Array.from({ length: 12 }, (_, i) => 
                    new Date(Date.now() - (11 - i) * 3600000).toISOString()
                )
            }
        },
        devices: threatAnalysisData.devices.map(device => ({
            ...device,
            lastSeen: new Date().toISOString()
        })),
        securityScore: {
            ...threatAnalysisData.securityScore,
            lastUpdated: new Date().toISOString()
        },
        networkHealth: {
            ...threatAnalysisData.networkHealth,
            latency: Math.floor(Math.random() * 20) + 5,
            bandwidthUsage: Math.floor(Math.random() * 30) + 50,
            timestamp: new Date().toISOString()
        }
    };
};

// Update data every 5 seconds
setInterval(updateSimulatedData, 5000);

const getThreatAnalysisData = asyncHandler(async (req, res) => {
    try {
        return res.status(200).json(
            new ApiResponse(200, threatAnalysisData, "Threat analysis data retrieved successfully")
        );
    } catch (error) {
        throw new ApiError(500, "Failed to fetch threat analysis data");
    }
});

export const threatController = {
    getThreatAnalysisData
}; 