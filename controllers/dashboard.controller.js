import { asyncHandler } from '../utils/asyncHandler.js';
import ApiResponse from '../utils/ApiResponse.js';
import ApiError from '../utils/ApiError.js';

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

const getNetworkHealth = asyncHandler(async (req, res) => {
    try {
        return res.status(200).json(
            new ApiResponse(200, networkHealthData, "Network health data retrieved successfully")
        );
    } catch (error) {
        throw new ApiError(500, "Failed to fetch network health data");
    }
});

const getThreats = asyncHandler(async (req, res) => {
    try {
        return res.status(200).json(
            new ApiResponse(200, threatData, "Threat data retrieved successfully")
        );
    } catch (error) {
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
        return res.status(200).json(
            new ApiResponse(200, securityScoreData, "Security score retrieved successfully")
        );
    } catch (error) {
        throw new ApiError(500, "Failed to fetch security score");
    }
});

export const dashboardController = {
    getNetworkHealth,
    getThreats,
    getAlerts,
    getSecurityScore
};