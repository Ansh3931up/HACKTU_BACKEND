import { Router } from 'express';
import { zeroDayController } from "../controllers/zeroDay.controllers.js";

const router = Router();

// Main comprehensive scan endpoint
router.get("/scan/all", zeroDayController.getAllZeroDayData);

// Individual scan endpoints
router.get("/system/health", zeroDayController.getAllSecurityData);
router.get("/network/security", zeroDayController.getNetworkSecurity);
router.get("/vulnerabilities", zeroDayController.getVulnerabilities);
router.get("/malware/scan", zeroDayController.getMalwareAnalysis);

// System-specific endpoints
router.get("/system/patches", zeroDayController.checkSystemPatches);
router.get("/system/processes", zeroDayController.getRunningProcesses);
router.get("/system/services", zeroDayController.getRunningServices);

// Network-specific endpoints
router.get("/network/connections", zeroDayController.getNetworkConnections);
router.get("/network/ports", zeroDayController.scanOpenPorts);
router.get("/network/firewall", zeroDayController.checkFirewallStatus);

export default router;
