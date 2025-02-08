import { Router } from "express";
import { networkAdvancedController } from "../controllers/networkAdvanced.controller.js";
import ApiResponse from "../utils/ApiResponse.js";

const router = Router();

// Security analysis routes
router.get("/analysis/:ipRange(*)", networkAdvancedController.analyzeNetworkSecurity);
router.get("/threat-check/:ip", async (req, res) => {
    try {
        const data = await networkAdvancedController.checkIPReputation(req.params.ip);
        return res.status(200).json(new ApiResponse(200, data, "Threat check completed"));
    } catch (error) {
        console.error("Threat check error:", error);
        return res.status(500).json(new ApiResponse(500, null, "Threat check failed"));
    }
});
router.get("/dark-web/:email", async (req, res) => {
    try {
        const data = await networkAdvancedController.checkDarkWebLeaks(req.params.email);
        return res.status(200).json(new ApiResponse(200, data, "Dark web check completed"));
    } catch (error) {
        console.error("Dark web check error:", error);
        return res.status(500).json(new ApiResponse(500, null, "Dark web check failed"));
    }
});

// Scheduled scan management
router.post("/schedule", networkAdvancedController.scheduleNetworkScan);

// Report generation
router.get("/report/:ipRange(*)", networkAdvancedController.generateSecurityReport);

export default router; 