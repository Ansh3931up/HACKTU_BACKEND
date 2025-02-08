import { Router } from 'express';
import { aptController } from "../controllers/apt.controllers.js";

const router = Router();

router.post("/monitoring/start", aptController.startNetworkMonitoring);
router.post("/monitoring/stop", aptController.stopNetworkMonitoring);
router.get("/monitoring/all", aptController.getAllMonitoringData);
router.post("/capture/packets", aptController.capturePackets);

export default router;

