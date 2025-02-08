import { Router } from 'express';
import { dashboardController } from '../controllers/dashboard.controller.js';

const router = Router();

router.get('/network-health', dashboardController.getNetworkHealth);
router.get('/threats', dashboardController.getThreats);
router.get('/alerts', dashboardController.getAlerts);
router.get('/security-score', dashboardController.getSecurityScore);

export default router; 