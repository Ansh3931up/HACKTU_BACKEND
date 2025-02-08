import { Router } from 'express';
import { networkController } from '../controllers/network.controller.js';

const router = Router();

// Network scanning routes
router.get('/scan/:ipRange(*)', networkController.scanNetwork);
router.get('/traffic', networkController.getTrafficAnalysis);
router.get('/analysis/:ipRange(*)', networkController.analyzeNetworkSecurity);

export default router;