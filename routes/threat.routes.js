import { Router } from 'express';
import { threatController } from '../controllers/threat.controller.js';

const router = Router();

router.get('/', threatController.getThreatAnalysisData);

export default router; 