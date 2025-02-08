import { Router } from 'express';
import { phishingController } from "../controllers/phishing.controller.js";

const router = Router();

// Main comprehensive scan endpoint
router.get("/scan/all", phishingController.getAllPhishingData);

// Individual scan endpoints
router.get("/check/whois", phishingController.checkWhois);
router.get("/check/dns", phishingController.checkDNS);
router.get("/check/content", phishingController.checkPhishingContent);
router.post("/extract/links", phishingController.extractLinks);
router.get("/check/url-safety", phishingController.checkGoogleSafeBrowsing);

export default router; 