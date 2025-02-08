import { exec } from 'child_process';
import { promisify } from 'util';
import dns from 'dns';
import axios from 'axios';
import * as cheerio from 'cheerio';
import { asyncHandler } from '../utils/asyncHandler.js';
import ApiError from '../utils/ApiError.js';
import ApiResponse from '../utils/ApiResponse.js';
import https from 'https';
import tls from 'tls';

const execAsync = promisify(exec);
const GOOGLE_SAFE_BROWSING_API_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

// First, check if required environment variables are set
if (!GOOGLE_SAFE_BROWSING_API_KEY) {
    console.warn('Warning: GOOGLE_SAFE_BROWSING_API_KEY is not set in environment variables');
}

class PhishingController {
    constructor() {
        this.scanResults = new Map();
        this.responseStorage = {
            whoisData: null,
            dnsRecords: null,
            contentAnalysis: null,
            urlSafety: null,
            extractedLinks: null,
            lastUpdated: null
        };
        this.startPeriodicScanning();
    }

    // Periodic scanning function
    startPeriodicScanning = () => {
        setInterval(async () => {
            try {
                await this.updateStoredResults();
            } catch (error) {
                console.error('Periodic scanning failed:', error);
            }
        }, 300000); // Update every 5 minutes
    };

    // Update stored results
    updateStoredResults = async () => {
        this.responseStorage.lastUpdated = new Date().toISOString();
    };

    // 1️⃣ WHOIS Domain Lookup
    checkWhois = asyncHandler(async (req, res) => {
        const { domain } = req.query;
        if (!domain) {
            throw new ApiError(400, "Domain is required");
        }

        try {
            // Use nslookup instead of whois as it's more commonly available
            const { stdout } = await execAsync(`nslookup ${domain}`);
            
            const whoisData = this.parseNsLookupData(stdout);
            this.responseStorage.whoisData = {
                domain,
                data: whoisData,
                timestamp: new Date().toISOString()
            };

            return res.status(200).json(
                new ApiResponse(
                    200,
                    { whoisData },
                    "Domain lookup completed successfully"
                )
            );
        } catch (error) {
            console.error('Domain lookup error:', error);
            return res.status(200).json(
                new ApiResponse(
                    200,
                    { 
                        whoisData: {
                            domain,
                            error: "Could not fetch domain information",
                            timestamp: new Date().toISOString()
                        }
                    },
                    "Domain lookup completed with limited information"
                )
            );
        }
    });

    // 2️⃣ DNS Lookup
    checkDNS = asyncHandler(async (req, res) => {
        const { domain } = req.query;
        if (!domain) {
            throw new ApiError(400, "Domain is required");
        }

        try {
            const records = await dns.promises.resolve(domain);
            const analysis = this.analyzeDnsRecords(records);

            this.responseStorage.dnsRecords = {
                domain,
                records,
                analysis,
                timestamp: new Date().toISOString()
            };

            return res.status(200).json(
                new ApiResponse(
                    200,
                    { dnsRecords: records, analysis },
                    "DNS lookup completed successfully"
                )
            );
        } catch (error) {
            throw new ApiError(500, `DNS lookup failed: ${error.message}`);
        }
    });

    // 3️⃣ Web Content Phishing Check
    checkPhishingContent = asyncHandler(async (req, res) => {
        const { url } = req.query;
        if (!url) {
            throw new ApiError(400, "URL is required");
        }

        try {
            const response = await axios.get(url);
            const content = response.data.toLowerCase();
            const analysis = this.analyzeContent(content);

            this.responseStorage.contentAnalysis = {
                url,
                analysis,
                timestamp: new Date().toISOString()
            };

            return res.status(200).json(
                new ApiResponse(
                    200,
                    analysis,
                    "Content analysis completed successfully"
                )
            );
        } catch (error) {
            throw new ApiError(500, `Content analysis failed: ${error.message}`);
        }
    });

    // 4️⃣ Extract Links from Email Content
    extractLinks = asyncHandler(async (req, res) => {
        const { html } = req.body;
        if (!html) {
            throw new ApiError(400, "HTML content is required");
        }

        try {
            const links = this.parseLinks(html);
            const analysis = this.analyzeLinks(links);

            this.responseStorage.extractedLinks = {
                links,
                analysis,
                timestamp: new Date().toISOString()
            };

            return res.status(200).json(
                new ApiResponse(
                    200,
                    { links, analysis },
                    "Link extraction completed successfully"
                )
            );
        } catch (error) {
            throw new ApiError(500, `Link extraction failed: ${error.message}`);
        }
    });

    // 5️⃣ Google Safe Browsing API Check
    checkGoogleSafeBrowsing = asyncHandler(async (req, res) => {
        const { url } = req.query;
        if (!url) {
            throw new ApiError(400, "URL is required");
        }

        try {
            const analysis = await this.checkUrlSafety(url);
            
            this.responseStorage.urlSafety = {
                url,
                analysis,
                timestamp: new Date().toISOString()
            };

            return res.status(200).json(
                new ApiResponse(
                    200,
                    analysis,
                    "URL safety check completed successfully"
                )
            );
        } catch (error) {
            throw new ApiError(500, `URL safety check failed: ${error.message}`);
        }
    });

    // Add this new method to your existing PhishingController class
    getAllPhishingData = asyncHandler(async (req, res) => {
        const { url, domain, html } = req.query;
        
        try {
            const results = {
                timestamp: new Date().toISOString(),
                domainAnalysis: null,
                urlAnalysis: null,
                contentAnalysis: null,
                status: {
                    isScanning: false,
                    lastUpdated: this.responseStorage.lastUpdated
                }
            };

            // Domain Analysis
            if (domain) {
                try {
                    // Use DNS lookup instead of whois
                    const [aRecords, nsRecords, mxRecords, txtRecords] = await Promise.all([
                        dns.promises.resolve(domain, 'A').catch(() => []),
                        dns.promises.resolve(domain, 'NS').catch(() => []),
                        dns.promises.resolve(domain, 'MX').catch(() => []),
                        dns.promises.resolve(domain, 'TXT').catch(() => [])
                    ]);

                    const dnsAnalysis = {
                        totalRecords: aRecords.length,
                        suspiciousPatterns: false,
                        recordTypes: ['A', 'NS', 'MX', 'TXT'].filter(type => {
                            switch(type) {
                                case 'A': return aRecords.length > 0;
                                case 'NS': return nsRecords.length > 0;
                                case 'MX': return mxRecords.length > 0;
                                case 'TXT': return txtRecords.length > 0;
                                default: return false;
                            }
                        })
                    };

                    results.domainAnalysis = {
                        domainInfo: {
                            domain,
                            nameservers: nsRecords,
                            mailServers: mxRecords,
                            txtRecords,
                            ipAddresses: aRecords,
                            lastChecked: new Date().toISOString()
                        },
                        dns: {
                            records: aRecords,
                            analysis: dnsAnalysis
                        }
                    };
                } catch (error) {
                    console.error('Domain analysis error:', error);
                    results.domainAnalysis = { error: error.message };
                }
            }

            // URL Analysis
            if (url) {
                try {
                    const [safetyCheck, contentResponse] = await Promise.all([
                        this.checkUrlSafety(url),
                        axios.get(url)
                    ]);

                    const content = contentResponse.data.toLowerCase();
                    const contentAnalysis = this.analyzeContent(content);

                    results.urlAnalysis = {
                        safety: safetyCheck,
                        content: contentAnalysis
                    };
                } catch (error) {
                    console.error('URL analysis error:', error);
                    results.urlAnalysis = { error: error.message };
                }
            }

            // Content Analysis
            if (html) {
                try {
                    const links = this.parseLinks(html);
                    const linkAnalysis = this.analyzeLinks(links);

                    results.contentAnalysis = {
                        links,
                        analysis: linkAnalysis
                    };
                } catch (error) {
                    console.error('Content analysis error:', error);
                    results.contentAnalysis = { error: error.message };
                }
            }

            // Update response storage
            this.responseStorage = {
                ...this.responseStorage,
                lastUpdated: results.timestamp,
                lastFullScan: results
            };

            return res.status(200).json(
                new ApiResponse(
                    200,
                    results,
                    "Phishing analysis completed successfully"
                )
            );
        } catch (error) {
            throw new ApiError(500, `Phishing analysis failed: ${error.message}`);
        }
    });

    // Helper Methods
    parseWhoisData(data) {
        const relevantFields = ['Registrar:', 'Creation Date:', 'Updated Date:', 'Expiration Date:'];
        const parsed = {};
        
        data.split('\n').forEach(line => {
            const field = relevantFields.find(f => line.startsWith(f));
            if (field) {
                parsed[field.replace(':', '').trim()] = line.replace(field, '').trim();
            }
        });

        return parsed;
    }

    analyzeDnsRecords(records) {
        return {
            totalRecords: records.length,
            suspiciousPatterns: records.some(r => r.length > 100 || /base64|hex/.test(r)),
            recordTypes: records.map(r => typeof r === 'object' ? r.type : 'A')
        };
    }

    analyzeContent(content) {
        const phishingIndicators = [
            'account verification',
            'update your account',
            'security check',
            'unusual activity',
            'login attempt',
            'verify your identity'
        ];

        const matches = phishingIndicators.filter(indicator => 
            content.includes(indicator)
        );

        return {
            phishingDetected: matches.length > 0,
            indicators: matches,
            riskLevel: matches.length > 2 ? 'high' : matches.length > 0 ? 'medium' : 'low'
        };
    }

    parseLinks(html) {
        const $ = cheerio.load(html);
        const links = [];
        
        $('a').each((i, elem) => {
            links.push($(elem).attr('href'));
        });

        return links.filter(Boolean);
    }

    analyzeLinks(links) {
        const analysis = {
            totalLinks: links.length,
            suspiciousLinks: [],
            domains: new Set()
        };

        links.forEach(link => {
            try {
                const url = new URL(link);
                analysis.domains.add(url.hostname);

                if (this.isSuspiciousUrl(url)) {
                    analysis.suspiciousLinks.push(link);
                }
            } catch (e) {
                // Invalid URL
            }
        });

        analysis.domains = Array.from(analysis.domains);
        return analysis;
    }

    isSuspiciousUrl(url) {
        const suspiciousPatterns = [
            /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,  // IP addresses
            /bit\.ly|tinyurl|goo\.gl/,              // URL shorteners
            /secure|login|account|update|verify/     // Suspicious keywords
        ];

        return suspiciousPatterns.some(pattern => 
            pattern.test(url.hostname) || pattern.test(url.pathname)
        );
    }

    async checkUrlSafety(url) {
        if (!GOOGLE_SAFE_BROWSING_API_KEY) {
            return {
                safe: true, // Default to safe if we can't check
                error: "API key not configured",
                checkedAt: new Date().toISOString()
            };
        }

        try {
            const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`;
            
            const payload = {
                client: {
                    clientId: "ddo-security-scanner",
                    clientVersion: "1.0.0"
                },
                threatInfo: {
                    threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: [{ url }]
                }
            };

            const response = await axios.post(endpoint, payload);
            return {
                safe: !response.data.matches,
                threats: response.data.matches || [],
                checkedAt: new Date().toISOString()
            };
        } catch (error) {
            console.error('URL safety check error:', error);
            return {
                safe: true, // Default to safe if check fails
                error: "Could not verify URL safety",
                checkedAt: new Date().toISOString()
            };
        }
    }

    // Add new method to parse nslookup output
    parseNsLookupData(data) {
        const lines = data.split('\n');
        const parsed = {
            servers: [],
            addresses: [],
            name: '',
        };

        lines.forEach(line => {
            if (line.includes('Server:')) {
                parsed.servers.push(line.split(':')[1]?.trim());
            } else if (line.includes('Address:')) {
                parsed.addresses.push(line.split(':')[1]?.trim());
            } else if (line.includes('Name:')) {
                parsed.name = line.split(':')[1]?.trim();
            }
        });

        return parsed;
    }

    // Add these helper methods to your class
    isPrivateIP(ip) {
        const parts = ip.split('.');
        return (
            parts[0] === '10' ||
            (parts[0] === '172' && parts[1] >= 16 && parts[1] <= 31) ||
            (parts[0] === '192' && parts[1] === '168')
        );
    }

    async getIPGeolocation(ip) {
        try {
            // Using ip-api.com (free, no API key required)
            const response = await axios.get(`http://ip-api.com/json/${ip}`);
            if (response.data.status === 'success') {
                return {
                    country: response.data.country,
                    region: response.data.regionName,
                    city: response.data.city,
                    lat: response.data.lat,
                    lon: response.data.lon,
                    isp: response.data.isp,
                    org: response.data.org,
                    timezone: response.data.timezone
                };
            }
            return null;
        } catch (error) {
            console.error('IP Geolocation error:', error);
            return null;
        }
    }

    async getDomainAge(domain) {
        try {
            // Using WHOIS data to get domain creation date
            const { stdout } = await execAsync(`whois ${domain}`);
            const creationDate = stdout.match(/Creation Date: (.+)/i);
            if (creationDate && creationDate[1]) {
                const created = new Date(creationDate[1]);
                const now = new Date();
                const ageInDays = Math.floor((now - created) / (1000 * 60 * 60 * 24));
                return {
                    createdDate: created.toISOString(),
                    ageInDays: ageInDays,
                    ageInYears: Math.floor(ageInDays / 365)
                };
            }
            return null;
        } catch (error) {
            console.error('Domain age lookup error:', error);
            return null;
        }
    }

    async getRegistrarInfo(domain) {
        try {
            const { stdout } = await execAsync(`whois ${domain}`);
            const registrarInfo = {
                registrar: null,
                registrantOrganization: null,
                registrantCountry: null,
                updatedDate: null,
                expiryDate: null
            };

            // Extract registrar information
            const registrarMatch = stdout.match(/Registrar: (.+)/i);
            if (registrarMatch) registrarInfo.registrar = registrarMatch[1].trim();

            // Extract organization
            const orgMatch = stdout.match(/Registrant Organization: (.+)/i);
            if (orgMatch) registrarInfo.registrantOrganization = orgMatch[1].trim();

            // Extract country
            const countryMatch = stdout.match(/Registrant Country: (.+)/i);
            if (countryMatch) registrarInfo.registrantCountry = countryMatch[1].trim();

            // Extract dates
            const updateMatch = stdout.match(/Updated Date: (.+)/i);
            if (updateMatch) registrarInfo.updatedDate = new Date(updateMatch[1]).toISOString();

            const expiryMatch = stdout.match(/Registry Expiry Date: (.+)/i);
            if (expiryMatch) registrarInfo.expiryDate = new Date(expiryMatch[1]).toISOString();

            return registrarInfo;
        } catch (error) {
            console.error('Registrar info lookup error:', error);
            return null;
        }
    }

    async getCertificateInfo(url) {
        return new Promise((resolve, reject) => {
            try {
                const urlObj = new URL(url);
                const options = {
                    host: urlObj.hostname,
                    port: 443,
                    method: 'GET',
                    rejectUnauthorized: false // Allow self-signed certificates
                };

                const req = https.request(options, (res) => {
                    const cert = res.socket.getPeerCertificate();
                    if (cert) {
                        resolve({
                            subject: cert.subject,
                            issuer: cert.issuer,
                            validFrom: cert.valid_from,
                            validTo: cert.valid_to,
                            serialNumber: cert.serialNumber,
                            fingerprint: cert.fingerprint,
                            isValid: tls.checkServerIdentity(urlObj.hostname, cert),
                            subjectAltNames: cert.subjectaltname?.split(', ') || [],
                            version: cert.version
                        });
                    } else {
                        resolve(null);
                    }
                });

                req.on('error', (error) => {
                    console.error('Certificate info error:', error);
                    resolve(null);
                });

                req.end();
            } catch (error) {
                console.error('Certificate info error:', error);
                resolve(null);
            }
        });
    }

    extractExternalResources(html) {
        const $ = cheerio.load(html);
        return {
            scripts: $('script[src]').map((_, el) => $(el).attr('src')).get(),
            styles: $('link[rel="stylesheet"]').map((_, el) => $(el).attr('href')).get(),
            images: $('img[src]').map((_, el) => $(el).attr('src')).get()
        };
    }

    detectSensitiveKeywords(html) {
        const keywords = [
            'password', 'credit card', 'ssn', 'social security',
            'bank account', 'login', 'verify', 'secure'
        ];
        return keywords.filter(keyword => html.toLowerCase().includes(keyword));
    }

    calculateOverallRisk(results) {
        const riskFactors = [];
        let riskLevel = 'low';

        // Analyze domain
        if (results.domainAnalysis?.dns?.analysis?.suspiciousPatterns) {
            riskFactors.push('Suspicious DNS patterns detected');
            riskLevel = 'high';
        }

        // Analyze URL
        if (results.urlAnalysis?.safety?.urlAnalysis?.suspicious) {
            riskFactors.push('Suspicious URL characteristics');
            riskLevel = 'high';
        }

        // Analyze content
        if (results.contentAnalysis?.analysis?.contentSecurity?.hasPasswordFields) {
            riskFactors.push('Contains password fields');
            riskLevel = Math.max(riskLevel === 'high' ? 2 : 1, 1);
        }

        return {
            overall: riskLevel,
            factors: riskFactors,
            recommendations: this.generateRecommendations(riskFactors)
        };
    }

    generateRecommendations(riskFactors) {
        const recommendations = [];
        if (riskFactors.includes('Suspicious DNS patterns detected')) {
            recommendations.push('Verify domain ownership through official channels');
        }
        if (riskFactors.includes('Suspicious URL characteristics')) {
            recommendations.push('Do not enter sensitive information on this site');
        }
        return recommendations;
    }
}

export const phishingController = new PhishingController();
