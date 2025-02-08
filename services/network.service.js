import { exec } from 'child_process';
import { promisify } from 'util';
import  ApiError  from '../utils/ApiError.js';
import { parseString } from 'xml2js';
import fs from 'fs/promises';

const execAsync = promisify(exec);

export class NetworkService {
    async executeCommand(command) {
        try {
            const { stdout } = await execAsync(command);
            return stdout;
        } catch (error) {
            console.error(`Command execution failed: ${error.message}`);
            throw new ApiError(500, `Command execution failed: ${error.message}`);
        }
    }

    async scanDevices(target) {
        return new Promise((resolve, reject) => {
            // Use Zenmap (Nmap) to scan the network and output to XML
            const outputFile = `scan_${Date.now()}.xml`;
            const command = `nmap -sS -sV -O --stylesheet nmap.xsl -oX ${outputFile} ${target}`;
            
            exec(command, async (error, stdout, stderr) => {
                if (error) {
                    reject(new Error(`Scan failed: ${error.message}`));
                    return;
                }

                try {
                    // Read the XML file
                    const xmlData = await fs.readFile(outputFile, 'utf8');
                    
                    // Parse XML to JSON
                    parseString(xmlData, (err, result) => {
                        if (err) {
                            reject(new Error(`XML parsing failed: ${err.message}`));
                            return;
                        }

                        // Process and filter the scan results
                        const hosts = result.nmaprun.host || [];
                        const processedData = hosts.map(host => ({
                            ip: host.address?.[0]?.$?.addr,
                            status: host.status?.[0]?.$?.state,
                            ports: this.processPortInfo(host.ports?.[0]?.port),
                            os: this.processOsInfo(host.os?.[0]?.osmatch),
                            vulnerabilities: this.processVulnerabilities(host)
                        }));

                        // Clean up the XML file
                        fs.unlink(outputFile).catch(console.error);
                        
                        resolve(processedData);
                    });
                } catch (err) {
                    reject(new Error(`Failed to process scan results: ${err.message}`));
                }
            });
        });
    }

    processPortInfo(ports) {
        if (!ports) return [];
        return ports.map(port => ({
            number: port.$?.portid,
            state: port.state?.[0]?.$?.state,
            service: port.service?.[0]?.$?.name,
            version: port.service?.[0]?.$?.version
        }));
    }

    processOsInfo(osMatches) {
        if (!osMatches) return null;
        const bestMatch = osMatches[0];
        return bestMatch ? {
            name: bestMatch.$?.name,
            accuracy: bestMatch.$?.accuracy
        } : null;
    }

    processVulnerabilities(host) {
        // Extract vulnerability information from script results
        // This can be expanded based on specific script outputs
        const scripts = host.hostscript || [];
        return scripts.map(script => ({
            id: script.script?.[0]?.$?.id,
            output: script.script?.[0]?.$?.output
        }));
    }

    async getTrafficData() {
        try {
            const netstatOutput = await this.executeCommand('netstat -e');
            const lines = netstatOutput.split('\n');
            
            const trafficData = {
                trafficData: {
                    inbound: [],
                    outbound: []
                }
            };

            if (lines.length >= 3) {
                const stats = lines[2].trim().split(/\s+/);
                if (stats.length >= 2) {
                    trafficData.trafficData.inbound.push(parseInt(stats[1]));
                    trafficData.trafficData.outbound.push(parseInt(stats[2]));
                }
            }

            return trafficData;
        } catch (error) {
            throw new ApiError(500, "Failed to get traffic data");
        }
    }

    async getNetworkStats() {
        try {
            const output = await this.executeCommand('netsh interface ipv4 show interfaces');
            const lines = output.split('\n').slice(3);
            const stats = [];

            for (const line of lines) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 4) {
                    stats.push({
                        interface: parts[3],
                        bytesReceived: 0,
                        bytesSent: 0,
                        timestamp: new Date().toISOString()
                    });
                }
            }

            return stats;
        } catch (error) {
            throw new ApiError(500, "Failed to get network statistics");
        }
    }

    async getTrafficAnalysis() {
        try {
            const currentTraffic = await this.getTrafficData();
            return {
                timestamp: new Date().toISOString(),
                ...currentTraffic
            };
        } catch (error) {
            throw new ApiError(500, "Failed to analyze network traffic");
        }
    }
} 