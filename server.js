import express from 'express';
import crypto from 'crypto';
import axios from 'axios';
import https from 'https';
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

// ES module equivalents for __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables
dotenv.config();

class VPNServer {
    constructor() {
        this.app = express();
        this.port = process.env.SERVER_PORT || 3000;
        this.encryptionKey = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
        
        this.setupMiddleware();
        this.setupRoutes();
        
        // Configure axios for both HTTP and HTTPS with better error handling
        this.httpAgent = new http.Agent({ keepAlive: true });
        this.httpsAgent = new https.Agent({ 
            keepAlive: true,
            rejectUnauthorized: false // For development - in production, set to true
        });
    }

    setupMiddleware() {
        // Parse raw binary data
        this.app.use('/tunnel', express.raw({ type: 'application/octet-stream', limit: '50mb' }));

        // CORS headers
        this.app.use((req, res, next) => {
            res.header('Access-Control-Allow-Origin', '*');
            res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
            res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, X-Tunnel-Client');
            next();
        });
    }

    encrypt(data) {
        try {
            const iv = crypto.randomBytes(12);
            const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);
            
            let encrypted = cipher.update(data, 'utf8');
            encrypted = Buffer.concat([encrypted, cipher.final()]);
            
            const authTag = cipher.getAuthTag();
            const result = Buffer.concat([iv, authTag, encrypted]);
            
            return result;
        } catch (error) {
            throw error;
        }
    }

    decrypt(encryptedData) {
        try {
            const iv = encryptedData.slice(0, 12);
            const authTag = encryptedData.slice(12, 28);
            const encrypted = encryptedData.slice(28);
            
            const decipher = crypto.createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
            decipher.setAuthTag(authTag);
            
            let decrypted = decipher.update(encrypted, null, 'utf8');
            decrypted += decipher.final('utf8');
            
            return decrypted;
        } catch (error) {
            throw error;
        }
    }

    async executeHttpRequest(requestData) {
        try {
            const { method, url, headers, body } = requestData;

            // Determine if it's HTTP or HTTPS
            const isHttps = url.toLowerCase().startsWith('https://');
            
            const axiosConfig = {
                method: method.toLowerCase(),
                url: url,
                headers: headers || {},
                timeout: 30000,
                maxRedirects: 5,
                validateStatus: () => true, // Accept all status codes
                httpAgent: this.httpAgent,
                httpsAgent: this.httpsAgent
            };

            // Add body for methods that support it
            if (['POST', 'PUT', 'PATCH'].includes(method.toUpperCase()) && body) {
                if (typeof body === 'object') {
                    axiosConfig.data = body;
                    axiosConfig.headers['Content-Type'] = axiosConfig.headers['Content-Type'] || 'application/json';
                } else {
                    axiosConfig.data = body;
                }
            }
            
            const response = await axios(axiosConfig);

            return {
                status: response.status,
                statusText: response.statusText,
                headers: response.headers,
                body: response.data
            };

        } catch (error) {
            // Return error response instead of throwing
            return {
                status: error.response?.status || 500,
                statusText: error.response?.statusText || 'Internal Server Error',
                headers: error.response?.headers || {},
                body: {
                    error: true,
                    message: error.message,
                    code: error.code || 'UNKNOWN_ERROR'
                }
            };
        }
    }

    setupRoutes() {
        // Main tunnel endpoint
        this.app.post('/tunnel', async (req, res) => {
            try {
                // Validate request
                if (!req.body || req.body.length === 0) {
                    return res.status(400).json({ error: 'Empty request body' });
                }

                // Decrypt request
                const decryptedData = this.decrypt(req.body);
                const requestData = JSON.parse(decryptedData);

                // Execute the HTTP request
                const response = await this.executeHttpRequest(requestData);

                // Encrypt response
                const responseJson = JSON.stringify(response);
                const encryptedResponse = this.encrypt(responseJson);

                // Send encrypted response
                res.set('Content-Type', 'application/octet-stream');
                res.send(encryptedResponse);

            } catch (error) {
                res.status(500).json({ error: 'Internal server error' });
            }
        });

        // Health check endpoint
        this.app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                uptime: process.uptime()
            });
        });

        // Server info endpoint
        this.app.get('/info', (req, res) => {
            res.json({
                name: 'VPN Tunnel Server',
                version: '1.0.0',
                supportedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
                supportedProtocols: ['HTTP', 'HTTPS']
            });
        });

        // 404 handler
        this.app.use('*', (req, res) => {
            res.status(404).json({ error: 'Route not found' });
        });

        // Error handler
        this.app.use((error, req, res, next) => {
            res.status(500).json({ error: 'Internal server error' });
        });
    }

    start() {
        this.app.listen(this.port, () => {
            console.log(`VPN Tunnel Server started on port ${this.port}`);
            console.log(`Health check: http://localhost:${this.port}/health`);
            console.log(`Server info: http://localhost:${this.port}/info`);
            console.log(`Tunnel endpoint: http://localhost:${this.port}/tunnel`);
        });
    }

    // Graceful shutdown
    setupGracefulShutdown() {
        process.on('SIGTERM', () => {
            process.exit(0);
        });

        process.on('SIGINT', () => {
            process.exit(0);
        });
    }
}

// Create and start server
const server = new VPNServer();
server.setupGracefulShutdown();

// Check if this is the main module (equivalent to require.main === module)
if (import.meta.url === `file://${process.argv[1]}`) {
    server.start();
}

export default VPNServer;
