const crypto = require('crypto');
const { promisify } = require('util');

class AIAgentSecurity {
    constructor(config = {}) {
        this.config = {
            maxRequestsPerMinute: config.maxRequestsPerMinute || 100,
            maxPayloadSize: config.maxPayloadSize || 1024 * 1024, // 1MB
            allowedOrigins: config.allowedOrigins || [],
            encryptionKey: config.encryptionKey || crypto.randomBytes(32),
            enableAuditLog: config.enableAuditLog || true,
            anomalyDetectionThreshold: config.anomalyDetectionThreshold || 0.8
        };
        
        this.requestLog = new Map();
        this.auditLog = [];
        this.knownPatterns = new Set();
        this.blacklistedIPs = new Set();
    }

    // Encrypt sensitive data
    async encryptData(data) {
        try {
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-gcm', this.config.encryptionKey, iv);
            
            let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
            encrypted += cipher.final('hex');
            
            const authTag = cipher.getAuthTag();
            
            return {
                encrypted,
                iv: iv.toString('hex'),
                authTag: authTag.toString('hex')
            };
        } catch (error) {
            this.logSecurityEvent('encryption_failure', { error: error.message });
            throw new Error('Encryption failed');
        }
    }

    // Decrypt sensitive data
    async decryptData(encryptedData) {
        try {
            const decipher = crypto.createDecipheriv(
                'aes-256-gcm',
                this.config.encryptionKey,
                Buffer.from(encryptedData.iv, 'hex')
            );
            
            decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
            
            let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            return JSON.parse(decrypted);
        } catch (error) {
            this.logSecurityEvent('decryption_failure', { error: error.message });
            throw new Error('Decryption failed');
        }
    }

    // Rate limiting check
    checkRateLimit(clientId) {
        const now = Date.now();
        const minuteAgo = now - 60000;
        
        if (!this.requestLog.has(clientId)) {
            this.requestLog.set(clientId, []);
        }
        
        const clientRequests = this.requestLog.get(clientId);
        const recentRequests = clientRequests.filter(time => time > minuteAgo);
        
        this.requestLog.set(clientId, recentRequests);
        
        if (recentRequests.length >= this.config.maxRequestsPerMinute) {
            this.logSecurityEvent('rate_limit_exceeded', { clientId });
            return false;
        }
        
        recentRequests.push(now);
        return true;
    }

    // Input validation and sanitization
    validateInput(input) {
        if (!input || typeof input !== 'object') {
            throw new Error('Invalid input format');
        }

        if (JSON.stringify(input).length > this.config.maxPayloadSize) {
            throw new Error('Payload size exceeds maximum allowed size');
        }

        // Sanitize and validate each field
        const sanitized = {};
        for (let [key, value] of Object.entries(input)) {
            // Remove any potential XSS or injection patterns
            if (typeof value === 'string') {
                value = this.sanitizeString(value);
            }
            sanitized[key] = value;
        }

        return sanitized;
    }

    // String sanitization helper
    sanitizeString(str) {
        return str
            .replace(/<[^>]*>/g, '') // Remove HTML tags
            .replace(/[;<>&]/g, '') // Remove potential dangerous characters
            .trim();
    }

    // Anomaly detection
    detectAnomalies(data, context) {
        const anomalyScore = this.calculateAnomalyScore(data, context);
        
        if (anomalyScore > this.config.anomalyDetectionThreshold) {
            this.logSecurityEvent('anomaly_detected', {
                score: anomalyScore,
                context
            });
            return true;
        }
        
        return false;
    }

    // Calculate anomaly score based on various factors
    calculateAnomalyScore(data, context) {
        let score = 0;
        const patterns = this.extractPatterns(data);
        
        // Check for known malicious patterns
        for (const pattern of patterns) {
            if (!this.knownPatterns.has(pattern)) {
                score += 0.1;
            }
        }
        
        // Check for unusual timing
        if (context.timestamp) {
            const hour = new Date(context.timestamp).getHours();
            if (hour >= 23 || hour <= 4) {
                score += 0.2;
            }
        }
        
        // Check for unusual data volumes
        if (JSON.stringify(data).length > this.config.maxPayloadSize / 2) {
            score += 0.3;
        }
        
        return score;
    }

    // Extract patterns from data for analysis
    extractPatterns(data) {
        const patterns = new Set();
        const dataStr = JSON.stringify(data);
        
        // Extract common patterns or signatures
        const regex = /[a-zA-Z0-9_-]{10,}/g;
        const matches = dataStr.match(regex) || [];
        
        matches.forEach(match => patterns.add(match));
        return patterns;
    }

    // Security event logging
    logSecurityEvent(eventType, details) {
        const event = {
            timestamp: new Date().toISOString(),
            type: eventType,
            details,
        };
        
        this.auditLog.push(event);
        
        // If audit log is enabled, log to console as well
        if (this.config.enableAuditLog) {
            console.log('Security Event:', event);
        }
        
        // Implement additional logging logic (e.g., to a security monitoring service)
    }

    // Generate secure random tokens
    generateSecureToken(length = 32) {
        return crypto.randomBytes(length).toString('hex');
    }

    // Verify request origin
    verifyOrigin(origin) {
        return this.config.allowedOrigins.includes(origin);
    }

    // Check for common attack patterns
    detectAttackPatterns(request) {
        const patterns = [
            /union\s+select/i,
            /exec\s*\(/i,
            /<script>/i,
            /document\s*\.\s*cookie/i,
            /eval\s*\(/i
        ];

        const requestStr = JSON.stringify(request).toLowerCase();
        
        for (const pattern of patterns) {
            if (pattern.test(requestStr)) {
                this.logSecurityEvent('attack_pattern_detected', {
                    pattern: pattern.toString(),
                });
                return true;
            }
        }
        
        return false;
    }

    // Get security audit log
    getAuditLog() {
        return [...this.auditLog];
    }

    // Clear old security logs
    clearOldLogs(maxAge = 7 * 24 * 60 * 60 * 1000) { // Default 7 days
        const now = Date.now();
        this.auditLog = this.auditLog.filter(event => {
            const eventTime = new Date(event.timestamp).getTime();
            return now - eventTime < maxAge;
        });
    }
}

module.exports = AIAgentSecurity;

// Example usage:
/*
const security = new AIAgentSecurity({
    maxRequestsPerMinute: 100,
    allowedOrigins: ['https://trusted-domain.com'],
    enableAuditLog: true
});

// Encrypt sensitive data
const encrypted = await security.encryptData({ sensitive: 'data' });

// Validate input
const sanitizedInput = security.validateInput(userInput);

// Check rate limiting
if (security.checkRateLimit('client123')) {
    // Process request
}

// Detect anomalies
if (security.detectAnomalies(data, { timestamp: Date.now() })) {
    // Handle anomaly
}
*/