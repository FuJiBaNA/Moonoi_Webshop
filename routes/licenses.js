// routes/licenses.js - License Management and API Verification Routes (แก้ไขการเข้าถึงฐานข้อมูล)
const express = require('express');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const router = express.Router();

// Function to get database pool and other dependencies
let getDbPool, config, requireAuth, requireAdmin, logActivity;

try {
    const serverModule = require('../server');
    getDbPool = serverModule.dbPool;
    config = serverModule.config;
    requireAuth = serverModule.requireAuth;
    requireAdmin = serverModule.requireAdmin;
    logActivity = serverModule.logActivity;
} catch (error) {
    console.error('Failed to import server module:', error);
    getDbPool = () => null;
    config = { moonoi_api_secret: 'fallback-secret' };
    requireAuth = (req, res, next) => next();
    requireAdmin = (req, res, next) => next();
    logActivity = () => Promise.resolve();
}

// Rate limiting for verification endpoint
const verifyLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 30, // 30 requests per minute per IP
    message: { success: false, message: 'Too many verification requests', code: 'RATE_LIMIT' }
});

// Helper function to validate IP format
function isValidIP(ip) {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(ip);
}

// Helper function to generate HMAC signature
function generateSignature(data, secret) {
    return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

// Helper function to verify HMAC signature
function verifySignature(data, signature, secret) {
    const expectedSignature = generateSignature(data, secret);
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature));
}

// POST /api/verify - Script License Verification API (Public with API Key)
router.post('/verify', verifyLimiter, async (req, res) => {
    const startTime = Date.now();
    const clientIP = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for']?.split(',')[0];

    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({
                success: false,
                message: 'Service temporarily unavailable',
                code: 'SERVICE_UNAVAILABLE'
            });
        }

        const { license_key, server_ip, server_name, trial_token, timestamp, nonce } = req.body;

        // Check API key
        const authHeader = req.headers.authorization;
        const token = authHeader && authHeader.startsWith('Bearer ')
            ? authHeader.slice(7)
            : null;
        
        if (!token || token !== config.moonoi_api_secret) {
            return res.status(401).json({
                success: false,
                message: 'Invalid API key',
                code: 'INVALID_API_KEY'
            });
        }

        // Validate required fields
        if (!server_ip || !server_name) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: server_ip, server_name',
                code: 'MISSING_FIELDS'
            });
        }

        // Validate timestamp and nonce for signature
        if (!timestamp || !nonce) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: timestamp, nonce',
                code: 'MISSING_SIGNATURE_FIELDS'
            });
        }

        // Validate IP format
        if (!isValidIP(server_ip)) {
            const errorResult = {
                success: false,
                message: 'Invalid IP address format',
                code: 'INVALID_IP'
            };
            
            await logVerificationAttempt({
                license_key: license_key || trial_token,
                server_ip,
                server_name,
                client_ip: clientIP,
                result: errorResult,
                response_time: Date.now() - startTime,
                is_trial: !!trial_token
            });
            
            return res.status(400).json(errorResult);
        }

        let verificationResult;

        // Handle Trial Token Verification
        if (trial_token) {
            verificationResult = await verifyTrialToken(trial_token, server_ip, req);
        } 
        // Handle License Key Verification
        else if (license_key) {
            verificationResult = await verifyLicenseKey(license_key, server_ip, req);
        } 
        else {
            verificationResult = {
                success: false,
                message: 'License key or trial token is required',
                code: 'MISSING_LICENSE_OR_TRIAL'
            };
        }

        // Add signature if verification successful
        if (verificationResult.success) {
            verificationResult.server_ip = server_ip;
            verificationResult.server_name = server_name;
            verificationResult.timestamp = timestamp;
            verificationResult.nonce = nonce;
            
            const signatureData = `${server_ip}|${timestamp}|${nonce}`;
            verificationResult.signature = generateSignature(signatureData, config.moonoi_api_secret);
        }

        // Log verification attempt
        await logVerificationAttempt({
            license_key: license_key || trial_token,
            server_ip,
            server_name,
            client_ip: clientIP,
            result: verificationResult,
            response_time: Date.now() - startTime,
            is_trial: !!trial_token
        });

        const statusCode = verificationResult.success ? 200 : 400;
        res.status(statusCode).json(verificationResult);

    } catch (error) {
        console.error('Verification error:', error);
        
        const errorResult = {
            success: false,
            message: 'Internal server error',
            code: 'SERVER_ERROR'
        };

        await logVerificationAttempt({
            license_key: req.body.license_key || req.body.trial_token,
            server_ip: req.body.server_ip || 'Unknown',
            server_name: req.body.server_name || 'Unknown',
            client_ip: clientIP,
            result: errorResult,
            response_time: Date.now() - startTime,
            error: error.message,
            is_trial: !!req.body.trial_token
        });

        res.status(500).json(errorResult);
    }
});

// Helper function to verify license key
async function verifyLicenseKey(licenseKey, serverIP, req) {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return {
                success: false,
                message: 'Database not available',
                code: 'DATABASE_UNAVAILABLE'
            };
        }

        // Get license details
        const [licenses] = await dbPool.execute(`
            SELECT 
                l.*,
                p.name as product_name,
                p.requires_discord,
                u.discord_id,
                u.is_blacklisted
            FROM licenses l
            JOIN products p ON l.product_id = p.id
            JOIN users u ON l.user_id = u.id
            WHERE l.license_key = ? AND l.is_active = 1
        `, [licenseKey]);

        if (licenses.length === 0) {
            return {
                success: false,
                message: 'License key not found or inactive',
                code: 'LICENSE_NOT_FOUND'
            };
        }

        const license = licenses[0];

        // Check if user is blacklisted
        if (license.is_blacklisted) {
            return {
                success: false,
                message: 'User is blacklisted',
                code: 'USER_BLACKLISTED'
            };
        }

        // Check if license has expired
        if (license.expires_at && new Date() > new Date(license.expires_at)) {
            return {
                success: false,
                message: 'License has expired',
                code: 'LICENSE_EXPIRED'
            };
        }

        // Check Discord requirement
        if (license.requires_discord && !license.discord_id) {
            return {
                success: false,
                message: 'Discord account required for this product',
                code: 'DISCORD_REQUIRED'
            };
        }

        // Handle IP verification
        if (!license.ip_address) {
            // First time use - bind IP
            await dbPool.execute(`
                UPDATE licenses 
                SET ip_address = ?, last_verification = NOW(), verification_count = verification_count + 1
                WHERE id = ?
            `, [serverIP, license.id]);

            return {
                success: true,
                message: 'License verified and IP bound',
                code: 'LICENSE_VERIFIED',
                data: {
                    product_name: license.product_name,
                    license_type: license.is_permanent ? 'permanent' : 'rental',
                    expires_at: license.expires_at,
                    first_use: true
                }
            };

        } else if (license.ip_address !== serverIP) {
            return {
                success: false,
                message: 'IP address mismatch',
                code: 'IP_MISMATCH',
                data: {
                    registered_ip: license.ip_address
                }
            };

        } else {
            // IP matches - update verification info
            await dbPool.execute(`
                UPDATE licenses 
                SET last_verification = NOW(), verification_count = verification_count + 1
                WHERE id = ?
            `, [license.id]);

            return {
                success: true,
                message: 'License verified',
                code: 'LICENSE_VERIFIED',
                data: {
                    product_name: license.product_name,
                    license_type: license.is_permanent ? 'permanent' : 'rental',
                    expires_at: license.expires_at,
                    verification_count: license.verification_count + 1
                }
            };
        }

    } catch (error) {
        console.error('License verification error:', error);
        return {
            success: false,
            message: 'Database error during verification',
            code: 'DATABASE_ERROR'
        };
    }
}

// Helper function to verify trial token
async function verifyTrialToken(trialToken, serverIP, req) {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return {
                success: false,
                message: 'Database not available',
                code: 'DATABASE_UNAVAILABLE'
            };
        }

        // Get trial details
        const [trials] = await dbPool.execute(`
            SELECT 
                t.*,
                p.name as product_name,
                u.is_blacklisted
            FROM trials t
            JOIN products p ON t.product_id = p.id
            JOIN users u ON t.user_id = u.id
            WHERE t.trial_token = ? AND t.is_active = 1
        `, [trialToken]);

        if (trials.length === 0) {
            return {
                success: false,
                message: 'Invalid or inactive trial token',
                code: 'TRIAL_INVALID'
            };
        }

        const trial = trials[0];

        // Check if user is blacklisted
        if (trial.is_blacklisted) {
            return {
                success: false,
                message: 'User is blacklisted',
                code: 'USER_BLACKLISTED'
            };
        }

        // Check if trial has expired
        if (new Date() > new Date(trial.expires_at)) {
            // Mark trial as inactive
            await dbPool.execute(`
                UPDATE trials SET is_active = 0 WHERE id = ?
            `, [trial.id]);

            return {
                success: false,
                message: 'Trial has expired',
                code: 'TRIAL_EXPIRED'
            };
        }

        // Handle IP binding for trial
        if (!trial.ip_address) {
            // First time use - bind IP
            await dbPool.execute(`
                UPDATE trials 
                SET ip_address = ?, used_at = NOW()
                WHERE id = ?
            `, [serverIP, trial.id]);

            return {
                success: true,
                message: 'Trial access granted',
                code: 'TRIAL_ACCESS_GRANTED',
                data: {
                    product_name: trial.product_name,
                    expires_at: trial.expires_at,
                    duration_hours: trial.duration_hours,
                    access_type: 'trial',
                    first_use: true
                }
            };

        } else if (trial.ip_address !== serverIP) {
            return {
                success: false,
                message: 'Trial is bound to different IP address',
                code: 'TRIAL_IP_MISMATCH'
            };

        } else {
            return {
                success: true,
                message: 'Trial access granted',
                code: 'TRIAL_ACCESS_GRANTED',
                data: {
                    product_name: trial.product_name,
                    expires_at: trial.expires_at,
                    duration_hours: trial.duration_hours,
                    access_type: 'trial'
                }
            };
        }

    } catch (error) {
        console.error('Trial verification error:', error);
        return {
            success: false,
            message: 'Database error during trial verification',
            code: 'DATABASE_ERROR'
        };
    }
}

// Helper function to log verification attempts
async function logVerificationAttempt(data) {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            console.warn('Cannot log verification attempt: Database not available');
            return;
        }

        const { license_key, server_ip, server_name, client_ip, result, response_time, error, is_trial } = data;

        // Log to database
        await dbPool.execute(`
            INSERT INTO activity_logs 
            (action, entity_type, details, ip_address, created_at)
            VALUES (?, ?, ?, ?, NOW())
        `, [
            is_trial ? 'trial_verification' : 'license_verification',
            'verification',
            JSON.stringify({
                license_key,
                server_ip,
                server_name,
                client_ip,
                result_code: result.code,
                success: result.success,
                response_time,
                error
            }),
            client_ip
        ]);

    } catch (error) {
        console.error('Error logging verification attempt:', error);
    }
}

// GET /api/licenses - Get User Licenses
router.get('/', requireAuth, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const userId = req.user.id;

        const [licenses] = await dbPool.execute(`
            SELECT 
                l.*,
                p.name as product_name,
                p.image_url as product_image,
                p.requires_discord,
                oi.created_at as purchase_date
            FROM licenses l
            JOIN products p ON l.product_id = p.id
            JOIN order_items oi ON l.order_item_id = oi.id
            WHERE l.user_id = ? AND l.is_active = 1
            ORDER BY oi.created_at DESC
        `, [userId]);

        res.json({
            success: true,
            data: licenses
        });

    } catch (error) {
        console.error('Get licenses error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/licenses/:id - Get Single License Details
router.get('/:id', requireAuth, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { id } = req.params;
        const userId = req.user.id;

        const [licenses] = await dbPool.execute(`
            SELECT 
                l.*,
                p.name as product_name,
                p.description as product_description,
                p.image_url as product_image,
                p.requires_discord,
                oi.created_at as purchase_date,
                o.order_number
            FROM licenses l
            JOIN products p ON l.product_id = p.id
            JOIN order_items oi ON l.order_item_id = oi.id
            JOIN orders o ON oi.order_id = o.id
            WHERE l.id = ? AND l.user_id = ?
        `, [id, userId]);

        if (licenses.length === 0) {
            return res.status(404).json({ error: 'License not found' });
        }

        res.json({
            success: true,
            data: licenses[0]
        });

    } catch (error) {
        console.error('Get license details error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/licenses/:id/change-ip - Change License IP
router.post('/:id/change-ip', requireAuth, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { id } = req.params;
        const { new_ip, reason } = req.body;
        const userId = req.user.id;

        if (!new_ip || !reason) {
            return res.status(400).json({ error: 'New IP and reason are required' });
        }

        if (!isValidIP(new_ip)) {
            return res.status(400).json({ error: 'Invalid IP address format' });
        }

        // Get license details
        const [licenses] = await dbPool.execute(`
            SELECT l.*, p.name as product_name
            FROM licenses l
            JOIN products p ON l.product_id = p.id
            WHERE l.id = ? AND l.user_id = ? AND l.is_active = 1
        `, [id, userId]);

        if (licenses.length === 0) {
            return res.status(404).json({ error: 'License not found' });
        }

        const license = licenses[0];

        if (!license.ip_address) {
            return res.status(400).json({ error: 'License IP not set yet' });
        }

        if (license.ip_address === new_ip) {
            return res.status(400).json({ error: 'New IP is the same as current IP' });
        }

        // Check IP change cooldown and limits
        const [settings] = await dbPool.execute(`
            SELECT setting_value FROM site_settings 
            WHERE setting_key IN ('ip_change_cooldown', 'max_ip_changes_per_day')
        `);

        const settingsMap = {};
        settings.forEach(setting => {
            settingsMap[setting.setting_key] = parseInt(setting.setting_value);
        });

        const cooldownHours = settingsMap.ip_change_cooldown || 24;
        const maxChangesPerDay = settingsMap.max_ip_changes_per_day || 3;

        // Check cooldown
        if (license.last_ip_change) {
            const timeSinceLastChange = (Date.now() - new Date(license.last_ip_change).getTime()) / (1000 * 60 * 60);
            if (timeSinceLastChange < cooldownHours) {
                const remainingHours = Math.ceil(cooldownHours - timeSinceLastChange);
                return res.status(400).json({ 
                    error: `IP change cooldown active. Please wait ${remainingHours} more hours.` 
                });
            }
        }

        // Check daily limit
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        if (license.ip_changes_today >= maxChangesPerDay) {
            return res.status(400).json({ 
                error: `Daily IP change limit (${maxChangesPerDay}) exceeded. Try again tomorrow.` 
            });
        }

        // Reset daily counter if it's a new day
        const lastChangeDate = license.last_ip_change ? new Date(license.last_ip_change) : null;
        const isNewDay = !lastChangeDate || lastChangeDate < today;

        const newChangesToday = isNewDay ? 1 : license.ip_changes_today + 1;

        // Update license IP
        await dbPool.execute(`
            UPDATE licenses 
            SET ip_address = ?, last_ip_change = NOW(), ip_changes_today = ?
            WHERE id = ?
        `, [new_ip, newChangesToday, id]);

        // Log activity
        await logActivity(userId, 'license_ip_changed', 'license', id, {
            product_name: license.product_name,
            old_ip: license.ip_address,
            new_ip: new_ip,
            reason: reason
        }, req);

        res.json({
            success: true,
            message: 'IP address changed successfully',
            data: {
                license_id: id,
                product_name: license.product_name,
                old_ip: license.ip_address,
                new_ip: new_ip,
                changes_today: newChangesToday,
                max_changes_per_day: maxChangesPerDay
            }
        });

    } catch (error) {
        console.error('Change IP error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/licenses/trials - Get User Trials
router.get('/trials', requireAuth, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const userId = req.user.id;

        const [trials] = await dbPool.execute(`
            SELECT 
                t.*,
                p.name as product_name,
                p.image_url as product_image
            FROM trials t
            JOIN products p ON t.product_id = p.id
            WHERE t.user_id = ?
            ORDER BY t.created_at DESC
        `, [userId]);

        res.json({
            success: true,
            data: trials
        });

    } catch (error) {
        console.error('Get trials error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/licenses/link-discord - Link Discord to Licenses
router.post('/link-discord', requireAuth, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { discord_user_id, discord_username } = req.body;
        const userId = req.user.id;

        if (!discord_user_id) {
            return res.status(400).json({ error: 'Discord User ID is required' });
        }

        // Update user's Discord info
        await dbPool.execute(`
            UPDATE users 
            SET discord_id = ?, discord_username = ?
            WHERE id = ?
        `, [discord_user_id, discord_username, userId]);

        // Update licenses that require Discord
        await dbPool.execute(`
            UPDATE licenses l
            JOIN products p ON l.product_id = p.id
            SET l.discord_user_id = ?
            WHERE l.user_id = ? AND p.requires_discord = 1 AND l.is_active = 1
        `, [discord_user_id, userId]);

        // Log activity
        await logActivity(userId, 'discord_linked_licenses', 'user', userId, {
            discord_user_id,
            discord_username
        }, req);

        res.json({
            success: true,
            message: 'Discord linked to licenses successfully'
        });

    } catch (error) {
        console.error('Link Discord error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;