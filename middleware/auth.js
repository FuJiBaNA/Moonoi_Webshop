// middleware/auth.js - Fixed Authentication Middleware
const jwt = require('jsonwebtoken');

// Configuration variables
let dbPool = null;
let config = { jwt_secret: 'fallback-secret' };

// Initialize middleware with dependencies
function initializeMiddleware(pool, conf) {
    dbPool = pool;
    config = conf;
    console.log('✅ Auth middleware initialized');
}

// Basic token verification (without database check)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            success: false,
            error: 'Access token required' 
        });
    }

    try {
        const user = jwt.verify(token, config.jwt_secret);
        req.user = user;
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                success: false,
                error: 'Token has expired' 
            });
        } else if (err.name === 'JsonWebTokenError') {
            return res.status(403).json({ 
                success: false,
                error: 'Invalid token' 
            });
        } else {
            return res.status(403).json({ 
                success: false,
                error: 'Token verification failed' 
            });
        }
    }
};

// Full authentication with database verification
const requireAuth = async (req, res, next) => {
    try {
        // Check if user is already authenticated via Passport session
        if (req.isAuthenticated && req.isAuthenticated()) {
            return next();
        }
        
        // Check for JWT token
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ 
                success: false,
                error: 'Authentication required' 
            });
        }
        
        // Verify JWT token
        let decoded;
        try {
            decoded = jwt.verify(token, config.jwt_secret);
        } catch (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ 
                    success: false,
                    error: 'Token has expired' 
                });
            } else {
                return res.status(401).json({ 
                    success: false,
                    error: 'Invalid token' 
                });
            }
        }
        
        // Check database connection
        if (!dbPool) {
            return res.status(503).json({ 
                success: false,
                error: 'Authentication service unavailable' 
            });
        }
        
        // Get user from database
        const [users] = await dbPool.execute(
            'SELECT * FROM users WHERE id = ? AND is_active = 1', 
            [decoded.id]
        );
        
        if (users.length === 0) {
            return res.status(401).json({ 
                success: false,
                error: 'User not found or inactive' 
            });
        }
        
        const user = users[0];
        
        // Check if user is blacklisted
        if (user.is_blacklisted) {
            return res.status(403).json({ 
                success: false,
                error: 'Account has been suspended' 
            });
        }
        
        // Add user to request object
        req.user = user;
        next();
        
    } catch (error) {
        console.error('Authentication middleware error:', error);
        return res.status(500).json({ 
            success: false,
            error: 'Authentication system error' 
        });
    }
};

// Admin permission check
const requireAdmin = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({ 
            success: false,
            error: 'Authentication required' 
        });
    }
    
    if (!['admin', 'superadmin'].includes(req.user.role)) {
        return res.status(403).json({ 
            success: false,
            error: 'Admin access required' 
        });
    }
    
    next();
};

// Super admin permission check
const requireSuperAdmin = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({ 
            success: false,
            error: 'Authentication required' 
        });
    }
    
    if (req.user.role !== 'superadmin') {
        return res.status(403).json({ 
            success: false,
            error: 'Super admin access required' 
        });
    }
    
    next();
};

// Optional authentication (doesn't fail if no token)
const optionalAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
            // No token provided, continue without user
            req.user = null;
            return next();
        }
        
        // Verify token
        const decoded = jwt.verify(token, config.jwt_secret);
        
        if (dbPool) {
            // Get user from database if pool is available
            const [users] = await dbPool.execute(
                'SELECT * FROM users WHERE id = ? AND is_active = 1', 
                [decoded.id]
            );
            
            req.user = users.length > 0 ? users[0] : null;
        } else {
            // Use token data if no database
            req.user = decoded;
        }
        
        next();
        
    } catch (error) {
        // Token invalid, continue without user
        req.user = null;
        next();
    }
};

// Activity logging function
const logActivity = async (userId, action, entityType = null, entityId = null, details = null, req = null) => {
    try {
        if (!dbPool) {
            console.warn('Cannot log activity: Database not available');
            return;
        }
        
        const ipAddress = req ? (req.ip || req.connection.remoteAddress) : null;
        const userAgent = req ? req.get('User-Agent') : null;
        
        await dbPool.execute(`
            INSERT INTO activity_logs (user_id, action, entity_type, entity_id, ip_address, user_agent, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [
            userId, 
            action, 
            entityType, 
            entityId, 
            ipAddress, 
            userAgent, 
            JSON.stringify(details)
        ]);
        
    } catch (error) {
        console.error('Failed to log activity:', error);
    }
};

// Helper function to generate JWT token
const generateToken = (user) => {
    return jwt.sign(
        { 
            id: user.id, 
            username: user.username, 
            email: user.email, 
            role: user.role 
        }, 
        config.jwt_secret, 
        { expiresIn: '24h' }
    );
};

// Helper function to verify and refresh token
const verifyAndRefreshToken = async (token) => {
    try {
        // Try to verify current token
        const decoded = jwt.verify(token, config.jwt_secret);
        
        // Check if token is close to expiry (less than 1 hour left)
        const now = Math.floor(Date.now() / 1000);
        const timeToExpiry = decoded.exp - now;
        
        if (timeToExpiry < 3600) { // Less than 1 hour
            // Generate new token
            const newToken = generateToken(decoded);
            return { token: newToken, refreshed: true };
        }
        
        return { token, refreshed: false };
        
    } catch (error) {
        throw new Error('Invalid token');
    }
};

// Rate limiting middleware for authentication endpoints
const authRateLimit = (windowMs = 15 * 60 * 1000, max = 5) => {
    const requests = new Map();
    
    return (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress;
        const now = Date.now();
        
        // Clean old entries
        for (const [key, data] of requests.entries()) {
            if (now - data.firstRequest > windowMs) {
                requests.delete(key);
            }
        }
        
        // Get current request count for IP
        const requestData = requests.get(ip) || { count: 0, firstRequest: now };
        
        if (requestData.count >= max) {
            return res.status(429).json({
                success: false,
                error: 'Too many authentication attempts, please try again later.',
                retryAfter: Math.ceil((requestData.firstRequest + windowMs - now) / 1000)
            });
        }
        
        // Update request count
        requestData.count++;
        requests.set(ip, requestData);
        
        next();
    };
};

// Middleware to check if user owns resource
const requireOwnership = (getResourceUserId) => {
    return async (req, res, next) => {
        try {
            if (!req.user) {
                return res.status(401).json({ 
                    success: false,
                    error: 'Authentication required' 
                });
            }
            
            // Skip ownership check for admins
            if (['admin', 'superadmin'].includes(req.user.role)) {
                return next();
            }
            
            // Get resource user ID
            const resourceUserId = await getResourceUserId(req);
            
            if (!resourceUserId) {
                return res.status(404).json({ 
                    success: false,
                    error: 'Resource not found' 
                });
            }
            
            if (resourceUserId !== req.user.id) {
                return res.status(403).json({ 
                    success: false,
                    error: 'Access denied: You can only access your own resources' 
                });
            }
            
            next();
            
        } catch (error) {
            console.error('Ownership check error:', error);
            return res.status(500).json({ 
                success: false,
                error: 'Permission check failed' 
            });
        }
    };
};

// Middleware to validate request data
const validateRequest = (schema) => {
    return (req, res, next) => {
        const { error } = schema.validate(req.body);
        
        if (error) {
            return res.status(400).json({
                success: false,
                error: 'Validation failed',
                details: error.details.map(detail => detail.message)
            });
        }
        
        next();
    };
};

// Helper function to sanitize user data (remove sensitive fields)
const sanitizeUser = (user) => {
    if (!user) return null;
    
    const { password, ...sanitizedUser } = user;
    return sanitizedUser;
};

// Helper function to check if user has permission
const hasPermission = (user, permission) => {
    if (!user) return false;
    
    const permissions = {
        superadmin: ['*'],
        admin: [
            'users.read', 
            'users.update', 
            'products.manage', 
            'orders.manage', 
            'payments.manage',
            'analytics.read'
        ],
        user: [
            'profile.read', 
            'profile.update', 
            'orders.read', 
            'products.read'
        ]
    };
    
    const userPermissions = permissions[user.role] || [];
    
    return userPermissions.includes('*') || userPermissions.includes(permission);
};

module.exports = {
    initializeMiddleware,
    authenticateToken,
    requireAuth,
    requireAdmin,
    requireSuperAdmin,
    optionalAuth,
    logActivity,
    generateToken,
    verifyAndRefreshToken,
    authRateLimit,
    requireOwnership,
    validateRequest,
    sanitizeUser,
    hasPermission
};