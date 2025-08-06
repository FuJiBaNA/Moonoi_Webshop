// routes/auth.js - Authentication Routes (แก้ไขการเข้าถึงฐานข้อมูล)
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const passport = require('passport');

const router = express.Router();

// Function to get database pool and other dependencies
let getDbPool, config, requireAuth, logActivity;

try {
    const serverModule = require('../server');
    getDbPool = serverModule.dbPool;
    config = serverModule.config;
    requireAuth  = serverModule.requireAuth;
    logActivity = serverModule.logActivity;
} catch (error) {
    console.error('Failed to import server module:', error);
    getDbPool = () => null;
    config = { jwt_secret: 'fallback-secret' };
    requireAuth  = (req, res, next) => next();
    logActivity = () => Promise.resolve();
}

// Rate limiting for authentication endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: { error: 'Too many authentication attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

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

// Helper function to sanitize user data
const sanitizeUser = (user) => {
    const { password, ...sanitizedUser } = user;
    return sanitizedUser;
};

// POST /api/auth/register - User Registration
router.post('/register', authLimiter, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { username, email, password, confirmPassword } = req.body;

        // Validation
        if (!username || !email || !password || !confirmPassword) {
            return res.status(400).json({ 
                error: 'All fields are required' 
            });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ 
                error: 'Passwords do not match' 
            });
        }

        if (password.length < 6) {
            return res.status(400).json({ 
                error: 'Password must be at least 6 characters long' 
            });
        }

        // Check if username or email already exists
        const [existingUsers] = await dbPool.execute(
            'SELECT id, username, email FROM users WHERE username = ? OR email = ?',
            [username, email]
        );

        if (existingUsers.length > 0) {
            const existingUser = existingUsers[0];
            if (existingUser.username === username) {
                return res.status(400).json({ error: 'Username already exists' });
            }
            if (existingUser.email === email) {
                return res.status(400).json({ error: 'Email already exists' });
            }
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Create user
        const [result] = await dbPool.execute(`
            INSERT INTO users (username, email, password, credits, created_at)
            VALUES (?, ?, ?, 0, NOW())
        `, [username, email, hashedPassword]);

        // Get the created user
        const [newUser] = await dbPool.execute(
            'SELECT * FROM users WHERE id = ?',
            [result.insertId]
        );

        const user = newUser[0];
        const token = generateToken(user);

        // Log activity
        await logActivity(user.id, 'user_register', 'user', user.id, { username, email }, req);

        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            token,
            user: sanitizeUser(user)
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/auth/login - User Login
router.post('/login', authLimiter, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { login, password } = req.body; // login can be username or email

        if (!login || !password) {
            return res.status(400).json({ 
                error: 'Username/Email and password are required' 
            });
        }

        // Find user by username or email
        const [users] = await dbPool.execute(`
            SELECT * FROM users 
            WHERE (username = ? OR email = ?) AND is_active = 1
        `, [login, login]);

        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = users[0];

        // Check if user is blacklisted
        if (user.is_blacklisted) {
            return res.status(403).json({ error: 'Account has been suspended' });
        }

        // Verify password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Update last login
        await dbPool.execute(
            'UPDATE users SET last_login = NOW() WHERE id = ?',
            [user.id]
        );

        const token = generateToken(user);

        // Log activity
        await logActivity(user.id, 'user_login', 'user', user.id, { login_method: 'password' }, req);

        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: sanitizeUser(user)
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/auth/forgot-password - Request Password Reset
router.post('/forgot-password', authLimiter, async (req, res) => {
    try {
        const dbPool = getDbPool();
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        // Always return success message for security
        res.json({
            success: true,
            message: 'If the email exists, a password reset link has been sent'
        });

        if (dbPool) {
            const [users] = await dbPool.execute(
                'SELECT id, username, email FROM users WHERE email = ? AND is_active = 1',
                [email]
            );

            if (users.length > 0) {
                // In a real application, you would send an email here
                // For now, we'll just log it
                console.log(`Password reset requested for user: ${users[0].username} (${email})`);
                
                await logActivity(users[0].id, 'password_reset_request', 'user', users[0].id, { email }, req);
            }
        }

    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/auth/change-password - Change Password (Authenticated)
router.post('/change-password', async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'Access token required' });
        }

        const decoded = jwt.verify(token, config.jwt_secret);
        const { currentPassword, newPassword, confirmPassword } = req.body;

        if (!currentPassword || !newPassword || !confirmPassword) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({ error: 'New passwords do not match' });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'New password must be at least 6 characters long' });
        }

        // Get user
        const [users] = await dbPool.execute('SELECT * FROM users WHERE id = ?', [decoded.id]);
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = users[0];

        // Verify current password
        const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
        if (!isCurrentPasswordValid) {
            return res.status(400).json({ error: 'Current password is incorrect' });
        }

        // Hash new password
        const hashedNewPassword = await bcrypt.hash(newPassword, 12);

        // Update password
        await dbPool.execute(
            'UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?',
            [hashedNewPassword, user.id]
        );

        // Log activity
        await logActivity(user.id, 'password_change', 'user', user.id, {}, req);

        res.json({
            success: true,
            message: 'Password changed successfully'
        });

    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: 'Invalid token' });
        }
        console.error('Change password error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/auth/me - Get Current User Info
router.get('/me', async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'Access token required' });
        }

        const decoded = jwt.verify(token, config.jwt_secret);
        
        const [users] = await dbPool.execute(`
            SELECT u.*, 
                   COUNT(DISTINCT o.id) as total_orders,
                   COUNT(DISTINCT l.id) as active_licenses
            FROM users u
            LEFT JOIN orders o ON u.id = o.user_id AND o.payment_status = 'completed'
            LEFT JOIN licenses l ON u.id = l.user_id AND l.is_active = 1
            WHERE u.id = ?
            GROUP BY u.id
        `, [decoded.id]);

        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = users[0];

        if (user.is_blacklisted) {
            return res.status(403).json({ error: 'Account has been suspended' });
        }

        res.json({
            success: true,
            user: sanitizeUser(user)
        });

    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: 'Invalid token' });
        }
        console.error('Get user info error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/auth/refresh-token - Refresh JWT Token
router.post('/refresh-token', async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'Access token required' });
        }

        // Verify token (even if expired)
        const decoded = jwt.verify(token, config.jwt_secret, { ignoreExpiration: true });
        
        // Get user
        const [users] = await dbPool.execute(
            'SELECT * FROM users WHERE id = ? AND is_active = 1',
            [decoded.id]
        );

        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = users[0];

        if (user.is_blacklisted) {
            return res.status(403).json({ error: 'Account has been suspended' });
        }

        // Generate new token
        const newToken = generateToken(user);

        res.json({
            success: true,
            token: newToken,
            user: sanitizeUser(user)
        });

    } catch (error) {
        console.error('Refresh token error:', error);
        res.status(401).json({ error: 'Invalid token' });
    }
});

// OAuth Routes

// GET /auth/google - Google OAuth
router.get('/google', (req, res, next) => {
    // Store return URL in session
    if (req.query.returnUrl) {
        req.session.returnUrl = req.query.returnUrl;
    }
    next();
}, passport.authenticate('google', { scope: ['profile', 'email'] }));

// GET /auth/google/callback - Google OAuth Callback
router.get('/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login?error=google_auth_failed' }),
    async (req, res) => {
        try {
            const token = generateToken(req.user);
            
            // Log activity
            await logActivity(req.user.id, 'user_login', 'user', req.user.id, { login_method: 'google' }, req);
            
            const returnUrl = req.session.returnUrl || '/dashboard';
            delete req.session.returnUrl;
            
            // Redirect with token
            res.redirect(`${returnUrl}?token=${token}`);
        } catch (error) {
            console.error('Google OAuth callback error:', error);
            res.redirect('/login?error=auth_failed');
        }
    }
);

// GET /auth/discord - Discord OAuth
router.get('/discord', (req, res, next) => {
    // Store return URL in session
    if (req.query.returnUrl) {
        req.session.returnUrl = req.query.returnUrl;
    }
    next();
}, passport.authenticate('discord'));

// GET /auth/discord/callback - Discord OAuth Callback
router.get('/discord/callback',
    passport.authenticate('discord', { failureRedirect: '/login?error=discord_auth_failed' }),
    async (req, res) => {
        try {
            const token = generateToken(req.user);
            
            // Log activity
            await logActivity(req.user.id, 'user_login', 'user', req.user.id, { login_method: 'discord' }, req);
            
            const returnUrl = req.session.returnUrl || '/dashboard';
            delete req.session.returnUrl;
            
            // Redirect with token
            res.redirect(`${returnUrl}?token=${token}`);
        } catch (error) {
            console.error('Discord OAuth callback error:', error);
            res.redirect('/login?error=auth_failed');
        }
    }
);

// POST /api/auth/link-discord - Link Discord Account
router.post('/link-discord', async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'Access token required' });
        }

        const decoded = jwt.verify(token, config.jwt_secret);
        const { discordUserId, discordUsername } = req.body;

        if (!discordUserId) {
            return res.status(400).json({ error: 'Discord User ID is required' });
        }

        // Check if Discord ID is already linked to another account
        const [existingLink] = await dbPool.execute(
            'SELECT id, username FROM users WHERE discord_id = ? AND id != ?',
            [discordUserId, decoded.id]
        );

        if (existingLink.length > 0) {
            return res.status(400).json({ 
                error: 'Discord account is already linked to another user' 
            });
        }

        // Update user with Discord info
        await dbPool.execute(`
            UPDATE users 
            SET discord_id = ?, discord_username = ?, updated_at = NOW()
            WHERE id = ?
        `, [discordUserId, discordUsername, decoded.id]);

        // Log activity
        await logActivity(decoded.id, 'discord_link', 'user', decoded.id, { discordUserId, discordUsername }, req);

        res.json({
            success: true,
            message: 'Discord account linked successfully'
        });

    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: 'Invalid token' });
        }
        console.error('Link Discord error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/auth/unlink-discord - Unlink Discord Account
router.post('/unlink-discord', async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'Access token required' });
        }

        const decoded = jwt.verify(token, config.jwt_secret);

        // Update user to remove Discord info
        await dbPool.execute(`
            UPDATE users 
            SET discord_id = NULL, discord_username = NULL, updated_at = NOW()
            WHERE id = ?
        `, [decoded.id]);

        // Log activity
        await logActivity(decoded.id, 'discord_unlink', 'user', decoded.id, {}, req);

        res.json({
            success: true,
            message: 'Discord account unlinked successfully'
        });

    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: 'Invalid token' });
        }
        console.error('Unlink Discord error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/auth/logout - Logout (Optional - client-side token removal is sufficient)
router.post('/logout', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (token) {
            try {
                const decoded = jwt.verify(token, config.jwt_secret);
                await logActivity(decoded.id, 'user_logout', 'user', decoded.id, {}, req);
            } catch (error) {
                // Token might be invalid, but that's okay for logout
            }
        }

        res.json({
            success: true,
            message: 'Logged out successfully'
        });

    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/auth/forgot-password - ขอรีเซ็ตรหัสผ่าน
router.post('/forgot-password', async (req, res) => {
    try {
        const dbPool = getDbPool();
        const { email } = req.body;
        if (!email) return res.status(400).json({ success: false, error: 'Email is required' });

        const [users] = await dbPool.execute('SELECT id, email FROM users WHERE email = ? AND is_active = 1', [email]);
        if (users.length === 0) {
            return res.json({ success: true, message: 'If an account exists, a reset link has been sent.' });
        }

        const user = users[0];
        const resetToken = crypto.randomBytes(32).toString('hex');
        const passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
        const passwordResetExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

        await dbPool.execute(
            'UPDATE users SET password_reset_token = ?, password_reset_expires = ? WHERE id = ?',
            [passwordResetToken, passwordResetExpires, user.id]
        );

        await sendPasswordResetEmail(user.email, resetToken);
        logActivity(user.id, 'password_reset_request', 'user', user.id, {}, req);
        res.json({ success: true, message: 'If an account exists, a reset link has been sent.' });

    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// POST /api/auth/reset-password - ตั้งรหัสผ่านใหม่
router.post('/reset-password', async (req, res) => {
    try {
        const dbPool = getDbPool();
        const { token, password } = req.body;
        if (!token || !password) return res.status(400).json({ success: false, error: 'Token and new password are required' });
        if (password.length < 6) return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });

        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
        const [users] = await dbPool.execute('SELECT * FROM users WHERE password_reset_token = ? AND password_reset_expires > NOW()', [hashedToken]);
        if (users.length === 0) return res.status(400).json({ success: false, error: 'Token is invalid or has expired' });

        const user = users[0];
        const hashedPassword = await bcrypt.hash(password, 12);

        await dbPool.execute('UPDATE users SET password = ?, password_reset_token = NULL, password_reset_expires = NULL WHERE id = ?', [hashedPassword, user.id]);
        logActivity(user.id, 'password_reset_success', 'user', user.id, {}, req);
        res.json({ success: true, message: 'Password has been reset successfully.' });

    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});


// POST /api/auth/unlink-discord - ยกเลิกการเชื่อมต่อ Discord
router.post('/unlink-discord', requireAuth, async (req, res) => {
    try {
        const dbPool = getDbPool();
        const userId = req.user.id;
        
        await dbPool.execute(
            'UPDATE users SET discord_id = NULL, discord_username = NULL WHERE id = ?',
            [userId]
        );

        logActivity(userId, 'discord_unlinked', 'user', userId, {}, req);
        res.json({ success: true, message: 'Discord account unlinked successfully.' });

    } catch (error) {
        console.error('Unlink Discord error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

module.exports = router;