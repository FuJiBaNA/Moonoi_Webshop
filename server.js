// server.js - Fixed for MariaDB + Route Mounting Issues
require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');

const app = express();

// Configuration
const config = {
    port: process.env.PORT || 3000,
    jwt_secret: process.env.JWT_SECRET || 'jwt-key-default-change-this',

    // Database Configuration
    database: {
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME || 'scriptshop_db',
        port: process.env.DB_PORT || 3306,
        charset: 'utf8mb4',
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0,
        connectTimeout: 60000,
        timeout: 60000
    },

    // API Keys
    truewallet_api_key: process.env.TRUEWALLET_API_KEY || 'BYShop-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    slip_api_key: process.env.SLIP_API_KEY || 'BYShop-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    moonoi_api_secret: process.env.MOONOI_API_SECRET || 'MoonoiXyI08BJdi3RdOB24YYpNVDir5UeHpFUjz21cJny4Htbtj5Gq9rchTIp1zC7p49D5zFw8QIhgtiW3sdjBV8QcMFa6ClnH6HsF3wqkV8TfmW723FrvyQ1I1dSiai',

    discord: {
        client_id: process.env.DISCORD_CLIENT_ID || 'your-discord-client-id',
        client_secret: process.env.DISCORD_CLIENT_SECRET || 'your-discord-client-secret'
    },

    // Site Configuration
    site_name: process.env.SITE_NAME || 'Moonoi Developer',
    site_url: process.env.SITE_URL || 'http://localhost:3000',
    admin_email: process.env.ADMIN_EMAIL || 'admin@scriptshop.com'
};

// Global variables
let dbPool = null;
let isDbConnected = false;

// Security and Performance Middleware
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));
app.use(compression());

// Logging
if (process.env.NODE_ENV === 'production') {
    app.use(morgan('combined'));
} else {
    app.use(morgan('dev'));
}

// CORS Configuration
app.use(cors({
    origin: process.env.NODE_ENV === 'production'
        ? [config.site_url]
        : ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:3001'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Body parsing middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Static files
app.use(express.static('public'));
/* Serve only public product images, not downloadable files */
app.use('/uploads/products', express.static('uploads/products'));

// Trust proxy configuration - FIXED
if (process.env.NODE_ENV === 'production') {
    const trustedProxies = process.env.TRUSTED_PROXIES ?
        process.env.TRUSTED_PROXIES.split(',').map(ip => ip.trim()) :
        ['127.0.0.1', '::1'];
    app.set('trust proxy', trustedProxies);
} else {
    app.set('trust proxy', ['127.0.0.1', '::1']);
}

// Rate limiting configuration
const skipAssets = (req, res) => {
    const assetPaths = ['/css', '/js', '/images', '/fonts'];
    return assetPaths.some(path => req.path.startsWith(path));
};

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 200, // Limit each IP to 200 requests per window
    message: { success: false, error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: skipAssets,
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10, // Limit auth attempts to 10 per 15 mins
    message: { success: false, error: 'Too many authentication attempts, please try again.' },
});

const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 60, // Limit API requests to 60 per minute
    message: { success: false, error: 'API rate limit exceeded.' },
    skip: skipAssets,
});

// Apply rate limiters to specific routes
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/', apiLimiter);
app.use(generalLimiter);

// Middleware Functions
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

const requireAuth = async (req, res, next) => {
    try {
        if (req.isAuthenticated && req.isAuthenticated()) {
            return next();
        }

        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({
                success: false,
                error: 'Authentication required'
            });
        }

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

        if (!dbPool) {
            return res.status(503).json({
                success: false,
                error: 'Authentication service unavailable'
            });
        }

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

        if (user.is_blacklisted) {
            return res.status(403).json({
                success: false,
                error: 'Account has been suspended'
            });
        }

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

const logActivity = async (userId, action, entityType = null, entityId = null, details = null, req = null) => {
    try {
        if (!dbPool || !isDbConnected) {
            console.warn('Cannot log activity: Database not available');
            return;
        }

        const ipAddress = req ? (req.ip || req.connection.remoteAddress) : null;
        const userAgent = req ? req.get('User-Agent') : null;

        await dbPool.execute(`
            INSERT INTO activity_logs (user_id, action, entity_type, entity_id, ip_address, user_agent, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [userId, action, entityType, entityId, ipAddress, userAgent, JSON.stringify(details)]);
    } catch (error) {
        console.error('Failed to log activity:', error);
    }
};

// Database Initialization
async function initializeDatabase() {
    try {
        console.log('🔄 Initializing database...');

        // Create database if not exists
        const connection = await mysql.createConnection({
            host: config.database.host,
            user: config.database.user,
            password: config.database.password,
            port: config.database.port
        });

        await connection.execute(`CREATE DATABASE IF NOT EXISTS ${config.database.database}`);
        await connection.end();

        // Create connection pool
        dbPool = mysql.createPool(config.database);

        // Test connection with MariaDB compatible query
        const testConnection = await dbPool.getConnection();
        await testConnection.ping();
        testConnection.release();

        isDbConnected = true;
        console.log('✅ Database connected successfully');

        // Create tables
        await createTables();

        // Insert default data
        await insertDefaultData();

        return true;

    } catch (error) {
        console.error('❌ Database initialization failed:', error);
        isDbConnected = false;
        return false;
    }
}

async function createTables() {
    const tables = [
        // Users table
        `CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NULL,
            discord_id VARCHAR(50) NULL,
            discord_username VARCHAR(100) NULL,
            avatar_url VARCHAR(500) NULL,
            role ENUM('user', 'admin', 'superadmin') DEFAULT 'user',
            credits DECIMAL(10,2) DEFAULT 0.00,
            total_spent DECIMAL(10,2) DEFAULT 0.00,
            loyalty_points INT DEFAULT 0,
            email_verified BOOLEAN DEFAULT FALSE,
            is_active BOOLEAN DEFAULT TRUE,
            is_blacklisted BOOLEAN DEFAULT FALSE,
            last_login TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_email (email),
            INDEX idx_discord_id (discord_id),
            INDEX idx_role (role),
            INDEX idx_active (is_active)
        )`,

        // Categories table
        `CREATE TABLE IF NOT EXISTS categories (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            description TEXT,
            icon VARCHAR(100),
            sort_order INT DEFAULT 0,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_active_sort (is_active, sort_order)
        )`,

        // Products table
        `CREATE TABLE IF NOT EXISTS products (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            short_description VARCHAR(500),
            category_id INT,
            product_type ENUM('script', 'file', 'id_data', 'physical', 'service') DEFAULT 'script',
            price DECIMAL(10,2) NOT NULL,
            discount_price DECIMAL(10,2) NULL,
            is_rental BOOLEAN DEFAULT FALSE,
            rental_duration_days INT NULL,
            requires_discord BOOLEAN DEFAULT FALSE,
            requires_license BOOLEAN DEFAULT FALSE,
            download_limit INT DEFAULT -1,
            stock_quantity INT DEFAULT -1,
            image_url VARCHAR(500),
            gallery JSON,
            file_path VARCHAR(500),
            file_size BIGINT,
            demo_url VARCHAR(500),
            video_url VARCHAR(500),
            requirements TEXT,
            features JSON,
            changelog JSON,
            tags JSON,
            is_featured BOOLEAN DEFAULT FALSE,
            is_active BOOLEAN DEFAULT TRUE,
            sort_order INT DEFAULT 0,
            total_sales INT DEFAULT 0,
            rating_average DECIMAL(3,2) DEFAULT 0.00,
            rating_count INT DEFAULT 0,
            created_by INT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_category (category_id),
            INDEX idx_type_active (product_type, is_active),
            INDEX idx_featured (is_featured),
            INDEX idx_price (price),
            INDEX idx_rating (rating_average)
        )`,

        // Orders table
        `CREATE TABLE IF NOT EXISTS orders (
            id INT AUTO_INCREMENT PRIMARY KEY,
            order_number VARCHAR(100) UNIQUE NOT NULL,
            user_id INT NOT NULL,
            total_amount DECIMAL(10,2) NOT NULL,
            credits_used DECIMAL(10,2) DEFAULT 0,
            payment_method ENUM('credits', 'truewallet', 'bank_transfer') DEFAULT 'credits',
            payment_status ENUM('pending', 'completed', 'failed', 'refunded') DEFAULT 'pending',
            order_status ENUM('pending', 'processing', 'completed', 'cancelled') DEFAULT 'pending',
            payment_data JSON,
            billing_info JSON,
            notes TEXT,
            completed_at TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_user_status (user_id, order_status),
            INDEX idx_payment_status (payment_status),
            INDEX idx_order_number (order_number)
        )`,

        // Order items table
        `CREATE TABLE IF NOT EXISTS order_items (
            id INT AUTO_INCREMENT PRIMARY KEY,
            order_id INT NOT NULL,
            product_id INT NULL,
            bundle_id INT NULL,
            item_type ENUM('product', 'bundle') NOT NULL,
            quantity INT DEFAULT 1,
            unit_price DECIMAL(10,2) NOT NULL,
            total_price DECIMAL(10,2) NOT NULL,
            license_key VARCHAR(255) NULL,
            license_expires_at TIMESTAMP NULL,
            download_count INT DEFAULT 0,
            is_delivered BOOLEAN DEFAULT FALSE,
            delivered_at TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE SET NULL,
            INDEX idx_order (order_id),
            INDEX idx_license (license_key)
        )`,

        // Licenses table
        `CREATE TABLE IF NOT EXISTS licenses (
            id INT AUTO_INCREMENT PRIMARY KEY,
            license_key VARCHAR(255) UNIQUE NOT NULL,
            user_id INT NOT NULL,
            product_id INT NOT NULL,
            order_item_id INT NOT NULL,
            discord_user_id VARCHAR(50) NULL,
            ip_address VARCHAR(45) NULL,
            is_active BOOLEAN DEFAULT TRUE,
            is_permanent BOOLEAN DEFAULT FALSE,
            expires_at TIMESTAMP NULL,
            last_verification TIMESTAMP NULL,
            verification_count INT DEFAULT 0,
            ip_changes_today INT DEFAULT 0,
            last_ip_change TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
            FOREIGN KEY (order_item_id) REFERENCES order_items(id) ON DELETE CASCADE,
            INDEX idx_license_key (license_key),
            INDEX idx_user_product (user_id, product_id),
            INDEX idx_discord_id (discord_user_id),
            INDEX idx_ip_address (ip_address),
            INDEX idx_active_expires (is_active, expires_at)
        )`,

        // Trials table
        `CREATE TABLE IF NOT EXISTS trials (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            product_id INT NOT NULL,
            trial_token VARCHAR(255) UNIQUE NOT NULL,
            discord_user_id VARCHAR(50) NULL,
            ip_address VARCHAR(45) NULL,
            duration_hours INT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            is_active BOOLEAN DEFAULT TRUE,
            used_at TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
            INDEX idx_trial_token (trial_token),
            INDEX idx_user_product (user_id, product_id),
            INDEX idx_expires (expires_at),
            INDEX idx_active (is_active)
        )`,

        // Credit transactions table
        `CREATE TABLE IF NOT EXISTS credit_transactions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            transaction_type ENUM('deposit', 'purchase', 'refund', 'bonus', 'admin_adjustment') NOT NULL,
            amount DECIMAL(10,2) NOT NULL,
            balance_before DECIMAL(10,2) NOT NULL,
            balance_after DECIMAL(10,2) NOT NULL,
            reference_type ENUM('order', 'payment', 'admin', 'loyalty', 'bonus') NULL,
            reference_id INT NULL,
            description TEXT,
            payment_method VARCHAR(50) NULL,
            payment_data JSON,
            processed_by INT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (processed_by) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_user_type (user_id, transaction_type),
            INDEX idx_reference (reference_type, reference_id),
            INDEX idx_created_at (created_at)
        )`,

        // Payment methods table
        `CREATE TABLE IF NOT EXISTS payment_methods (
            id INT AUTO_INCREMENT PRIMARY KEY,
            method_name VARCHAR(100) NOT NULL,
            method_type ENUM('truewallet', 'bank_transfer', 'crypto', 'other') NOT NULL,
            is_active BOOLEAN DEFAULT TRUE,
            configuration JSON,
            fees JSON,
            instructions TEXT,
            min_amount DECIMAL(10,2) DEFAULT 0,
            max_amount DECIMAL(10,2) NULL,
            sort_order INT DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_active_type (is_active, method_type)
        )`,

        // Payment requests table
        `CREATE TABLE IF NOT EXISTS payment_requests (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            amount DECIMAL(10,2) NOT NULL,
            method_type VARCHAR(50) NOT NULL,
            payment_data JSON,
            status ENUM('pending', 'processing', 'completed', 'failed', 'cancelled') DEFAULT 'pending',
            reference_code VARCHAR(255),
            slip_image VARCHAR(500),
            verification_data JSON,
            processed_by INT NULL,
            notes TEXT,
            completed_at TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (processed_by) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_user_status (user_id, status),
            INDEX idx_reference (reference_code),
            INDEX idx_method (method_type)
        )`,

        // Reviews table
        `CREATE TABLE IF NOT EXISTS reviews (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            product_id INT NOT NULL,
            order_item_id INT NOT NULL,
            rating INT NOT NULL CHECK (rating >= 1 AND rating <= 5),
            review_text TEXT,
            is_verified_purchase BOOLEAN DEFAULT FALSE,
            is_approved BOOLEAN DEFAULT FALSE,
            admin_reply TEXT,
            helpful_count INT DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
            FOREIGN KEY (order_item_id) REFERENCES order_items(id) ON DELETE CASCADE,
            UNIQUE KEY unique_user_product (user_id, product_id),
            INDEX idx_product_approved (product_id, is_approved),
            INDEX idx_rating (rating)
        )`,

        // Announcements table
        `CREATE TABLE IF NOT EXISTS announcements (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            content TEXT NOT NULL,
            announcement_type ENUM('info', 'warning', 'success', 'danger') DEFAULT 'info',
            target_audience ENUM('all', 'users', 'vip', 'admins') DEFAULT 'all',
            is_active BOOLEAN DEFAULT TRUE,
            is_sticky BOOLEAN DEFAULT FALSE,
            starts_at TIMESTAMP NULL,
            ends_at TIMESTAMP NULL,
            created_by INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_active_audience (is_active, target_audience),
            INDEX idx_dates (starts_at, ends_at)
        )`,

        // Site settings table
        `CREATE TABLE IF NOT EXISTS site_settings (
            id INT AUTO_INCREMENT PRIMARY KEY,
            setting_key VARCHAR(100) UNIQUE NOT NULL,
            setting_value TEXT,
            setting_type ENUM('string', 'number', 'boolean', 'json') DEFAULT 'string',
            description TEXT,
            category VARCHAR(50) DEFAULT 'general',
            is_public BOOLEAN DEFAULT FALSE,
            updated_by INT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_category (category),
            INDEX idx_public (is_public)
        )`,

        // Activity logs table
        `CREATE TABLE IF NOT EXISTS activity_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NULL,
            action VARCHAR(100) NOT NULL,
            entity_type VARCHAR(50),
            entity_id INT NULL,
            ip_address VARCHAR(45),
            user_agent TEXT,
            details JSON,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_user_action (user_id, action),
            INDEX idx_entity (entity_type, entity_id),
            INDEX idx_created_at (created_at)
        )`
    ];

    for (const tableSQL of tables) {
        await dbPool.execute(tableSQL);
    }

    console.log('✅ Database tables created successfully');
}

async function insertDefaultData() {
    try {
        // Check if admin user exists
        const [adminCheck] = await dbPool.execute('SELECT id FROM users WHERE role = "superadmin" LIMIT 1');

        if (adminCheck.length === 0) {
            // Create default admin user
            const hashedPassword = await bcrypt.hash('admin123', 12);
            await dbPool.execute(`
                INSERT INTO users (username, email, password, role, email_verified, credits)
                VALUES ('admin', 'admin@scriptshop.com', ?, 'superadmin', 1, 10000)
            `, [hashedPassword]);
            console.log('✅ Default admin user created (admin/admin123)');
        }

        // Insert default categories if they don't exist
        const categories = [
            ['Scripts', 'FiveM Lua Scripts', 'fas fa-code', 1],
            ['Assets', 'Game Assets & Resources', 'fas fa-cube', 2],
            ['Maps', 'Custom Maps & MLOs', 'fas fa-map', 3],
            ['Vehicles', 'Custom Vehicles', 'fas fa-car', 4],
            ['Tools', 'Development Tools', 'fas fa-tools', 5],
            ['Services', 'Custom Services', 'fas fa-handshake', 6]
        ];

        for (const [name, description, icon, sort_order] of categories) {
            await dbPool.execute(`
                INSERT IGNORE INTO categories (name, description, icon, sort_order)
                VALUES (?, ?, ?, ?)
            `, [name, description, icon, sort_order]);
        }

        // Insert default site settings
        const siteSettings = [
            ['site_name', config.site_name, 'string', 'Website Name', 'general', true],
            ['site_description', 'Premium Scripts & Resources Marketplace', 'string', 'Website Description', 'general', true],
            ['maintenance_mode', 'false', 'boolean', 'Maintenance Mode', 'general', false],
            ['allow_registration', 'true', 'boolean', 'Allow New Registration', 'general', false],
            ['min_topup_amount', '50', 'number', 'Minimum Top-up Amount', 'payment', false],
            ['max_topup_amount', '10000', 'number', 'Maximum Top-up Amount', 'payment', false],
            ['loyalty_rate', '0.01', 'number', 'Loyalty Points Rate (points per baht)', 'loyalty', false],
            ['ip_change_cooldown', '24', 'number', 'IP Change Cooldown (hours)', 'license', false],
            ['max_ip_changes_per_day', '3', 'number', 'Maximum IP Changes Per Day', 'license', false],
            ['trial_duration_default', '24', 'number', 'Default Trial Duration (hours)', 'trial', false],
            ['max_trials_per_user', '1', 'number', 'Maximum Trials Per User Per Product', 'trial', false]
        ];

        for (const [key, value, type, description, category, is_public] of siteSettings) {
            await dbPool.execute(`
                INSERT IGNORE INTO site_settings (setting_key, setting_value, setting_type, description, category, is_public)
                VALUES (?, ?, ?, ?, ?, ?)
            `, [key, value, type, description, category, is_public]);
        }

        console.log('✅ Default data inserted successfully');

    } catch (error) {
        console.error('❌ Failed to insert default data:', error);
    }
}

// Session Configuration
async function setupSession() {
    if (!dbPool || !isDbConnected) {
        console.warn('⚠️ Database not available for session store, using memory store');
        app.use(session({
            key: 'scriptshop_session',
            secret: config.jwt_secret,
            resave: false,
            saveUninitialized: false,
            cookie: {
                maxAge: 24 * 60 * 60 * 1000, // 24 hours
                secure: process.env.NODE_ENV === 'production',
                httpOnly: true,
                sameSite: 'lax'
            }
        }));
    } else {
        try {
            const sessionStore = new MySQLStore({}, dbPool);
            app.use(session({
                key: 'scriptshop_session',
                secret: config.jwt_secret,
                store: sessionStore,
                resave: false,
                saveUninitialized: false,
                rolling: true,
                cookie: {
                    maxAge: 24 * 60 * 60 * 1000, // 24 hours
                    secure: process.env.NODE_ENV === 'production',
                    httpOnly: true,
                    sameSite: 'lax'
                }
            }));
            console.log('✅ Session store configured with MySQL');
        } catch (error) {
            console.error('❌ Session store setup failed:', error);
        }
    }
}

// Passport Configuration
async function setupPassport() {
    app.use(passport.initialize());
    app.use(passport.session());

    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    passport.deserializeUser(async (id, done) => {
        try {
            if (!dbPool || !isDbConnected) {
                return done(new Error('Database not available'), null);
            }

            const [rows] = await dbPool.execute('SELECT * FROM users WHERE id = ?', [id]);
            done(null, rows[0] || null);
        } catch (error) {
            done(error, null);
        }
    });

    // Discord OAuth Strategy
    if (config.discord.client_id !== 'your-discord-client-id') {
    passport.use(new DiscordStrategy({
        clientID: config.discord.client_id,
        clientSecret: config.discord.client_secret,
        callbackURL: `${config.site_url}/auth/discord/callback`,
        scope: ['identify', 'email']
    }, async (accessToken, refreshToken, profile, done) => {
        try {
            if (!dbPool || !isDbConnected) {
                return done(new Error('Database not available'), null);
            }

            console.log('Discord OAuth Profile:', {
                id: profile.id,
                username: profile.username,
                email: profile.email
            });

            // 1. ตรวจสอบว่ามี discord_id นี้อยู่แล้วหรือไม่ (มีบัญชีที่เชื่อมต่อแล้ว)
            const [discordUser] = await dbPool.execute(
                'SELECT * FROM users WHERE discord_id = ?',
                [profile.id]
            );

            if (discordUser.length > 0) {
                console.log('Found existing user with Discord ID:', discordUser[0].username);
                // มีบัญชีที่เชื่อมต่อ Discord แล้ว - ให้ login เข้าบัญชีนั้น
                return done(null, discordUser[0]);
            }

            // 2. ตรวจสอบว่ามี email นี้อยู่แล้วหรือไม่ (บัญชีเดิมที่ยังไม่เชื่อมต่อ Discord)
            if (profile.email) {
                const [emailUser] = await dbPool.execute(
                    'SELECT * FROM users WHERE email = ? AND discord_id IS NULL',
                    [profile.email]
                );

                if (emailUser.length > 0) {
                    console.log('Found existing user with email, linking Discord:', emailUser[0].username);
                    // มีบัญชีเดิมแต่ยังไม่เชื่อมต่อ Discord - ให้เชื่อมต่อเข้ากับบัญชีเดิม
                    await dbPool.execute(
                        'UPDATE users SET discord_id = ?, discord_username = ?, updated_at = NOW() WHERE id = ?',
                        [profile.id, profile.username, emailUser[0].id]
                    );

                    // ดึงข้อมูลที่อัปเดตแล้ว
                    const [updatedUser] = await dbPool.execute('SELECT * FROM users WHERE id = ?', [emailUser[0].id]);
                    return done(null, updatedUser[0]);
                }
            }

            // 3. ไม่พบบัญชีเดิม - สร้างบัญชีใหม่
            console.log('Creating new user for Discord:', profile.username);
            
            // ตรวจสอบว่า username ซ้ำหรือไม่
            let username = profile.username || `discord_${profile.id}`;
            const [existingUsername] = await dbPool.execute(
                'SELECT id FROM users WHERE username = ?',
                [username]
            );

            if (existingUsername.length > 0) {
                username = `${username}_${Date.now()}`;
            }

            const [result] = await dbPool.execute(`
                INSERT INTO users (username, email, discord_id, discord_username, email_verified, credits, created_at)
                VALUES (?, ?, ?, ?, 1, 0, NOW())
            `, [
                username,
                profile.email || null,
                profile.id,
                profile.username
            ]);

            const [newUser] = await dbPool.execute('SELECT * FROM users WHERE id = ?', [result.insertId]);
            console.log('Created new user:', newUser[0].username);
            
            return done(null, newUser[0]);

        } catch (error) {
            console.error('Discord OAuth Error:', error);
            return done(error, null);
        }
    }));
    }
}
// Database availability middleware
app.use('/api', (req, res, next) => {
    // Skip database check for health endpoint and debug routes
    if (req.path === '/health' || req.path.startsWith('/debug/')) {
        return next();
    }

    if (!dbPool || !isDbConnected) {
        return res.status(503).json({
            success: false,
            error: 'Service temporarily unavailable',
            message: 'Database connection is not available'
        });
    }
    next();
});

// Basic health check endpoint (before routes) - MariaDB Compatible
app.get('/api/health', async (req, res) => {
    try {
        let dbStatus = 'disconnected';
        let dbTestResult = null;

        if (dbPool && isDbConnected) {
            try {
                // MariaDB compatible query - avoid using column aliases that might conflict
                const [result] = await dbPool.execute('SELECT 1 as test_value, NOW() as time_now');
                dbStatus = result[0].test_value === 1 ? 'connected' : 'error';
                dbTestResult = result[0];
            } catch (dbError) {
                dbStatus = 'error';
                console.error('Health check DB error:', dbError.message);
            }
        }

        res.json({
            success: true,
            message: 'API is running',
            timestamp: new Date().toISOString(),
            database: {
                status: dbStatus,
                test_result: dbTestResult
            },
            version: '1.0.0',
            environment: process.env.NODE_ENV || 'development',
            server_info: {
                uptime: process.uptime(),
                memory_usage: process.memoryUsage(),
                node_version: process.version
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Health check failed',
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});


// Function to setup routes - FIXED
async function setupRoutes() {
    try {
        console.log('🔄 Setting up routes...');

        // --- Static HTML page routes ---
        app.get('/', (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'index.html'));
        });
        app.get('/login', (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'login.html'));
        });
        app.get('/register', (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'register.html'));
        });
        app.get('/dashboard', (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
        });
        app.get('/admin', (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'admin.html'));
        });
        app.get('/products', (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'products.html'));
        });
        app.get('/product/:id', (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'product-detail.html'));
        });
        app.get('/cart', (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'cart.html'));
        });
        app.get('/checkout', (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'checkout.html'));
        });
        app.get('/payment', (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'payment.html'));
        });


        // --- OAuth routes ---

        app.get('/auth/discord', (req, res, next) => {
            if (req.query.returnUrl) {
                req.session.returnUrl = req.query.returnUrl;
            }
            next();
        }, passport.authenticate('discord'));

        app.get('/auth/discord/callback',
            passport.authenticate('discord', { failureRedirect: '/login?error=discord_auth_failed' }),
            (req, res) => {
                // 1. สร้าง Token จากข้อมูล user ที่ passport ส่งมาให้
                const token = generateToken(req.user);

                // 2. กำหนดหน้าปลายทางที่จะส่ง Token ไปให้ (หน้า login)
                // สคริปต์ในหน้า login.html ถูกเขียนให้รอรับ token จาก URL อยู่แล้ว
                const destinationUrl = new URL(`${config.site_url}/login`);

                // 3. แนบ Token ไปกับ URL parameter
                destinationUrl.searchParams.set('token', token);
                
                // 4. สั่ง redirect ไปยัง URL ใหม่ที่มี Token อยู่ด้วย
                res.redirect(destinationUrl.toString());
            }
        );


        // --- API routes ---
        const apiRouter = express.Router();

        // Mount debug routes FIRST (only in development)
        if (process.env.NODE_ENV !== 'production') {
             console.log('🐛 Setting up debug routes...');
            apiRouter.get('/debug/routes', (req, res) => {
                // ... (debug route logic)
            });
            apiRouter.get('/debug/database', async (req, res) => {
                // ... (debug route logic)
            });
        }

        // Import and mount other API routes
        try {
            const mainRoutes = require('./routes/index');
            apiRouter.use('/', mainRoutes);
            console.log('✅ Main API routes loaded');
        } catch (error) {
            console.error('❌ Failed to load main routes:', error.message);
            apiRouter.use('/', (req, res) => {
                res.status(503).json({
                    success: false,
                    error: 'API routes unavailable',
                    message: 'Main routes failed to load during server startup',
                    details: error.message
                });
            });
        }

        // Mount the API router
        app.use('/api', apiRouter);

        console.log('✅ All routes mounted successfully');
    } catch (error) {
        console.error('❌ Failed to setup routes:', error.message);
        app.use('/', (req, res) => {
            res.status(503).json({
                success: false,
                error: 'Route setup failed',
                message: 'Routes failed to setup during server startup'
            });
        });
    }
}

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);

    if (err.code === 'PROTOCOL_CONNECTION_LOST') {
        console.log('Database connection lost. Marking as disconnected...');
        isDbConnected = false;
    }

    if (err.type === 'time-out') {
        return res.status(408).json({
            success: false,
            error: 'Request timeout'
        });
    }
    
    // Check if headers have already been sent
    if (res.headersSent) {
        return next(err);
    }

    res.status(500).json({
        success: false,
        error: process.env.NODE_ENV === 'production'
            ? 'Internal server error'
            : err.message
    });
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\n🔄 Shutting down gracefully...');

    if (dbPool) {
        await dbPool.end();
        console.log('✅ Database pool closed');
    }

    process.exit(0);
});

// Export for testing and other modules
module.exports = {
    app,
    dbPool: () => dbPool,
    config,
    authenticateToken,
    requireAuth,
    requireAdmin,
    logActivity
};

// Start server
if (require.main === module) {
    (async () => {
        try {
            console.log('🚀 Starting Moonoi Developer API Server...');
            console.log('📍 Environment:', process.env.NODE_ENV || 'development');

            // Initialize database first
            const dbInitialized = await initializeDatabase();

            if (!dbInitialized) {
                console.warn('⚠️ Starting server without database connection');
                if (process.env.NODE_ENV === 'production') {
                    process.exit(1);
                }
            }

            // Setup session (this calls app.use(session(...)))
            await setupSession();

            // Setup passport strategies (this calls app.use(passport...))
            await setupPassport();

            // Setup ALL routes AFTER session and passport are configured
            await setupRoutes();

            // 404 handler - Must be placed AFTER all other routes
            app.use((req, res) => {
                if (req.originalUrl.startsWith('/api/')) {
                    res.status(404).json({
                        success: false,
                        error: 'API endpoint not found',
                        path: req.originalUrl,
                        method: req.method,
                        available_debug_endpoints: process.env.NODE_ENV !== 'production' ? [
                            'GET /api/health',
                            'GET /api/debug/routes',
                            'GET /api/debug/database'
                        ] : []
                    });
                } else {
                    res.status(404);
                    const notFoundPath = path.join(__dirname, 'public', '404.html');
                    fs.access(notFoundPath).then(() => {
                        res.sendFile(notFoundPath);
                    }).catch(() => {
                        res.send('<h1>404 - Page Not Found</h1><p>The requested page could not be found.</p>');
                    });
                }
            });


            // Start the server
            const server = app.listen(config.port, () => {
                console.log(`✅ Server running on port ${config.port}`);
                console.log(`🌐 Website: ${config.site_url}`);
                console.log(`👑 Admin Panel: ${config.site_url}/admin`);
                console.log(`📊 Default Admin: admin / admin123`);
                console.log(`🏥 Health Check: ${config.site_url}/api/health`);

                if (process.env.NODE_ENV !== 'production') {
                    console.log(`🐛 Debug Routes: ${config.site_url}/api/debug/routes`);
                    console.log(`🐛 Debug Database: ${config.site_url}/api/debug/database`);
                }
            });

            // Handle server errors
            server.on('error', (error) => {
                if (error.code === 'EADDRINUSE') {
                    console.error(`❌ Port ${config.port} is already in use`);
                } else {
                    console.error('❌ Server error:', error);
                }
                process.exit(1);
            });

        } catch (error) {
            console.error('❌ Failed to start server:', error);
            process.exit(1);
        }
    })();
}