// routes/admin.js - Admin Dashboard and Management Routes (แก้ไขการเข้าถึงฐานข้อมูล)
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;

const router = express.Router();

// Function to get database pool and other dependencies
let getDbPool, requireAuth, requireAdmin, logActivity;

try {
    const serverModule = require('../server');
    getDbPool = serverModule.dbPool;
    requireAuth = serverModule.requireAuth;
    requireAdmin = serverModule.requireAdmin;
    logActivity = serverModule.logActivity;
} catch (error) {
    console.error('Failed to import server module:', error);
    getDbPool = () => null;
    requireAuth = (req, res, next) => next();
    requireAdmin = (req, res, next) => next();
    logActivity = () => Promise.resolve();
}

// File upload configuration for admin
const adminStorage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const uploadType = req.uploadType || 'general';
        const uploadPath = `uploads/${uploadType}`;
        try {
            await fs.mkdir(uploadPath, { recursive: true });
            cb(null, uploadPath);
        } catch (error) {
            cb(error);
        }
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const adminUpload = multer({
    storage: adminStorage,
    limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit
    fileFilter: (req, file, cb) => {
        // Allow all file types for admin uploads
        cb(null, true);
    }
});

// GET /api/admin/dashboard - Admin Dashboard Statistics
router.get('/dashboard', requireAuth, requireAdmin, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        // Get various statistics for dashboard
        const [userStats] = await dbPool.execute(`
            SELECT 
                COUNT(*) as total_users,
                COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN 1 END) as new_users_30d,
                COUNT(CASE WHEN last_login >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 END) as active_users_7d,
                COUNT(CASE WHEN is_blacklisted = 1 THEN 1 END) as blacklisted_users
            FROM users
        `);

        const [productStats] = await dbPool.execute(`
            SELECT 
                COUNT(*) as total_products,
                COUNT(CASE WHEN is_active = 1 THEN 1 END) as active_products,
                COUNT(CASE WHEN product_type = 'script' THEN 1 END) as script_products,
                COUNT(CASE WHEN is_featured = 1 THEN 1 END) as featured_products
            FROM products
        `);

        const [orderStats] = await dbPool.execute(`
            SELECT 
                COUNT(*) as total_orders,
                COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN 1 END) as orders_30d,
                COALESCE(SUM(CASE WHEN order_status = 'completed' THEN total_amount END), 0) as total_revenue,
                COALESCE(SUM(CASE WHEN order_status = 'completed' AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN total_amount END), 0) as revenue_30d
            FROM orders
        `);

        const [licenseStats] = await dbPool.execute(`
            SELECT 
                COUNT(*) as total_licenses,
                COUNT(CASE WHEN is_active = 1 THEN 1 END) as active_licenses,
                COUNT(CASE WHEN expires_at IS NOT NULL AND expires_at <= NOW() THEN 1 END) as expired_licenses,
                COUNT(CASE WHEN last_verification >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 END) as verified_7d
            FROM licenses
        `);

        const [paymentStats] = await dbPool.execute(`
            SELECT 
                COUNT(*) as total_payments,
                COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_payments,
                COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_payments,
                COALESCE(SUM(CASE WHEN status = 'completed' THEN amount END), 0) as total_deposited
            FROM payment_requests
        `);

        const [trialStats] = await dbPool.execute(`
            SELECT 
                COUNT(*) as total_trials,
                COUNT(CASE WHEN is_active = 1 AND expires_at > NOW() THEN 1 END) as active_trials,
                COUNT(CASE WHEN expires_at <= NOW() THEN 1 END) as expired_trials
            FROM trials
        `);

        // Recent activities
        const [recentActivities] = await dbPool.execute(`
            SELECT 
                al.*,
                u.username
            FROM activity_logs al
            LEFT JOIN users u ON al.user_id = u.id
            ORDER BY al.created_at DESC
            LIMIT 10
        `);

        const processedActivities = recentActivities.map(activity => ({
            ...activity,
            details: activity.details ? JSON.parse(activity.details) : {}
        }));

        // Top selling products
        const [topProducts] = await dbPool.execute(`
            SELECT 
                p.id,
                p.name,
                p.total_sales,
                p.price,
                p.discount_price,
                COALESCE(SUM(oi.total_price), 0) as total_revenue
            FROM products p
            LEFT JOIN order_items oi ON p.id = oi.product_id
            LEFT JOIN orders o ON oi.order_id = o.id AND o.order_status = 'completed'
            WHERE p.is_active = 1
            GROUP BY p.id
            ORDER BY p.total_sales DESC
            LIMIT 5
        `);

        res.json({
            success: true,
            data: {
                statistics: {
                    users: userStats[0],
                    products: productStats[0],
                    orders: orderStats[0],
                    licenses: licenseStats[0],
                    payments: paymentStats[0],
                    trials: trialStats[0]
                },
                recent_activities: processedActivities,
                top_products: topProducts
            }
        });

    } catch (error) {
        console.error('Admin dashboard error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/admin/products - Create Product
router.post('/products', requireAuth, requireAdmin, adminUpload.fields([
    { name: 'image', maxCount: 1 },
    { name: 'gallery', maxCount: 10 },
    { name: 'file', maxCount: 1 }
]), async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const {
            name, description, short_description, category_id, product_type,
            price, discount_price, is_rental, rental_duration_days,
            requires_discord, requires_license, download_limit, stock_quantity,
            demo_url, video_url, requirements, features, tags, is_featured, sort_order
        } = req.body;

        const adminId = req.user.id;

        // Process uploaded files
        let imageUrl = null;
        let gallery = [];
        let filePath = null;
        let fileSize = null;

        if (req.files) {
            if (req.files.image && req.files.image[0]) {
                imageUrl = `/uploads/products/${req.files.image[0].filename}`;
            }

            if (req.files.gallery) {
                gallery = req.files.gallery.map(file => `/uploads/products/${file.filename}`);
            }

            if (req.files.file && req.files.file[0]) {
                filePath = `/uploads/files/${req.files.file[0].filename}`;
                fileSize = req.files.file[0].size;
            }
        }

        // Parse JSON fields
        const featuresArray = features ? JSON.parse(features) : [];
        const tagsArray = tags ? JSON.parse(tags) : [];

        // Create product
        const [result] = await dbPool.execute(`
            INSERT INTO products (
                name, description, short_description, category_id, product_type,
                price, discount_price, is_rental, rental_duration_days,
                requires_discord, requires_license, download_limit, stock_quantity,
                image_url, gallery, file_path, file_size, demo_url, video_url,
                requirements, features, tags, is_featured, sort_order, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            name, description, short_description, category_id, product_type,
            parseFloat(price), discount_price ? parseFloat(discount_price) : null,
            is_rental === 'true', rental_duration_days ? parseInt(rental_duration_days) : null,
            requires_discord === 'true', requires_license === 'true',
            download_limit ? parseInt(download_limit) : -1,
            stock_quantity ? parseInt(stock_quantity) : -1,
            imageUrl, JSON.stringify(gallery), filePath, fileSize,
            demo_url || null, video_url || null, requirements || null,
            JSON.stringify(featuresArray), JSON.stringify(tagsArray),
            is_featured === 'true', sort_order ? parseInt(sort_order) : 0, adminId
        ]);

        // Log activity
        await logActivity(adminId, 'product_created', 'product', result.insertId, {
            product_name: name,
            product_type,
            price: parseFloat(price)
        }, req);

        res.status(201).json({
            success: true,
            message: 'Product created successfully',
            data: {
                id: result.insertId,
                name,
                product_type,
                price: parseFloat(price)
            }
        });

    } catch (error) {
        console.error('Create product error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// PUT /api/admin/products/:id - Update Product
router.put('/products/:id', requireAuth, requireAdmin, adminUpload.fields([
    { name: 'image', maxCount: 1 },
    { name: 'gallery', maxCount: 10 },
    { name: 'file', maxCount: 1 }
]), async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { id } = req.params;
        const adminId = req.user.id;

        // Get existing product
        const [existingProducts] = await dbPool.execute('SELECT * FROM products WHERE id = ?', [id]);
        if (existingProducts.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        const existingProduct = existingProducts[0];

        // Process form data
        const {
            name, description, short_description, category_id, product_type,
            price, discount_price, is_rental, rental_duration_days,
            requires_discord, requires_license, download_limit, stock_quantity,
            demo_url, video_url, requirements, features, tags, is_featured, 
            sort_order, is_active
        } = req.body;

        // Process uploaded files
        let imageUrl = existingProduct.image_url;
        let gallery = existingProduct.gallery ? JSON.parse(existingProduct.gallery) : [];
        let filePath = existingProduct.file_path;
        let fileSize = existingProduct.file_size;

        if (req.files) {
            if (req.files.image && req.files.image[0]) {
                imageUrl = `/uploads/products/${req.files.image[0].filename}`;
            }

            if (req.files.gallery) {
                gallery = req.files.gallery.map(file => `/uploads/products/${file.filename}`);
            }

            if (req.files.file && req.files.file[0]) {
                filePath = `/uploads/files/${req.files.file[0].filename}`;
                fileSize = req.files.file[0].size;
            }
        }

        // Parse JSON fields
        const featuresArray = features ? JSON.parse(features) : JSON.parse(existingProduct.features || '[]');
        const tagsArray = tags ? JSON.parse(tags) : JSON.parse(existingProduct.tags || '[]');

        // Update product
        await dbPool.execute(`
            UPDATE products SET
                name = ?, description = ?, short_description = ?, category_id = ?, product_type = ?,
                price = ?, discount_price = ?, is_rental = ?, rental_duration_days = ?,
                requires_discord = ?, requires_license = ?, download_limit = ?, stock_quantity = ?,
                image_url = ?, gallery = ?, file_path = ?, file_size = ?, demo_url = ?, video_url = ?,
                requirements = ?, features = ?, tags = ?, is_featured = ?, sort_order = ?, 
                is_active = ?, updated_at = NOW()
            WHERE id = ?
        `, [
            name || existingProduct.name,
            description || existingProduct.description,
            short_description || existingProduct.short_description,
            category_id || existingProduct.category_id,
            product_type || existingProduct.product_type,
            price ? parseFloat(price) : existingProduct.price,
            discount_price ? parseFloat(discount_price) : existingProduct.discount_price,
            is_rental !== undefined ? (is_rental === 'true') : existingProduct.is_rental,
            rental_duration_days ? parseInt(rental_duration_days) : existingProduct.rental_duration_days,
            requires_discord !== undefined ? (requires_discord === 'true') : existingProduct.requires_discord,
            requires_license !== undefined ? (requires_license === 'true') : existingProduct.requires_license,
            download_limit !== undefined ? parseInt(download_limit) : existingProduct.download_limit,
            stock_quantity !== undefined ? parseInt(stock_quantity) : existingProduct.stock_quantity,
            imageUrl, JSON.stringify(gallery), filePath, fileSize,
            demo_url !== undefined ? demo_url : existingProduct.demo_url,
            video_url !== undefined ? video_url : existingProduct.video_url,
            requirements !== undefined ? requirements : existingProduct.requirements,
            JSON.stringify(featuresArray), JSON.stringify(tagsArray),
            is_featured !== undefined ? (is_featured === 'true') : existingProduct.is_featured,
            sort_order !== undefined ? parseInt(sort_order) : existingProduct.sort_order,
            is_active !== undefined ? (is_active === 'true') : existingProduct.is_active,
            id
        ]);

        // Log activity
        await logActivity(adminId, 'product_updated', 'product', id, {
            product_name: name || existingProduct.name,
            changes: Object.keys(req.body)
        }, req);

        res.json({
            success: true,
            message: 'Product updated successfully'
        });

    } catch (error) {
        console.error('Update product error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// DELETE /api/admin/products/:id - Delete Product
router.delete('/products/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { id } = req.params;
        const adminId = req.user.id;

        // Get product details
        const [products] = await dbPool.execute('SELECT name FROM products WHERE id = ?', [id]);
        if (products.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        const product = products[0];

        // Soft delete (set as inactive)
        await dbPool.execute('UPDATE products SET is_active = 0 WHERE id = ?', [id]);

        // Log activity
        await logActivity(adminId, 'product_deleted', 'product', id, {
            product_name: product.name
        }, req);

        res.json({
            success: true,
            message: 'Product deleted successfully'
        });

    } catch (error) {
        console.error('Delete product error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/admin/categories - Create Category
router.post('/categories', requireAuth, requireAdmin, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { name, description, icon, sort_order } = req.body;
        const adminId = req.user.id;

        if (!name) {
            return res.status(400).json({ error: 'Category name is required' });
        }

        // Check if category exists
        const [existing] = await dbPool.execute('SELECT id FROM categories WHERE name = ?', [name]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Category already exists' });
        }

        // Create category
        const [result] = await dbPool.execute(`
            INSERT INTO categories (name, description, icon, sort_order)
            VALUES (?, ?, ?, ?)
        `, [name, description || null, icon || null, sort_order ? parseInt(sort_order) : 0]);

        // Log activity
        await logActivity(adminId, 'category_created', 'category', result.insertId, {
            category_name: name
        }, req);

        res.status(201).json({
            success: true,
            message: 'Category created successfully',
            data: {
                id: result.insertId,
                name
            }
        });

    } catch (error) {
        console.error('Create category error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// PUT /api/admin/categories/:id - Update Category
router.put('/categories/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { id } = req.params;
        const { name, description, icon, sort_order, is_active } = req.body;
        const adminId = req.user.id;

        // Check if category exists
        const [categories] = await dbPool.execute('SELECT name FROM categories WHERE id = ?', [id]);
        if (categories.length === 0) {
            return res.status(404).json({ error: 'Category not found' });
        }

        // Update category
        await dbPool.execute(`
            UPDATE categories 
            SET name = ?, description = ?, icon = ?, sort_order = ?, is_active = ?
            WHERE id = ?
        `, [
            name || categories[0].name,
            description,
            icon,
            sort_order ? parseInt(sort_order) : 0,
            is_active !== undefined ? (is_active === 'true') : true,
            id
        ]);

        // Log activity
        await logActivity(adminId, 'category_updated', 'category', id, {
            category_name: name || categories[0].name
        }, req);

        res.json({
            success: true,
            message: 'Category updated successfully'
        });

    } catch (error) {
        console.error('Update category error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/admin/users - Get All Users
router.get('/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { page = 1, limit = 20, search, role, status } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        let whereConditions = [];
        let queryParams = [];

        if (search) {
            whereConditions.push('(u.username LIKE ? OR u.email LIKE ?)');
            const searchTerm = `%${search}%`;
            queryParams.push(searchTerm, searchTerm);
        }

        if (role && ['user', 'admin', 'superadmin'].includes(role)) {
            whereConditions.push('u.role = ?');
            queryParams.push(role);
        }

        if (status === 'active') {
            whereConditions.push('u.is_active = 1 AND u.is_blacklisted = 0');
        } else if (status === 'blacklisted') {
            whereConditions.push('u.is_blacklisted = 1');
        } else if (status === 'inactive') {
            whereConditions.push('u.is_active = 0');
        }

        const whereClause = whereConditions.length > 0 ? 'WHERE ' + whereConditions.join(' AND ') : '';

        // Get total count
        const [countResult] = await dbPool.execute(`
            SELECT COUNT(*) as total FROM users u ${whereClause}
        `, queryParams);
        const totalUsers = countResult[0].total;

        // Get users
        const [users] = await dbPool.execute(`
            SELECT 
                u.*,
                COUNT(DISTINCT o.id) as total_orders,
                COUNT(DISTINCT l.id) as active_licenses,
                COALESCE(SUM(CASE WHEN o.order_status = 'completed' THEN o.total_amount END), 0) as total_spent_calculated
            FROM users u
            LEFT JOIN orders o ON u.id = o.user_id
            LEFT JOIN licenses l ON u.id = l.user_id AND l.is_active = 1
            ${whereClause}
            GROUP BY u.id
            ORDER BY u.created_at DESC
            LIMIT ? OFFSET ?
        `, [...queryParams, parseInt(limit), offset]);

        // Remove sensitive data
        const sanitizedUsers = users.map(user => {
            const { password, ...sanitizedUser } = user;
            return sanitizedUser;
        });

        res.json({
            success: true,
            data: {
                users: sanitizedUsers,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: totalUsers,
                    totalPages: Math.ceil(totalUsers / parseInt(limit))
                }
            }
        });

    } catch (error) {
        console.error('Get admin users error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/admin/users/:id/blacklist - Blacklist User
router.post('/users/:id/blacklist', requireAuth, requireAdmin, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { id } = req.params;
        const { reason } = req.body;
        const adminId = req.user.id;

        // Get user details
        const [users] = await dbPool.execute('SELECT username, is_blacklisted FROM users WHERE id = ?', [id]);
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = users[0];

        if (user.is_blacklisted) {
            return res.status(400).json({ error: 'User is already blacklisted' });
        }

        // Blacklist user
        await dbPool.execute('UPDATE users SET is_blacklisted = 1 WHERE id = ?', [id]);

        // Deactivate all user licenses
        await dbPool.execute('UPDATE licenses SET is_active = 0 WHERE user_id = ?', [id]);

        // Log activity
        await logActivity(adminId, 'user_blacklisted', 'user', id, {
            target_user: user.username,
            reason: reason || 'No reason provided'
        }, req);

        res.json({
            success: true,
            message: 'User blacklisted successfully',
            data: {
                user_id: id,
                username: user.username
            }
        });

    } catch (error) {
        console.error('Blacklist user error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/admin/users/:id/unblacklist - Unblacklist User
router.post('/users/:id/unblacklist', requireAuth, requireAdmin, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { id } = req.params;
        const adminId = req.user.id;

        // Get user details
        const [users] = await dbPool.execute('SELECT username, is_blacklisted FROM users WHERE id = ?', [id]);
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = users[0];

        if (!user.is_blacklisted) {
            return res.status(400).json({ error: 'User is not blacklisted' });
        }

        // Unblacklist user
        await dbPool.execute('UPDATE users SET is_blacklisted = 0 WHERE id = ?', [id]);

        // Log activity
        await logActivity(adminId, 'user_unblacklisted', 'user', id, {
            target_user: user.username
        }, req);

        res.json({
            success: true,
            message: 'User unblacklisted successfully',
            data: {
                user_id: id,
                username: user.username
            }
        });

    } catch (error) {
        console.error('Unblacklist user error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/admin/settings - Get Site Settings
router.get('/settings', requireAuth, requireAdmin, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { category } = req.query;

        let whereCondition = '';
        let queryParams = [];

        if (category) {
            whereCondition = 'WHERE category = ?';
            queryParams.push(category);
        }

        const [settings] = await dbPool.execute(`
            SELECT * FROM site_settings ${whereCondition}
            ORDER BY category, setting_key
        `, queryParams);

        // Group by category
        const groupedSettings = {};
        settings.forEach(setting => {
            if (!groupedSettings[setting.category]) {
                groupedSettings[setting.category] = [];
            }
            
            let value = setting.setting_value;
            if (setting.setting_type === 'boolean') {
                value = value === 'true';
            } else if (setting.setting_type === 'number') {
                value = parseFloat(value);
            } else if (setting.setting_type === 'json') {
                try {
                    value = JSON.parse(value);
                } catch (e) {
                    // Keep as string if JSON parsing fails
                }
            }

            groupedSettings[setting.category].push({
                ...setting,
                setting_value: value
            });
        });

        res.json({
            success: true,
            data: groupedSettings
        });

    } catch (error) {
        console.error('Get settings error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// PUT /api/admin/settings - Update Site Settings
router.put('/settings', requireAuth, requireAdmin, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { settings } = req.body;
        const adminId = req.user.id;

        if (!settings || !Array.isArray(settings)) {
            return res.status(400).json({ error: 'Settings array is required' });
        }

        // Update each setting
        for (const setting of settings) {
            const { setting_key, setting_value, setting_type } = setting;

            let valueToStore = setting_value;
            if (setting_type === 'boolean') {
                valueToStore = setting_value ? 'true' : 'false';
            } else if (setting_type === 'json') {
                valueToStore = JSON.stringify(setting_value);
            } else {
                valueToStore = String(setting_value);
            }

            await dbPool.execute(`
                UPDATE site_settings 
                SET setting_value = ?, updated_by = ?, updated_at = NOW()
                WHERE setting_key = ?
            `, [valueToStore, adminId, setting_key]);
        }

        // Log activity
        await logActivity(adminId, 'settings_updated', 'settings', null, {
            updated_settings: settings.map(s => s.setting_key)
        }, req);

        res.json({
            success: true,
            message: 'Settings updated successfully'
        });

    } catch (error) {
        console.error('Update settings error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/admin/announcements - Create Announcement
router.post('/announcements', requireAuth, requireAdmin, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { title, content, announcement_type, target_audience, is_sticky, starts_at, ends_at } = req.body;
        const adminId = req.user.id;

        if (!title || !content) {
            return res.status(400).json({ error: 'Title and content are required' });
        }

        // Create announcement
        const [result] = await dbPool.execute(`
            INSERT INTO announcements (title, content, announcement_type, target_audience, is_sticky, starts_at, ends_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            title, content,
            announcement_type || 'info',
            target_audience || 'all',
            is_sticky === true,
            starts_at || null,
            ends_at || null,
            adminId
        ]);

        // Log activity
        await logActivity(adminId, 'announcement_created', 'announcement', result.insertId, {
            title,
            target_audience: target_audience || 'all'
        }, req);

        res.status(201).json({
            success: true,
            message: 'Announcement created successfully',
            data: {
                id: result.insertId,
                title
            }
        });

    } catch (error) {
        console.error('Create announcement error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/admin/analytics - Get Analytics Data
router.get('/analytics', requireAuth, requireAdmin, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { period = '30d' } = req.query;

        let dateFilter = 'DATE_SUB(NOW(), INTERVAL 30 DAY)';
        if (period === '7d') {
            dateFilter = 'DATE_SUB(NOW(), INTERVAL 7 DAY)';
        } else if (period === '90d') {
            dateFilter = 'DATE_SUB(NOW(), INTERVAL 90 DAY)';
        } else if (period === '1y') {
            dateFilter = 'DATE_SUB(NOW(), INTERVAL 1 YEAR)';
        }

        // Revenue analytics
        const [revenueData] = await dbPool.execute(`
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as orders,
                SUM(total_amount) as revenue
            FROM orders
            WHERE order_status = 'completed' AND created_at >= ${dateFilter}
            GROUP BY DATE(created_at)
            ORDER BY date ASC
        `);

        // User registration analytics
        const [userData] = await dbPool.execute(`
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as new_users
            FROM users
            WHERE created_at >= ${dateFilter}
            GROUP BY DATE(created_at)
            ORDER BY date ASC
        `);

        // Product performance
        const [productData] = await dbPool.execute(`
            SELECT 
                p.name,
                p.total_sales,
                COALESCE(SUM(oi.total_price), 0) as revenue
            FROM products p
            LEFT JOIN order_items oi ON p.id = oi.product_id
            LEFT JOIN orders o ON oi.order_id = o.id AND o.order_status = 'completed' AND o.created_at >= ${dateFilter}
            WHERE p.is_active = 1
            GROUP BY p.id
            ORDER BY revenue DESC
            LIMIT 10
        `);

        // Verification statistics
        const [verificationData] = await dbPool.execute(`
            SELECT 
                DATE(created_at) as date,
                COUNT(CASE WHEN action = 'license_verification' THEN 1 END) as license_verifications,
                COUNT(CASE WHEN action = 'trial_verification' THEN 1 END) as trial_verifications
            FROM activity_logs
            WHERE action IN ('license_verification', 'trial_verification') AND created_at >= ${dateFilter}
            GROUP BY DATE(created_at)
            ORDER BY date ASC
        `);

        res.json({
            success: true,
            data: {
                revenue: revenueData,
                users: userData,
                products: productData,
                verifications: verificationData,
                period
            }
        });

    } catch (error) {
        console.error('Get analytics error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/admin/orders - ดูรายการคำสั่งซื้อทั้งหมด
router.get('/orders', requireAuth, requireAdmin, async (req, res) => {
    try {
        const dbPool = getDbPool();
        const { page = 1, limit = 20, search, status } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        let whereConditions = [];
        let queryParams = [];

        if (search) {
            whereConditions.push('(o.order_number LIKE ? OR u.username LIKE ? OR u.email LIKE ?)');
            const searchTerm = `%${search}%`;
            queryParams.push(searchTerm, searchTerm, searchTerm);
        }
        if (status) {
            whereConditions.push('o.order_status = ?');
            queryParams.push(status);
        }
        const whereClause = whereConditions.length > 0 ? 'WHERE ' + whereConditions.join(' AND ') : '';

        const [countResult] = await dbPool.execute(`SELECT COUNT(*) as total FROM orders o LEFT JOIN users u ON o.user_id = u.id ${whereClause}`, queryParams);
        const totalOrders = countResult[0].total;

        const [orders] = await dbPool.execute(`
            SELECT o.*, u.username as customer_username
            FROM orders o
            LEFT JOIN users u ON o.user_id = u.id
            ${whereClause}
            ORDER BY o.created_at DESC
            LIMIT ? OFFSET ?
        `, [...queryParams, parseInt(limit), offset]);

        res.json({
            success: true,
            data: {
                orders,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: totalOrders,
                    totalPages: Math.ceil(totalOrders / parseInt(limit))
                }
            }
        });
    } catch (error) {
        console.error('Admin get orders error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


// GET /api/admin/payments - ดูประวัติการเติมเงินทั้งหมด
router.get('/payments', requireAuth, requireAdmin, async (req, res) => {
    try {
        const dbPool = getDbPool();
        const { page = 1, limit = 20, status, method } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        let whereConditions = [];
        let queryParams = [];
        if (status) {
            whereConditions.push('pr.status = ?');
            queryParams.push(status);
        }
        if (method) {
            whereConditions.push('pr.method_type = ?');
            queryParams.push(method);
        }
        const whereClause = whereConditions.length > 0 ? 'WHERE ' + whereConditions.join(' AND ') : '';

        const [countResult] = await dbPool.execute(`SELECT COUNT(*) as total FROM payment_requests pr ${whereClause}`, queryParams);
        const totalPayments = countResult[0].total;

        const [payments] = await dbPool.execute(`
            SELECT pr.*, u.username as user_username
            FROM payment_requests pr
            LEFT JOIN users u ON pr.user_id = u.id
            ${whereClause}
            ORDER BY pr.created_at DESC
            LIMIT ? OFFSET ?
        `, [...queryParams, parseInt(limit), offset]);

        res.json({
            success: true,
            data: {
                payments: payments,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: totalPayments,
                    totalPages: Math.ceil(totalPayments / parseInt(limit))
                }
            }
        });
    } catch (error) {
        console.error('Admin get payments error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


// POST /api/admin/users/adjust-credits - ปรับเครดิตผู้ใช้
router.post('/users/adjust-credits', requireAuth, requireAdmin, async (req, res) => {
    try {
        const dbPool = getDbPool();
        const { userId, amount, reason } = req.body;
        const adminId = req.user.id;
        const parsedAmount = parseFloat(amount);

        if (!userId || isNaN(parsedAmount) || !reason) {
            return res.status(400).json({ success: false, error: 'User ID, amount, and reason are required' });
        }

        const [users] = await dbPool.execute('SELECT credits FROM users WHERE id = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        const balanceBefore = parseFloat(users[0].credits);
        const balanceAfter = balanceBefore + parsedAmount;

        await dbPool.execute('UPDATE users SET credits = ? WHERE id = ?', [balanceAfter, userId]);

        await dbPool.execute(`
            INSERT INTO credit_transactions 
            (user_id, transaction_type, amount, balance_before, balance_after, reference_type, reference_id, description, processed_by)
            VALUES (?, 'admin_adjustment', ?, ?, ?, 'admin', ?, ?, ?)
        `, [userId, parsedAmount, balanceBefore, balanceAfter, adminId, `Admin adjustment: ${reason}`, adminId]);

        logActivity(adminId, 'credits_adjusted', 'user', userId, { target_user_id: userId, amount: parsedAmount, reason }, req);

        res.json({ success: true, message: 'Credits adjusted successfully', data: { userId, newBalance: balanceAfter } });
    } catch (error) {
        console.error('Adjust credits error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// GET /api/admin/licenses - ดึงข้อมูล License ทั้งหมด
router.get('/licenses', requireAuth, requireAdmin, async (req, res) => {
    try {
        const dbPool = getDbPool();
        const { page = 1, limit = 20, search } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        let whereConditions = [];
        let queryParams = [];

        if (search) {
            whereConditions.push('(l.license_key LIKE ? OR u.username LIKE ? OR p.name LIKE ?)');
            const searchTerm = `%${search}%`;
            queryParams.push(searchTerm, searchTerm, searchTerm);
        }
        const whereClause = whereConditions.length > 0 ? 'WHERE ' + whereConditions.join(' AND ') : '';

        const [countResult] = await dbPool.execute(`
            SELECT COUNT(*) as total 
            FROM licenses l 
            LEFT JOIN users u ON l.user_id = u.id 
            LEFT JOIN products p ON l.product_id = p.id 
            ${whereClause}`, queryParams);
        const totalLicenses = countResult[0].total;

        const [licenses] = await dbPool.execute(`
            SELECT l.*, u.username as owner_username, p.name as product_name
            FROM licenses l
            LEFT JOIN users u ON l.user_id = u.id
            LEFT JOIN products p ON l.product_id = p.id
            ${whereClause}
            ORDER BY l.created_at DESC
            LIMIT ? OFFSET ?
        `, [...queryParams, parseInt(limit), offset]);

        res.json({
            success: true,
            data: {
                licenses,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: totalLicenses,
                    totalPages: Math.ceil(totalLicenses / parseInt(limit))
                }
            }
        });
    } catch (error) {
        console.error('Admin get licenses error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


module.exports = router;