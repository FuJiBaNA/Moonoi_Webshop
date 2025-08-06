// routes/products.js - Product Management Routes (แก้ไขการเข้าถึงฐานข้อมูล)
const express = require('express');

const router = express.Router();

// Function to get database pool
let getDbPool;
let requireAuth, requireAdmin, logActivity;

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

// ==============================================
// SPECIFIC ROUTES ต้องไปก่อน GENERIC ROUTES
// ==============================================

// GET /api/products/categories - Get All Categories (Public)
router.get('/categories', async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const [categories] = await dbPool.execute(`
            SELECT 
                c.*,
                COUNT(p.id) as product_count
            FROM categories c
            LEFT JOIN products p ON c.id = p.category_id AND p.is_active = 1
            WHERE c.is_active = 1
            GROUP BY c.id
            ORDER BY c.sort_order ASC, c.name ASC
        `);

        res.json({
            success: true,
            data: categories
        });

    } catch (error) {
        console.error('Get categories error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/products/featured - Get Featured Products (Public)
router.get('/featured', async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { limit = 6 } = req.query;

        const [products] = await dbPool.execute(`
            SELECT 
                p.*,
                c.name as category_name,
                c.icon as category_icon,
                CASE 
                    WHEN p.discount_price IS NOT NULL THEN p.discount_price
                    ELSE p.price
                END as final_price,
                CASE 
                    WHEN p.discount_price IS NOT NULL THEN 
                        ROUND(((p.price - p.discount_price) / p.price) * 100, 0)
                    ELSE 0
                END as discount_percentage
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE p.is_active = 1 AND p.is_featured = 1
            ORDER BY p.sort_order ASC, p.created_at DESC
            LIMIT ?
        `, [parseInt(limit)]);

        // Parse JSON fields
        const processedProducts = products.map(product => ({
            ...product,
            gallery: product.gallery ? JSON.parse(product.gallery) : [],
            features: product.features ? JSON.parse(product.features) : [],
            tags: product.tags ? JSON.parse(product.tags) : []
        }));

        res.json({
            success: true,
            data: processedProducts
        });

    } catch (error) {
        console.error('Get featured products error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/products/bundles - Get Product Bundles (Public)
router.get('/bundles', async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { page = 1, limit = 6 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        // Get total count
        const [countResult] = await dbPool.execute(`
            SELECT COUNT(*) as total
            FROM product_bundles
            WHERE is_active = 1
        `);
        const totalBundles = countResult[0].total;

        // Get bundles with their products
        const [bundles] = await dbPool.execute(`
            SELECT 
                pb.*,
                GROUP_CONCAT(
                    CONCAT(p.id, ':', p.name, ':', COALESCE(p.discount_price, p.price))
                    SEPARATOR '|||'
                ) as bundle_products,
                SUM(COALESCE(p.discount_price, p.price)) as original_total
            FROM product_bundles pb
            LEFT JOIN bundle_items bi ON pb.id = bi.bundle_id
            LEFT JOIN products p ON bi.product_id = p.id AND p.is_active = 1
            WHERE pb.is_active = 1
            GROUP BY pb.id
            ORDER BY pb.created_at DESC
            LIMIT ? OFFSET ?
        `, [parseInt(limit), offset]);

        // Process bundles data
        const processedBundles = bundles.map(bundle => {
            let products = [];
            if (bundle.bundle_products) {
                products = bundle.bundle_products.split('|||').map(productStr => {
                    const [id, name, price] = productStr.split(':');
                    return { id: parseInt(id), name, price: parseFloat(price) };
                });
            }

            const savings = bundle.original_total ? bundle.original_total - bundle.bundle_price : 0;
            const savingsPercentage = bundle.original_total ? 
                Math.round((savings / bundle.original_total) * 100) : 0;

            return {
                ...bundle,
                bundle_products: undefined,
                original_total: undefined,
                products,
                savings,
                savings_percentage: savingsPercentage
            };
        });

        res.json({
            success: true,
            data: {
                bundles: processedBundles,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: totalBundles,
                    totalPages: Math.ceil(totalBundles / parseInt(limit))
                }
            }
        });

    } catch (error) {
        console.error('Get bundles error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/products/bundles/:id - Get Single Bundle (Public)
router.get('/bundles/:id(\\d+)', async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { id } = req.params;

        const [bundles] = await dbPool.execute(`
            SELECT * FROM product_bundles WHERE id = ? AND is_active = 1
        `, [id]);

        if (bundles.length === 0) {
            return res.status(404).json({ error: 'Bundle not found' });
        }

        const bundle = bundles[0];

        // Get bundle products
        const [products] = await dbPool.execute(`
            SELECT 
                p.*,
                c.name as category_name,
                CASE 
                    WHEN p.discount_price IS NOT NULL THEN p.discount_price
                    ELSE p.price
                END as final_price
            FROM bundle_items bi
            JOIN products p ON bi.product_id = p.id
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE bi.bundle_id = ? AND p.is_active = 1
            ORDER BY p.name
        `, [id]);

        // Calculate savings
        const originalTotal = products.reduce((sum, product) => sum + parseFloat(product.final_price), 0);
        const savings = originalTotal - bundle.bundle_price;
        const savingsPercentage = originalTotal > 0 ? Math.round((savings / originalTotal) * 100) : 0;

        // Process products
        const processedProducts = products.map(product => ({
            ...product,
            gallery: product.gallery ? JSON.parse(product.gallery) : [],
            features: product.features ? JSON.parse(product.features) : [],
            tags: product.tags ? JSON.parse(product.tags) : []
        }));

        res.json({
            success: true,
            data: {
                bundle: {
                    ...bundle,
                    products: processedProducts,
                    original_total: originalTotal,
                    savings,
                    savings_percentage: savingsPercentage
                }
            }
        });

    } catch (error) {
        console.error('Get bundle error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/products/search/suggestions - Get Search Suggestions (Public)
router.get('/search/suggestions', async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { q } = req.query;

        if (!q || q.length < 2) {
            return res.json({ success: true, data: [] });
        }

        const searchTerm = `%${q}%`;

        const [suggestions] = await dbPool.execute(`
            SELECT DISTINCT name, id
            FROM products
            WHERE is_active = 1 AND name LIKE ?
            ORDER BY total_sales DESC, name ASC
            LIMIT 8
        `, [searchTerm]);

        res.json({
            success: true,
            data: suggestions
        });

    } catch (error) {
        console.error('Get search suggestions error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/products/stats - Get Product Statistics (Public)
router.get('/stats', async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const [stats] = await dbPool.execute(`
            SELECT 
                COUNT(*) as total_products,
                COUNT(CASE WHEN product_type = 'script' THEN 1 END) as scripts_count,
                COUNT(CASE WHEN product_type = 'file' THEN 1 END) as files_count,
                COUNT(CASE WHEN is_featured = 1 THEN 1 END) as featured_count,
                AVG(CASE WHEN discount_price IS NOT NULL THEN discount_price ELSE price END) as average_price,
                SUM(total_sales) as total_sales_count
            FROM products
            WHERE is_active = 1
        `);

        const [categoryStats] = await dbPool.execute(`
            SELECT 
                c.name,
                c.icon,
                COUNT(p.id) as product_count
            FROM categories c
            LEFT JOIN products p ON c.id = p.category_id AND p.is_active = 1
            WHERE c.is_active = 1
            GROUP BY c.id
            ORDER BY product_count DESC
        `);

        res.json({
            success: true,
            data: {
                overview: stats[0],
                categories: categoryStats
            }
        });

    } catch (error) {
        console.error('Get product stats error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ==============================================
// GENERIC ROUTES - ต้องไปหลัง SPECIFIC ROUTES
// ==============================================

// GET /api/products - Get Products List (Public)
router.get('/', async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const {
            category,
            type,
            search,
            featured,
            sort = 'created_at',
            order = 'DESC',
            page = 1,
            limit = 12,
            minPrice,
            maxPrice
        } = req.query;

        let whereConditions = ['p.is_active = 1'];
        let queryParams = [];

        // Category filter
        if (category) {
            whereConditions.push('p.category_id = ?');
            queryParams.push(category);
        }

        // Product type filter
        if (type) {
            whereConditions.push('p.product_type = ?');
            queryParams.push(type);
        }

        // Search filter
        if (search) {
            whereConditions.push('(p.name LIKE ? OR p.description LIKE ? OR p.short_description LIKE ?)');
            const searchTerm = `%${search}%`;
            queryParams.push(searchTerm, searchTerm, searchTerm);
        }

        // Featured filter
        if (featured === 'true') {
            whereConditions.push('p.is_featured = 1');
        }

        // Price range filter
        if (minPrice) {
            whereConditions.push('(p.discount_price IS NOT NULL AND p.discount_price >= ?) OR (p.discount_price IS NULL AND p.price >= ?)');
            queryParams.push(minPrice, minPrice);
        }

        if (maxPrice) {
            whereConditions.push('(p.discount_price IS NOT NULL AND p.discount_price <= ?) OR (p.discount_price IS NULL AND p.price <= ?)');
            queryParams.push(maxPrice, maxPrice);
        }

        const whereClause = whereConditions.length > 0 ? 'WHERE ' + whereConditions.join(' AND ') : '';

        // Validate sort field
        const allowedSortFields = ['name', 'price', 'created_at', 'total_sales', 'rating_average'];
        const sortField = allowedSortFields.includes(sort) ? sort : 'created_at';
        const sortOrder = order.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

        // Calculate offset
        const offset = (parseInt(page) - 1) * parseInt(limit);

        // Get total count
        const countQuery = `
            SELECT COUNT(*) as total
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            ${whereClause}
        `;
        const [countResult] = await dbPool.execute(countQuery, queryParams);
        const totalProducts = countResult[0].total;

        // Get products
        const productsQuery = `
            SELECT 
                p.*,
                c.name as category_name,
                c.icon as category_icon,
                CASE 
                    WHEN p.discount_price IS NOT NULL THEN p.discount_price
                    ELSE p.price
                END as final_price,
                CASE 
                    WHEN p.discount_price IS NOT NULL THEN 
                        ROUND(((p.price - p.discount_price) / p.price) * 100, 0)
                    ELSE 0
                END as discount_percentage
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            ${whereClause}
            ORDER BY p.${sortField} ${sortOrder}
            LIMIT ? OFFSET ?
        `;

        const [products] = await dbPool.execute(productsQuery, [...queryParams, parseInt(limit), offset]);

        // Parse JSON fields
        const processedProducts = products.map(product => ({
            ...product,
            gallery: product.gallery ? JSON.parse(product.gallery) : [],
            features: product.features ? JSON.parse(product.features) : [],
            tags: product.tags ? JSON.parse(product.tags) : [],
            changelog: product.changelog ? JSON.parse(product.changelog) : []
        }));

        res.json({
            success: true,
            data: {
                products: processedProducts,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: totalProducts,
                    totalPages: Math.ceil(totalProducts / parseInt(limit))
                },
                filters: {
                    category,
                    type,
                    search,
                    featured,
                    minPrice,
                    maxPrice,
                    sort: sortField,
                    order: sortOrder
                }
            }
        });

    } catch (error) {
        console.error('Get products error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/products/:id - Get Single Product (Public) - ใช้ regex เพื่อให้แน่ใจว่าเป็นตัวเลข
router.get('/:id(\\d+)', async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { id } = req.params;

        const [products] = await dbPool.execute(`
            SELECT 
                p.*,
                c.name as category_name,
                c.icon as category_icon,
                u.username as created_by_username,
                CASE 
                    WHEN p.discount_price IS NOT NULL THEN p.discount_price
                    ELSE p.price
                END as final_price,
                CASE 
                    WHEN p.discount_price IS NOT NULL THEN 
                        ROUND(((p.price - p.discount_price) / p.price) * 100, 0)
                    ELSE 0
                END as discount_percentage
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            LEFT JOIN users u ON p.created_by = u.id
            WHERE p.id = ? AND p.is_active = 1
        `, [id]);

        if (products.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        const product = products[0];

        // Parse JSON fields
        const processedProduct = {
            ...product,
            gallery: product.gallery ? JSON.parse(product.gallery) : [],
            features: product.features ? JSON.parse(product.features) : [],
            tags: product.tags ? JSON.parse(product.tags) : [],
            changelog: product.changelog ? JSON.parse(product.changelog) : []
        };

        // Get reviews for this product
        const [reviews] = await dbPool.execute(`
            SELECT 
                r.*,
                u.username,
                u.avatar_url
            FROM reviews r
            JOIN users u ON r.user_id = u.id
            WHERE r.product_id = ? AND r.is_approved = 1
            ORDER BY r.created_at DESC
            LIMIT 10
        `, [id]);

        // Get related products
        const [relatedProducts] = await dbPool.execute(`
            SELECT 
                p.*,
                c.name as category_name,
                CASE 
                    WHEN p.discount_price IS NOT NULL THEN p.discount_price
                    ELSE p.price
                END as final_price
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE p.category_id = ? AND p.id != ? AND p.is_active = 1
            ORDER BY p.total_sales DESC, p.rating_average DESC
            LIMIT 4
        `, [product.category_id, id]);

        const processedRelatedProducts = relatedProducts.map(p => ({
            ...p,
            gallery: p.gallery ? JSON.parse(p.gallery) : [],
            features: p.features ? JSON.parse(p.features) : [],
            tags: p.tags ? JSON.parse(p.tags) : []
        }));

        res.json({
            success: true,
            data: {
                product: processedProduct,
                reviews,
                relatedProducts: processedRelatedProducts
            }
        });

    } catch (error) {
        console.error('Get product error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/products/:id/reviews - Add Product Review (Authenticated)
router.post('/:id(\\d+)/reviews', requireAuth, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { id } = req.params;
        const { rating, review_text } = req.body;
        const userId = req.user.id;

        // Validate rating
        if (!rating || rating < 1 || rating > 5) {
            return res.status(400).json({ error: 'Rating must be between 1 and 5' });
        }

        // Check if product exists
        const [products] = await dbPool.execute(
            'SELECT id FROM products WHERE id = ? AND is_active = 1',
            [id]
        );

        if (products.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        // Check if user has purchased this product
        const [purchases] = await dbPool.execute(`
            SELECT oi.id
            FROM order_items oi
            JOIN orders o ON oi.order_id = o.id
            WHERE o.user_id = ? AND oi.product_id = ? 
            AND o.payment_status = 'completed'
            LIMIT 1
        `, [userId, id]);

        const isVerifiedPurchase = purchases.length > 0;

        // Check if user already reviewed this product
        const [existingReviews] = await dbPool.execute(
            'SELECT id FROM reviews WHERE user_id = ? AND product_id = ?',
            [userId, id]
        );

        if (existingReviews.length > 0) {
            return res.status(400).json({ error: 'You have already reviewed this product' });
        }

        // Create review
        const [result] = await dbPool.execute(`
            INSERT INTO reviews (user_id, product_id, order_item_id, rating, review_text, is_verified_purchase)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [userId, id, purchases[0]?.id || null, rating, review_text, isVerifiedPurchase]);

        // Update product rating
        const [ratingStats] = await dbPool.execute(`
            SELECT AVG(rating) as avg_rating, COUNT(*) as rating_count
            FROM reviews
            WHERE product_id = ? AND is_approved = 1
        `, [id]);

        await dbPool.execute(`
            UPDATE products
            SET rating_average = ?, rating_count = ?
            WHERE id = ?
        `, [ratingStats[0].avg_rating || 0, ratingStats[0].rating_count || 0, id]);

        // Log activity
        await logActivity(userId, 'review_created', 'review', result.insertId, { product_id: id, rating }, req);

        res.status(201).json({
            success: true,
            message: 'Review submitted successfully',
            data: {
                id: result.insertId,
                rating,
                review_text,
                is_verified_purchase: isVerifiedPurchase
            }
        });

    } catch (error) {
        console.error('Add review error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/products/:id/trial - Request Trial Access (Authenticated)
router.post('/:id(\\d+)/trial', requireAuth, async (req, res) => {
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

        // Check if product exists and supports trials
        const [products] = await dbPool.execute(`
            SELECT * FROM products 
            WHERE id = ? AND is_active = 1 AND product_type = 'script'
        `, [id]);

        if (products.length === 0) {
            return res.status(404).json({ error: 'Product not found or does not support trials' });
        }

        const product = products[0];

        // Check if user already has an active trial for this product
        const [existingTrials] = await dbPool.execute(`
            SELECT id FROM trials
            WHERE user_id = ? AND product_id = ? AND is_active = 1 AND expires_at > NOW()
        `, [userId, id]);

        if (existingTrials.length > 0) {
            return res.status(400).json({ error: 'You already have an active trial for this product' });
        }

        // Check trial limits (from site settings)
        const [settings] = await dbPool.execute(`
            SELECT setting_value FROM site_settings 
            WHERE setting_key IN ('trial_duration_default', 'max_trials_per_user')
        `);

        const settingsMap = {};
        settings.forEach(setting => {
            settingsMap[setting.setting_key] = setting.setting_value;
        });

        const trialDuration = parseInt(settingsMap.trial_duration_default || 24);
        const maxTrialsPerUser = parseInt(settingsMap.max_trials_per_user || 1);

        // Check if user has exceeded trial limit for this product
        const [trialCount] = await dbPool.execute(`
            SELECT COUNT(*) as count FROM trials
            WHERE user_id = ? AND product_id = ?
        `, [userId, id]);

        if (trialCount[0].count >= maxTrialsPerUser) {
            return res.status(400).json({ 
                error: `You have reached the maximum number of trials (${maxTrialsPerUser}) for this product` 
            });
        }

        // Generate trial token
        const trialToken = `Trial-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`.toUpperCase();
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + trialDuration);

        // Create trial
        const [result] = await dbPool.execute(`
            INSERT INTO trials (user_id, product_id, trial_token, duration_hours, expires_at)
            VALUES (?, ?, ?, ?, ?)
        `, [userId, id, trialToken, trialDuration, expiresAt]);

        // Log activity
        await logActivity(userId, 'trial_requested', 'trial', result.insertId, { 
            product_id: id, 
            trial_token: trialToken,
            duration_hours: trialDuration 
        }, req);

        res.status(201).json({
            success: true,
            message: 'Trial access granted',
            data: {
                trial_token: trialToken,
                product_name: product.name,
                duration_hours: trialDuration,
                expires_at: expiresAt.toISOString()
            }
        });

    } catch (error) {
        console.error('Request trial error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;