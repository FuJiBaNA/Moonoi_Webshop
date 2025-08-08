// routes/index.js 
const express = require('express');
const path = require('path');

const router = express.Router();

// Function to get database pool
let getDbPool;
try {
    const serverModule = require('../server');
    getDbPool = serverModule.dbPool;
} catch (error) {
    console.error('Failed to import server module:', error);
    getDbPool = () => null;
}

// ==============================================
// DEBUG ROUTES - ต้องมาก่อน HEALTH CHECK
// ==============================================
if (process.env.NODE_ENV !== 'production') {
    // GET /api/debug/routes - Show all available routes
    router.get('/debug/routes', (req, res) => {
        const routes = [];
        
        function extractRoutes(stack, basePath = '') {
            stack.forEach((layer) => {
                if (layer.route) {
                    const path = basePath + layer.route.path;
                    const methods = Object.keys(layer.route.methods).join(', ').toUpperCase();
                    routes.push({ 
                        path, 
                        methods,
                        middleware_count: layer.route.stack ? layer.route.stack.length : 0
                    });
                } else if (layer.name === 'router' && layer.handle.stack) {
                    let routerPath = '';
                    if (layer.regexp && layer.regexp.source) {
                        routerPath = layer.regexp.source
                            .replace('\\/?', '')
                            .replace('(?=\\/|$)', '')
                            .replace('^', '')
                            .replace('$', '');
                    }
                    extractRoutes(layer.handle.stack, basePath + routerPath);
                }
            });
        }
        
        // Get main app routes
        const app = req.app;
        if (app._router && app._router.stack) {
            extractRoutes(app._router.stack);
        }
        
        // Get current router routes
        if (router.stack) {
            extractRoutes(router.stack, '/api');
        }
        
        const categorizedRoutes = {
            debug: routes.filter(r => r.path.includes('/debug/')),
            public: routes.filter(r => !r.path.includes('/debug/') && !r.path.includes('/admin') && !r.path.includes('/auth')),
            auth: routes.filter(r => r.path.includes('/auth')),
            admin: routes.filter(r => r.path.includes('/admin')),
            other: routes.filter(r => !r.path.includes('/debug/') && !r.path.includes('/admin') && !r.path.includes('/auth'))
        };
        
        res.json({
            success: true,
            message: 'Available API routes',
            server_info: {
                environment: process.env.NODE_ENV || 'development',
                total_routes: routes.length,
                timestamp: new Date().toISOString()
            },
            routes: {
                all: routes.sort((a, b) => a.path.localeCompare(b.path)),
                categorized: categorizedRoutes
            }
        });
    });

    // GET /api/debug/database - Database status and info
    router.get('/debug/database', async (req, res) => {
        try {
            const dbPool = getDbPool();
            
            if (!dbPool) {
                return res.json({
                    success: false,
                    status: 'not_available',
                    message: 'Database pool not initialized'
                });
            }

            const [result] = await dbPool.execute('SELECT 1 as test, NOW() as current_time, VERSION() as db_version');
            
            // Get table information
            const [tables] = await dbPool.execute('SHOW TABLES');
            
            // Get pool status if available
            let poolInfo = {};
            try {
                if (dbPool.pool) {
                    poolInfo = {
                        all_connections: dbPool.pool.allConnections?.length || 'N/A',
                        free_connections: dbPool.pool.freeConnections?.length || 'N/A',
                        acquire_requests: dbPool.pool.acquiringConnections?.length || 'N/A'
                    };
                }
            } catch (poolError) {
                poolInfo = { error: 'Pool info not available' };
            }
            
            res.json({
                success: true,
                status: 'connected',
                database_info: result[0],
                tables: tables.map(t => Object.values(t)[0]),
                pool_info: poolInfo,
                connection_config: {
                    host: process.env.DB_HOST || 'localhost',
                    database: process.env.DB_NAME || 'scriptshop_db',
                    port: process.env.DB_PORT || 3306
                }
            });
            
        } catch (error) {
            res.json({
                success: false,
                status: 'error',
                error: error.message,
                code: error.code
            });
        }
    });

    // GET /api/debug/test/:module - Test specific modules
    router.get('/debug/test/:module', async (req, res) => {
        const { module } = req.params;
        
        const testEndpoints = {
            auth: {
                description: 'Authentication endpoints',
                endpoints: [
                    'POST /api/auth/login',
                    'POST /api/auth/register', 
                    'GET /api/auth/me'
                ],
                test_url: '/api/auth/me'
            },
            products: {
                description: 'Product management endpoints',
                endpoints: [
                    'GET /api/products',
                    'GET /api/products/categories',
                    'GET /api/products/featured'
                ],
                test_url: '/api/products'
            },
            orders: {
                description: 'Order management endpoints',
                endpoints: [
                    'GET /api/orders/cart',
                    'POST /api/orders/cart/add',
                    'GET /api/orders'
                ],
                test_url: '/api/orders/cart'
            },
            admin: {
                description: 'Admin panel endpoints',
                endpoints: [
                    'GET /api/admin/dashboard',
                    'GET /api/admin/users',
                    'GET /api/admin/settings'
                ],
                test_url: '/api/admin/dashboard'
            },
            payments: {
                description: 'Payment processing endpoints',
                endpoints: [
                    'GET /api/payments/methods',
                    'GET /api/payments/history',
                    'POST /api/payments/truewallet'
                ],
                test_url: '/api/payments/methods'
            },
            licenses: {
                description: 'License verification endpoints',
                endpoints: [
                    'POST /api/licenses/verify',
                    'GET /api/licenses',
                    'GET /api/licenses/trials'
                ],
                test_url: '/api/licenses'
            }
        };
        
        const moduleInfo = testEndpoints[module];
        
        if (!moduleInfo) {
            return res.status(404).json({
                success: false,
                error: 'Module not found',
                available_modules: Object.keys(testEndpoints)
            });
        }
        
        res.json({
            success: true,
            module,
            ...moduleInfo,
            instructions: {
                manual_test: `curl ${req.protocol}://${req.get('host')}${moduleInfo.test_url}`,
                browser_test: `${req.protocol}://${req.get('host')}${moduleInfo.test_url}`
            }
        });
    });

    // GET /api/debug/env - Environment variables (safe ones only)
    router.get('/debug/env', (req, res) => {
        const safeEnvVars = {
            NODE_ENV: process.env.NODE_ENV,
            PORT: process.env.PORT,
            DB_HOST: process.env.DB_HOST,
            DB_NAME: process.env.DB_NAME,
            DB_PORT: process.env.DB_PORT,
            SITE_NAME: process.env.SITE_NAME,
            SITE_URL: process.env.SITE_URL
        };
        
        res.json({
            success: true,
            environment_variables: safeEnvVars,
            process_info: {
                node_version: process.version,
                platform: process.platform,
                uptime: process.uptime(),
                memory_usage: process.memoryUsage()
            }
        });
    });
}

// ==============================================
// HEALTH CHECK - ต้องมาก่อน ROUTES อื่นๆ
// ==============================================
router.get('/health', async (req, res) => {
    try {
        const dbPool = getDbPool();
        let dbStatus = 'disconnected';
        let dbTestResult = null;
        
        if (dbPool) {
            try {
                const [result] = await dbPool.execute('SELECT 1 as test, NOW() as current_time');
                dbStatus = result[0].test === 1 ? 'connected' : 'error';
                dbTestResult = result[0];
            } catch (dbError) {
                dbStatus = 'error';
                console.error('Health check DB error:', dbError.message);
            }
        }
        
        res.json({
            success: true,
            message: 'API is healthy',
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
            message: 'API health check failed',
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// ==============================================
// IMPORT ROUTE MODULES WITH ERROR HANDLING
// ==============================================
let authRoutes, productRoutes, orderRoutes, paymentRoutes, licenseRoutes, adminRoutes;

try {
    authRoutes = require('./auth');
    console.log('✅ Auth routes loaded');
} catch (error) {
    console.error('❌ Failed to load auth routes:', error.message);
    authRoutes = express.Router();
    authRoutes.all('*', (req, res) => res.status(503).json({ 
        success: false,
        error: 'Auth service unavailable',
        details: error.message 
    }));
}

try {
    productRoutes = require('./products');
    console.log('✅ Product routes loaded');
} catch (error) {
    console.error('❌ Failed to load product routes:', error.message);
    productRoutes = express.Router();
    productRoutes.all('*', (req, res) => res.status(503).json({ 
        success: false,
        error: 'Product service unavailable',
        details: error.message 
    }));
}

try {
    orderRoutes = require('./orders');
    console.log('✅ Order routes loaded');
} catch (error) {
    console.error('❌ Failed to load order routes:', error.message);
    orderRoutes = express.Router();
    orderRoutes.all('*', (req, res) => res.status(503).json({ 
        success: false,
        error: 'Order service unavailable',
        details: error.message 
    }));
}

try {
    paymentRoutes = require('./payments');
    console.log('✅ Payment routes loaded');
} catch (error) {
    console.error('❌ Failed to load payment routes:', error.message);
    paymentRoutes = express.Router();
    paymentRoutes.all('*', (req, res) => res.status(503).json({ 
        success: false,
        error: 'Payment service unavailable',
        details: error.message 
    }));
}

try {
    licenseRoutes = require('./licenses');
    console.log('✅ License routes loaded');
} catch (error) {
    console.error('❌ Failed to load license routes:', error.message);
    licenseRoutes = express.Router();
    licenseRoutes.all('*', (req, res) => res.status(503).json({ 
        success: false,
        error: 'License service unavailable',
        details: error.message 
    }));
}

try {
    adminRoutes = require('./admin');
    console.log('✅ Admin routes loaded');
} catch (error) {
    console.error('❌ Failed to load admin routes:', error.message);
    adminRoutes = express.Router();
    adminRoutes.all('*', (req, res) => res.status(503).json({ 
        success: false,
        error: 'Admin service unavailable',
        details: error.message 
    }));
}

// ==============================================
// MOUNT ALL ROUTES WITH PROPER ORDER
// ==============================================
router.use('/auth', authRoutes);
router.use('/admin', adminRoutes);
router.use('/products', productRoutes);
router.use('/orders', orderRoutes);
router.use('/payments', paymentRoutes);
router.use('/licenses', licenseRoutes);

// ==============================================
// PUBLIC API ENDPOINTS
// ==============================================

// GET /api/announcements - Get Public Announcements
router.get('/announcements', async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { target = 'all' } = req.query;

        let whereConditions = ['a.is_active = 1'];
        let queryParams = [];

        // Filter by target audience
        if (target !== 'all') {
            whereConditions.push('(a.target_audience = ? OR a.target_audience = "all")');
            queryParams.push(target);
        } else {
            whereConditions.push('a.target_audience = "all"');
        }

        // Filter by date range
        whereConditions.push('(a.starts_at IS NULL OR a.starts_at <= NOW())');
        whereConditions.push('(a.ends_at IS NULL OR a.ends_at >= NOW())');

        const whereClause = 'WHERE ' + whereConditions.join(' AND ');

        const [announcements] = await dbPool.execute(`
            SELECT 
                a.*,
                u.username as created_by_username
            FROM announcements a
            LEFT JOIN users u ON a.created_by = u.id
            ${whereClause}
            ORDER BY a.is_sticky DESC, a.created_at DESC
            LIMIT 10
        `, queryParams);

        res.json({
            success: true,
            data: announcements
        });

    } catch (error) {
        console.error('Get announcements error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Internal server error' 
        });
    }
});

// GET /api/site-info - Get Public Site Information
router.get('/site-info', async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        // Get public site settings
        const [settings] = await dbPool.execute(`
            SELECT setting_key, setting_value, setting_type
            FROM site_settings 
            WHERE is_public = 1
        `);

        // Process settings
        const siteInfo = {};
        settings.forEach(setting => {
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
            siteInfo[setting.setting_key] = value;
        });

        // Get basic statistics
        const [stats] = await dbPool.execute(`
            SELECT 
                (SELECT COUNT(*) FROM products WHERE is_active = 1) as total_products,
                (SELECT COUNT(*) FROM users WHERE is_active = 1) as total_users,
                (SELECT COUNT(*) FROM orders WHERE order_status = 'completed') as total_orders,
                (SELECT COUNT(*) FROM categories WHERE is_active = 1) as total_categories
        `);

        res.json({
            success: true,
            data: {
                site_info: siteInfo,
                statistics: stats[0]
            }
        });

    } catch (error) {
        console.error('Get site info error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Internal server error' 
        });
    }
});

// GET /api/search - Global Search
router.get('/search', async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { q, type = 'all', limit = 20 } = req.query;

        if (!q || q.length < 2) {
            return res.json({
                success: true,
                data: {
                    products: [],
                    bundles: [],
                    categories: []
                }
            });
        }

        const searchTerm = `%${q}%`;
        const searchLimit = parseInt(limit);

        let results = {};

        // Search products
        if (type === 'all' || type === 'products') {
            const [products] = await dbPool.execute(`
                SELECT 
                    p.id, p.name, p.short_description, p.price, p.discount_price, 
                    p.image_url, p.product_type, p.total_sales,
                    c.name as category_name,
                    CASE 
                        WHEN p.discount_price IS NOT NULL THEN p.discount_price
                        ELSE p.price
                    END as final_price
                FROM products p
                LEFT JOIN categories c ON p.category_id = c.id
                WHERE p.is_active = 1 
                AND (p.name LIKE ? OR p.description LIKE ? OR p.short_description LIKE ?)
                ORDER BY p.total_sales DESC, p.name ASC
                LIMIT ?
            `, [searchTerm, searchTerm, searchTerm, searchLimit]);

            results.products = products;
        }

        // Search categories
        if (type === 'all' || type === 'categories') {
            const [categories] = await dbPool.execute(`
                SELECT 
                    c.id, c.name, c.description, c.icon,
                    COUNT(p.id) as product_count
                FROM categories c
                LEFT JOIN products p ON c.id = p.category_id AND p.is_active = 1
                WHERE c.is_active = 1 
                AND (c.name LIKE ? OR c.description LIKE ?)
                GROUP BY c.id
                ORDER BY product_count DESC, c.name ASC
                LIMIT ?
            `, [searchTerm, searchTerm, Math.min(searchLimit, 10)]);

            results.categories = categories;
        }

        res.json({
            success: true,
            data: results
        });

    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Internal server error' 
        });
    }
});

// POST /api/contact - Contact Form (Public)
router.post('/contact', async (req, res) => {
    try {
        const dbPool = getDbPool();
        const { name, email, subject, message } = req.body;

        if (!name || !email || !subject || !message) {
            return res.status(400).json({ 
                success: false,
                error: 'All fields are required' 
            });
        }

        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ 
                success: false,
                error: 'Invalid email format' 
            });
        }

        // In a real application, you would send an email or store in database
        console.log('Contact form submission:', { name, email, subject, message });

        // Log to activity logs if database is available
        if (dbPool) {
            try {
                await dbPool.execute(`
                    INSERT INTO activity_logs (action, entity_type, details, ip_address)
                    VALUES ('contact_form', 'contact', ?, ?)
                `, [
                    JSON.stringify({ name, email, subject, message }),
                    req.ip || req.connection.remoteAddress
                ]);
            } catch (dbError) {
                console.warn('Failed to log contact form submission:', dbError.message);
            }
        }

        res.json({
            success: true,
            message: 'Message sent successfully. We will get back to you soon!'
        });

    } catch (error) {
        console.error('Contact form error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Internal server error' 
        });
    }
});

// GET /api/stats/public - Public Statistics
router.get('/stats/public', async (req, res) => {
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
                (SELECT COUNT(*) FROM products WHERE is_active = 1) as total_products,
                (SELECT COUNT(*) FROM products WHERE is_active = 1 AND product_type = 'script') as total_scripts,
                (SELECT COUNT(*) FROM users WHERE is_active = 1) as total_users,
                (SELECT COUNT(*) FROM orders WHERE order_status = 'completed') as total_sales,
                (SELECT COUNT(*) FROM licenses WHERE is_active = 1) as active_licenses,
                (SELECT COALESCE(SUM(total_amount), 0) FROM orders WHERE order_status = 'completed') as total_revenue
        `);

        // Get top categories
        const [topCategories] = await dbPool.execute(`
            SELECT 
                c.name,
                c.icon,
                COUNT(p.id) as product_count
            FROM categories c
            LEFT JOIN products p ON c.id = p.category_id AND p.is_active = 1
            WHERE c.is_active = 1
            GROUP BY c.id
            HAVING product_count > 0
            ORDER BY product_count DESC
            LIMIT 6
        `);

        res.json({
            success: true,
            data: {
                overview: stats[0],
                top_categories: topCategories
            }
        });

    } catch (error) {
        console.error('Get public stats error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Internal server error' 
        });
    }
});

// GET /api/categories - Get all categories (public)
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
        res.status(500).json({ 
            success: false,
            error: 'Internal server error' 
        });
    }
});

// ==============================================
// 404 HANDLER FOR API ROUTES
// ==============================================
router.use((req, res) => {
    console.log(`404 - API Route not found: ${req.method} ${req.originalUrl}`);
    
    const availableEndpoints = [
        'GET /api/health - Health check',
        'GET /api/announcements - Public announcements', 
        'GET /api/site-info - Site information',
        'GET /api/search - Global search',
        'POST /api/contact - Contact form',
        'GET /api/stats/public - Public statistics',
        'GET /api/categories - Product categories',
        'GET /api/auth/* - Authentication endpoints',
        'GET /api/products/* - Product endpoints',
        'GET /api/orders/* - Order endpoints',
        'GET /api/payments/* - Payment endpoints',
        'GET /api/licenses/* - License endpoints',
        'GET /api/admin/* - Admin endpoints'
    ];
    
    const debugEndpoints = process.env.NODE_ENV !== 'production' ? [
        'GET /api/debug/routes - List all routes',
        'GET /api/debug/database - Database status',
        'GET /api/debug/test/:module - Test specific module',
        'GET /api/debug/env - Environment info'
    ] : [];
    
    res.status(404).json({
        success: false,
        message: 'API endpoint not found',
        path: req.originalUrl,
        method: req.method,
        timestamp: new Date().toISOString(),
        available_endpoints: availableEndpoints,
        debug_endpoints: debugEndpoints
    });
});

module.exports = router;