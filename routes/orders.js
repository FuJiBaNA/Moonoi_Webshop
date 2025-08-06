// routes/orders.js - Order Management Routes (แก้ไขการเข้าถึงฐานข้อมูล)
const express = require('express');
const crypto = require('crypto');

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

// Helper function to generate order number
function generateOrderNumber() {
    const timestamp = Date.now().toString();
    const random = Math.random().toString(36).substr(2, 6).toUpperCase();
    return `ORD-${timestamp.substr(-8)}-${random}`;
}

// Helper function to generate license key
function generateLicenseKey() {
    const segments = [];
    for (let i = 0; i < 4; i++) {
        segments.push(crypto.randomBytes(2).toString('hex').toUpperCase());
    }
    return 'LICENSE-' + segments.join('-');
}

// Helper function to calculate final price
function calculateFinalPrice(product) {
    return product.discount_price || product.price;
}

// POST /api/orders/cart/add - Add Item to Cart
router.post('/cart/add', requireAuth, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { product_id, bundle_id, quantity = 1 } = req.body;
        const userId = req.user.id;

        if (!product_id && !bundle_id) {
            return res.status(400).json({ error: 'Product ID or Bundle ID is required' });
        }

        if (product_id && bundle_id) {
            return res.status(400).json({ error: 'Cannot add both product and bundle in the same request' });
        }

        // Validate quantity
        const qty = parseInt(quantity);
        if (qty < 1 || qty > 10) {
            return res.status(400).json({ error: 'Quantity must be between 1 and 10' });
        }

        let item = null;

        if (product_id) {
            // Get product details
            const [products] = await dbPool.execute(`
                SELECT id, name, price, discount_price, stock_quantity, is_active
                FROM products 
                WHERE id = ? AND is_active = 1
            `, [product_id]);

            if (products.length === 0) {
                return res.status(404).json({ error: 'Product not found' });
            }

            const product = products[0];

            // Check stock
            if (product.stock_quantity !== -1 && product.stock_quantity < qty) {
                return res.status(400).json({ error: 'Insufficient stock' });
            }

            item = {
                product_id: product.id,
                bundle_id: null,
                item_type: 'product',
                name: product.name,
                unit_price: calculateFinalPrice(product),
                quantity: qty,
                total_price: calculateFinalPrice(product) * qty
            };

        } else if (bundle_id) {
            // Get bundle details
            const [bundles] = await dbPool.execute(`
                SELECT id, name, bundle_price, is_active
                FROM product_bundles 
                WHERE id = ? AND is_active = 1
            `, [bundle_id]);

            if (bundles.length === 0) {
                return res.status(404).json({ error: 'Bundle not found' });
            }

            const bundle = bundles[0];

            item = {
                product_id: null,
                bundle_id: bundle.id,
                item_type: 'bundle',
                name: bundle.name,
                unit_price: bundle.bundle_price,
                quantity: qty,
                total_price: bundle.bundle_price * qty
            };
        }

        // Store in session (simple cart implementation)
        if (!req.session.cart) {
            req.session.cart = [];
        }

        // Check if item already exists in cart
        const existingItemIndex = req.session.cart.findIndex(cartItem => 
            cartItem.product_id === item.product_id && cartItem.bundle_id === item.bundle_id
        );

        if (existingItemIndex >= 0) {
            // Update existing item
            req.session.cart[existingItemIndex].quantity += qty;
            req.session.cart[existingItemIndex].total_price = 
                req.session.cart[existingItemIndex].unit_price * req.session.cart[existingItemIndex].quantity;
        } else {
            // Add new item
            req.session.cart.push(item);
        }

        // Calculate cart totals
        const cartTotal = req.session.cart.reduce((sum, cartItem) => sum + cartItem.total_price, 0);
        const cartItemCount = req.session.cart.reduce((sum, cartItem) => sum + cartItem.quantity, 0);

        res.json({
            success: true,
            message: 'Item added to cart',
            data: {
                cart: req.session.cart,
                cart_total: cartTotal,
                cart_item_count: cartItemCount
            }
        });

    } catch (error) {
        console.error('Add to cart error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/orders/cart - Get Cart Contents
router.get('/cart', requireAuth, async (req, res) => {
    try {
        const cart = req.session.cart || [];
        const cartTotal = cart.reduce((sum, item) => sum + item.total_price, 0);
        const cartItemCount = cart.reduce((sum, item) => sum + item.quantity, 0);

        res.json({
            success: true,
            data: {
                cart,
                cart_total: cartTotal,
                cart_item_count: cartItemCount
            }
        });

    } catch (error) {
        console.error('Get cart error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// PUT /api/orders/cart/update - Update Cart Item
router.put('/cart/update', requireAuth, async (req, res) => {
    try {
        const { index, quantity } = req.body;
        
        if (!req.session.cart || !req.session.cart[index]) {
            return res.status(404).json({ error: 'Cart item not found' });
        }

        const qty = parseInt(quantity);
        if (qty < 1 || qty > 10) {
            return res.status(400).json({ error: 'Quantity must be between 1 and 10' });
        }

        // Update item
        req.session.cart[index].quantity = qty;
        req.session.cart[index].total_price = req.session.cart[index].unit_price * qty;

        const cartTotal = req.session.cart.reduce((sum, item) => sum + item.total_price, 0);
        const cartItemCount = req.session.cart.reduce((sum, item) => sum + item.quantity, 0);

        res.json({
            success: true,
            message: 'Cart updated',
            data: {
                cart: req.session.cart,
                cart_total: cartTotal,
                cart_item_count: cartItemCount
            }
        });

    } catch (error) {
        console.error('Update cart error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// DELETE /api/orders/cart/remove/:index - Remove Cart Item
router.delete('/cart/remove/:index', requireAuth, async (req, res) => {
    try {
        const { index } = req.params;
        
        if (!req.session.cart || !req.session.cart[index]) {
            return res.status(404).json({ error: 'Cart item not found' });
        }

        req.session.cart.splice(index, 1);

        const cartTotal = req.session.cart.reduce((sum, item) => sum + item.total_price, 0);
        const cartItemCount = req.session.cart.reduce((sum, item) => sum + item.quantity, 0);

        res.json({
            success: true,
            message: 'Item removed from cart',
            data: {
                cart: req.session.cart,
                cart_total: cartTotal,
                cart_item_count: cartItemCount
            }
        });

    } catch (error) {
        console.error('Remove from cart error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// DELETE /api/orders/cart/clear - Clear Cart
router.delete('/cart/clear', requireAuth, async (req, res) => {
    try {
        req.session.cart = [];

        res.json({
            success: true,
            message: 'Cart cleared',
            data: {
                cart: [],
                cart_total: 0,
                cart_item_count: 0
            }
        });

    } catch (error) {
        console.error('Clear cart error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/orders/checkout - Process Order Checkout
router.post('/checkout', requireAuth, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const userId = req.user.id;
        const cart = req.session.cart || [];

        if (cart.length === 0) {
            return res.status(400).json({ error: 'Cart is empty' });
        }

        // Calculate total
        const totalAmount = cart.reduce((sum, item) => sum + item.total_price, 0);

        // Check user credits
        const [userResult] = await dbPool.execute('SELECT credits FROM users WHERE id = ?', [userId]);
        const userCredits = parseFloat(userResult[0].credits);

        if (userCredits < totalAmount) {
            return res.status(400).json({ 
                error: 'Insufficient credits', 
                required: totalAmount, 
                available: userCredits 
            });
        }

        // Start transaction
        const connection = await dbPool.getConnection();
        await connection.beginTransaction();

        try {
            // Generate order number
            const orderNumber = generateOrderNumber();

            // Create order
            const [orderResult] = await connection.execute(`
                INSERT INTO orders (order_number, user_id, total_amount, credits_used, payment_method, payment_status, order_status)
                VALUES (?, ?, ?, ?, 'credits', 'completed', 'processing')
            `, [orderNumber, userId, totalAmount, totalAmount]);

            const orderId = orderResult.insertId;

            // Process each cart item
            for (const item of cart) {
                let licenseKey = null;
                let licenseExpiresAt = null;

                // Create order item
                const [orderItemResult] = await connection.execute(`
                    INSERT INTO order_items (order_id, product_id, bundle_id, item_type, quantity, unit_price, total_price)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                `, [orderId, item.product_id, item.bundle_id, item.item_type, item.quantity, item.unit_price, item.total_price]);

                const orderItemId = orderItemResult.insertId;

                // Handle product-specific logic
                if (item.item_type === 'product') {
                    // Get product details
                    const [products] = await connection.execute(`
                        SELECT * FROM products WHERE id = ?
                    `, [item.product_id]);

                    const product = products[0];

                    // Generate license if needed
                    if (product.requires_license) {
                        licenseKey = generateLicenseKey();
                        
                        if (product.is_rental && product.rental_duration_days) {
                            licenseExpiresAt = new Date();
                            licenseExpiresAt.setDate(licenseExpiresAt.getDate() + product.rental_duration_days);
                        }

                        // Update order item with license
                        await connection.execute(`
                            UPDATE order_items 
                            SET license_key = ?, license_expires_at = ?
                            WHERE id = ?
                        `, [licenseKey, licenseExpiresAt, orderItemId]);

                        // Create license record
                        await connection.execute(`
                            INSERT INTO licenses (license_key, user_id, product_id, order_item_id, is_permanent, expires_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                        `, [licenseKey, userId, item.product_id, orderItemId, !product.is_rental, licenseExpiresAt]);
                    }

                    // Update product sales count
                    await connection.execute(`
                        UPDATE products 
                        SET total_sales = total_sales + ?
                        WHERE id = ?
                    `, [item.quantity, item.product_id]);

                    // Update stock if not unlimited
                    if (product.stock_quantity !== -1) {
                        await connection.execute(`
                            UPDATE products 
                            SET stock_quantity = stock_quantity - ?
                            WHERE id = ?
                        `, [item.quantity, item.product_id]);
                    }

                } else if (item.item_type === 'bundle') {
                    // Handle bundle - create licenses for all script products in bundle
                    const [bundleProducts] = await connection.execute(`
                        SELECT p.*
                        FROM bundle_items bi
                        JOIN products p ON bi.product_id = p.id
                        WHERE bi.bundle_id = ? AND p.requires_license = 1
                    `, [item.bundle_id]);

                    for (const bundleProduct of bundleProducts) {
                        const bundleLicenseKey = generateLicenseKey();
                        let bundleLicenseExpiresAt = null;

                        if (bundleProduct.is_rental && bundleProduct.rental_duration_days) {
                            bundleLicenseExpiresAt = new Date();
                            bundleLicenseExpiresAt.setDate(bundleLicenseExpiresAt.getDate() + bundleProduct.rental_duration_days);
                        }

                        // Create license record for bundle product
                        await connection.execute(`
                            INSERT INTO licenses (license_key, user_id, product_id, order_item_id, is_permanent, expires_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                        `, [bundleLicenseKey, userId, bundleProduct.id, orderItemId, !bundleProduct.is_rental, bundleLicenseExpiresAt]);

                        // Update product sales count
                        await connection.execute(`
                            UPDATE products 
                            SET total_sales = total_sales + 1
                            WHERE id = ?
                        `, [bundleProduct.id]);
                    }
                }
            }

            // Deduct credits from user
            await connection.execute(`
                UPDATE users 
                SET credits = credits - ?, total_spent = total_spent + ?
                WHERE id = ?
            `, [totalAmount, totalAmount, userId]);

            // Record credit transaction
            const newBalance = userCredits - totalAmount;
            await connection.execute(`
                INSERT INTO credit_transactions 
                (user_id, transaction_type, amount, balance_before, balance_after, reference_type, reference_id, description)
                VALUES (?, 'purchase', ?, ?, ?, 'order', ?, ?)
            `, [userId, -totalAmount, userCredits, newBalance, orderId, `Order ${orderNumber}`]);

            // Mark order as completed
            await connection.execute(`
                UPDATE orders 
                SET order_status = 'completed', completed_at = NOW()
                WHERE id = ?
            `, [orderId]);

            await connection.commit();

            // Clear cart
            req.session.cart = [];

            // Log activity
            await logActivity(userId, 'order_completed', 'order', orderId, {
                order_number: orderNumber,
                total_amount: totalAmount,
                items_count: cart.length
            }, req);

            res.json({
                success: true,
                message: 'Order completed successfully',
                data: {
                    order_id: orderId,
                    order_number: orderNumber,
                    total_amount: totalAmount,
                    new_balance: newBalance
                }
            });

        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }

    } catch (error) {
        console.error('Checkout error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/orders - Get User Orders
router.get('/', requireAuth, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { page = 1, limit = 10, status } = req.query;
        const userId = req.user.id;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        let whereCondition = 'WHERE o.user_id = ?';
        let queryParams = [userId];

        if (status) {
            whereCondition += ' AND o.order_status = ?';
            queryParams.push(status);
        }

        // Get total count
        const [countResult] = await dbPool.execute(`
            SELECT COUNT(*) as total FROM orders o ${whereCondition}
        `, queryParams);
        const totalOrders = countResult[0].total;

        // Get orders
        const [orders] = await dbPool.execute(`
            SELECT 
                o.*,
                COUNT(oi.id) as items_count
            FROM orders o
            LEFT JOIN order_items oi ON o.id = oi.order_id
            ${whereCondition}
            GROUP BY o.id
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
        console.error('Get orders error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/orders/:id - Get Single Order Details
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

        // Get order
        const [orders] = await dbPool.execute(`
            SELECT * FROM orders 
            WHERE id = ? AND user_id = ?
        `, [id, userId]);

        if (orders.length === 0) {
            return res.status(404).json({ error: 'Order not found' });
        }

        const order = orders[0];

        // Get order items
        const [orderItems] = await dbPool.execute(`
            SELECT 
                oi.*,
                p.name as product_name,
                p.image_url as product_image,
                p.file_path,
                p.requires_discord,
                pb.name as bundle_name
            FROM order_items oi
            LEFT JOIN products p ON oi.product_id = p.id
            LEFT JOIN product_bundles pb ON oi.bundle_id = pb.id
            WHERE oi.order_id = ?
            ORDER BY oi.id
        `, [id]);

        // Get licenses for this order
        const [licenses] = await dbPool.execute(`
            SELECT 
                l.*,
                p.name as product_name
            FROM licenses l
            JOIN products p ON l.product_id = p.id
            JOIN order_items oi ON l.order_item_id = oi.id
            WHERE oi.order_id = ?
        `, [id]);

        res.json({
            success: true,
            data: {
                order,
                items: orderItems,
                licenses
            }
        });

    } catch (error) {
        console.error('Get order details error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/orders/:id/download/:item_id - Download Product File
router.post('/:id/download/:item_id', requireAuth, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { id, item_id } = req.params;
        const userId = req.user.id;

        // Verify order ownership and get item details
        const [orderItems] = await dbPool.execute(`
            SELECT 
                oi.*,
                o.user_id,
                o.order_status,
                p.file_path,
                p.download_limit,
                p.name as product_name
            FROM order_items oi
            JOIN orders o ON oi.order_id = o.id
            JOIN products p ON oi.product_id = p.id
            WHERE oi.id = ? AND oi.order_id = ? AND o.user_id = ?
        `, [item_id, id, userId]);

        if (orderItems.length === 0) {
            return res.status(404).json({ error: 'Order item not found' });
        }

        const orderItem = orderItems[0];

        // Check if order is completed
        if (orderItem.order_status !== 'completed') {
            return res.status(400).json({ error: 'Order is not completed yet' });
        }

        // Check download limit
        if (orderItem.download_limit !== -1 && orderItem.download_count >= orderItem.download_limit) {
            return res.status(400).json({ error: 'Download limit exceeded' });
        }

        // Check if file exists
        if (!orderItem.file_path) {
            return res.status(404).json({ error: 'File not available for download' });
        }

        // Update download count
        await dbPool.execute(`
            UPDATE order_items 
            SET download_count = download_count + 1
            WHERE id = ?
        `, [item_id]);

        // Log activity
        await logActivity(userId, 'file_downloaded', 'order_item', item_id, {
            product_name: orderItem.product_name,
            download_count: orderItem.download_count + 1
        }, req);

        // Return download info (in a real app, you'd stream the file)
        res.json({
            success: true,
            message: 'Download initiated',
            data: {
                file_path: orderItem.file_path,
                product_name: orderItem.product_name,
                download_count: orderItem.download_count + 1,
                download_limit: orderItem.download_limit
            }
        });

    } catch (error) {
        console.error('Download file error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;