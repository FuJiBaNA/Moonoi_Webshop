// routes/payments.js - Payment Management Routes (แก้ไขการเข้าถึงฐานข้อมูล)
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;

const router = express.Router();

// Function to get database pool and other dependencies
let getDbPool, config, requireAuth, logActivity;

try {
    const serverModule = require('../server');
    getDbPool = serverModule.dbPool;
    config = serverModule.config;
    requireAuth = serverModule.requireAuth;
    logActivity = serverModule.logActivity;
} catch (error) {
    console.error('Failed to import server module:', error);
    getDbPool = () => null;
    config = {
        truewallet_api_key: 'fallback-key',
        slip_api_key: 'fallback-key'
    };
    requireAuth = (req, res, next) => next();
    logActivity = () => Promise.resolve();
}

// File upload configuration for slip images
const slipStorage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const uploadPath = 'uploads/slips';
        try {
            await fs.mkdir(uploadPath, { recursive: true });
            cb(null, uploadPath);
        } catch (error) {
            cb(error);
        }
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'slip-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const slipUpload = multer({
    storage: slipStorage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JPEG and PNG images are allowed.'));
        }
    }
});

// Helper function to call TrueWallet API
async function processTrueWalletPayment(giftLink) {
    try {
        const response = await axios.post('https://byshop.me/api/truewallet', {
            keyapi: config.truewallet_api_key,
            phone: process.env.TRUEWALLET_PHONE || '0123456789',
            gift_link: giftLink
        }, {
            timeout: 30000,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        return response.data;
    } catch (error) {
        console.error('TrueWallet API error:', error.response?.data || error.message);
        throw new Error('Failed to process TrueWallet payment');
    }
}

// Helper function to verify slip image
async function verifySlipImage(qrcodeText) {
    try {
        const response = await axios.post('https://byshop.me/api/check_slip', {
            keyapi: config.slip_api_key,
            qrcode_text: qrcodeText
        }, {
            timeout: 30000
        });

        return response.data;
    } catch (error) {
        console.error('Slip verification API error:', error.response?.data || error.message);
        throw new Error('Failed to verify slip');
    }
}

// Helper function to update user credits
async function updateUserCredits(userId, amount, transactionType, referenceType, referenceId, description, req) {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            throw new Error('Database not available');
        }

        // Get current balance
        const [userResult] = await dbPool.execute('SELECT credits FROM users WHERE id = ?', [userId]);
        if (userResult.length === 0) {
            throw new Error('User not found');
        }

        const currentBalance = parseFloat(userResult[0].credits);
        const newBalance = currentBalance + amount;

        // Update user credits
        await dbPool.execute('UPDATE users SET credits = ? WHERE id = ?', [newBalance, userId]);

        // Record transaction
        await dbPool.execute(`
            INSERT INTO credit_transactions 
            (user_id, transaction_type, amount, balance_before, balance_after, reference_type, reference_id, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [userId, transactionType, amount, currentBalance, newBalance, referenceType, referenceId, description]);

        // Log activity
        await logActivity(userId, 'credits_updated', 'transaction', null, {
            amount,
            transaction_type: transactionType,
            balance_before: currentBalance,
            balance_after: newBalance
        }, req);

        return newBalance;
    } catch (error) {
        console.error('Update credits error:', error);
        throw error;
    }
}

// GET /api/payments/methods - Get Available Payment Methods
router.get('/methods', async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const [methods] = await dbPool.execute(`
            SELECT id, method_name, method_type, instructions, min_amount, max_amount, fees
            FROM payment_methods
            WHERE is_active = 1
            ORDER BY sort_order ASC
        `);

        // Parse JSON fields
        const processedMethods = methods.map(method => ({
            ...method,
            fees: method.fees ? JSON.parse(method.fees) : {}
        }));

        res.json({
            success: true,
            data: processedMethods
        });

    } catch (error) {
        console.error('Get payment methods error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/payments/truewallet - Process TrueWallet Payment
router.post('/truewallet', requireAuth, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { gift_link } = req.body;
        const userId = req.user.id;

        if (!gift_link) {
            return res.status(400).json({ error: 'Gift link is required' });
        }

        // Validate gift link format
        const giftLinkRegex = /https:\/\/gift\.truemoney\.com\/campaign\/\?v=.+/;
        if (!giftLinkRegex.test(gift_link)) {
            return res.status(400).json({ error: 'Invalid TrueWallet gift link format' });
        }

        // Check for duplicate gift link usage
        const [existingPayment] = await dbPool.execute(`
            SELECT id FROM payment_requests 
            WHERE JSON_EXTRACT(payment_data, '$.gift_link') = ? 
            AND status IN ('completed', 'processing')
        `, [gift_link]);

        if (existingPayment.length > 0) {
            return res.status(400).json({ error: 'This gift link has already been used' });
        }

        // Create payment request
        const [paymentResult] = await dbPool.execute(`
            INSERT INTO payment_requests (user_id, amount, method_type, payment_data, status)
            VALUES (?, 0, 'truewallet', ?, 'processing')
        `, [userId, JSON.stringify({ gift_link })]);

        const paymentRequestId = paymentResult.insertId;

        try {
            // Process TrueWallet payment
            const trueWalletResponse = await processTrueWalletPayment(gift_link);

            if (trueWalletResponse.status === 'success') {
                const amount = parseFloat(trueWalletResponse.amount);

                // Update payment request
                await dbPool.execute(`
                    UPDATE payment_requests 
                    SET amount = ?, status = 'completed', completed_at = NOW(),
                        verification_data = ?
                    WHERE id = ?
                `, [amount, JSON.stringify(trueWalletResponse), paymentRequestId]);

                // Add credits to user
                const newBalance = await updateUserCredits(
                    userId,
                    amount,
                    'deposit',
                    'payment',
                    paymentRequestId,
                    `TrueWallet deposit: ${amount} THB`,
                    req
                );

                res.json({
                    success: true,
                    message: 'Payment processed successfully',
                    data: {
                        amount,
                        new_balance: newBalance,
                        transaction_id: paymentRequestId
                    }
                });

            } else {
                // Update payment request as failed
                await dbPool.execute(`
                    UPDATE payment_requests 
                    SET status = 'failed', verification_data = ?
                    WHERE id = ?
                `, [JSON.stringify(trueWalletResponse), paymentRequestId]);

                res.status(400).json({
                    error: trueWalletResponse.message || 'Payment failed',
                    details: trueWalletResponse
                });
            }

        } catch (apiError) {
            // Update payment request as failed
            await dbPool.execute(`
                UPDATE payment_requests 
                SET status = 'failed', notes = ?
                WHERE id = ?
            `, [apiError.message, paymentRequestId]);

            res.status(500).json({ error: 'Failed to process TrueWallet payment' });
        }

    } catch (error) {
        console.error('TrueWallet payment error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/payments/slip-upload - Upload and Verify Bank Transfer Slip
router.post('/slip-upload', requireAuth, slipUpload.single('slip_image'), async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { qrcode_text } = req.body;
        const userId = req.user.id;

        if (!req.file) {
            return res.status(400).json({ error: 'Slip image is required' });
        }

        if (!qrcode_text) {
            return res.status(400).json({ error: 'QR code text is required' });
        }

        const slipImagePath = req.file.filename;

        // Create payment request
        const [paymentResult] = await dbPool.execute(`
            INSERT INTO payment_requests (user_id, amount, method_type, payment_data, slip_image, status)
            VALUES (?, 0, 'bank_transfer', ?, ?, 'processing')
        `, [userId, JSON.stringify({ qrcode_text }), slipImagePath]);

        const paymentRequestId = paymentResult.insertId;

        try {
            // Verify slip with API
            const slipVerification = await verifySlipImage(qrcode_text);

            if (slipVerification.status === 1 && slipVerification.check_slip === 0) {
                const amount = parseFloat(slipVerification.amount);

                // Get bank account info for verification
                const [bankConfig] = await dbPool.execute(`
                    SELECT configuration FROM payment_methods 
                    WHERE method_type = 'bank_transfer' AND is_active = 1
                    LIMIT 1
                `);

                if (bankConfig.length === 0) {
                    throw new Error('Bank transfer configuration not found');
                }

                const config = JSON.parse(bankConfig[0].configuration);
                
                // Verify receiver account (basic check)
                const receiverAcc = slipVerification.receiver?.acc_no || '';
                const configAcc = config.account_number || '';
                
                // Check if last 4 digits match (for security)
                const accMatch = receiverAcc.slice(-4) === configAcc.slice(-4);

                if (!accMatch) {
                    await dbPool.execute(`
                        UPDATE payment_requests 
                        SET status = 'failed', notes = 'Account number mismatch'
                        WHERE id = ?
                    `, [paymentRequestId]);

                    return res.status(400).json({ 
                        error: 'Bank account verification failed. Please ensure you transferred to the correct account.' 
                    });
                }

                // Check slip time (not older than 24 hours)
                const slipTime = new Date(slipVerification.slip_time);
                const hoursDiff = (Date.now() - slipTime.getTime()) / (1000 * 60 * 60);

                if (hoursDiff > 24) {
                    await dbPool.execute(`
                        UPDATE payment_requests 
                        SET status = 'failed', notes = 'Slip is too old (>24 hours)'
                        WHERE id = ?
                    `, [paymentRequestId]);

                    return res.status(400).json({ 
                        error: 'Bank slip is too old. Please use a slip from the last 24 hours.' 
                    });
                }

                // Update payment request
                await dbPool.execute(`
                    UPDATE payment_requests 
                    SET amount = ?, status = 'completed', completed_at = NOW(),
                        verification_data = ?
                    WHERE id = ?
                `, [amount, JSON.stringify(slipVerification), paymentRequestId]);

                // Add credits to user
                const newBalance = await updateUserCredits(
                    userId,
                    amount,
                    'deposit',
                    'payment',
                    paymentRequestId,
                    `Bank transfer deposit: ${amount} THB`,
                    req
                );

                res.json({
                    success: true,
                    message: 'Bank transfer verified successfully',
                    data: {
                        amount,
                        new_balance: newBalance,
                        transaction_id: paymentRequestId
                    }
                });

            } else {
                let errorMessage = 'Slip verification failed';
                if (slipVerification.check_slip === 1) {
                    errorMessage = 'This slip has already been used';
                } else if (slipVerification.massage_th) {
                    errorMessage = slipVerification.massage_th;
                }

                await dbPool.execute(`
                    UPDATE payment_requests 
                    SET status = 'failed', verification_data = ?, notes = ?
                    WHERE id = ?
                `, [JSON.stringify(slipVerification), errorMessage, paymentRequestId]);

                res.status(400).json({
                    error: errorMessage,
                    details: slipVerification
                });
            }

        } catch (apiError) {
            await dbPool.execute(`
                UPDATE payment_requests 
                SET status = 'failed', notes = ?
                WHERE id = ?
            `, [apiError.message, paymentRequestId]);

            res.status(500).json({ error: 'Failed to verify bank slip' });
        }

    } catch (error) {
        console.error('Slip upload error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/payments/history - Get Payment History
router.get('/history', requireAuth, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { page = 1, limit = 10 } = req.query;
        const userId = req.user.id;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        // Get total count
        const [countResult] = await dbPool.execute(`
            SELECT COUNT(*) as total FROM payment_requests WHERE user_id = ?
        `, [userId]);
        const totalPayments = countResult[0].total;

        // Get payment history
        const [payments] = await dbPool.execute(`
            SELECT 
                id,
                amount,
                method_type,
                status,
                payment_data,
                slip_image,
                notes,
                created_at,
                completed_at
            FROM payment_requests
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        `, [userId, parseInt(limit), offset]);

        // Parse payment data
        const processedPayments = payments.map(payment => ({
            ...payment,
            payment_data: payment.payment_data ? JSON.parse(payment.payment_data) : null,
            slip_image: payment.slip_image ? `/uploads/slips/${payment.slip_image}` : null
        }));

        res.json({
            success: true,
            data: {
                payments: processedPayments,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: totalPayments,
                    totalPages: Math.ceil(totalPayments / parseInt(limit))
                }
            }
        });

    } catch (error) {
        console.error('Get payment history error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/payments/transactions - Get Credit Transactions
router.get('/transactions', requireAuth, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const { page = 1, limit = 10, type } = req.query;
        const userId = req.user.id;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        let whereCondition = 'WHERE user_id = ?';
        let queryParams = [userId];

        if (type) {
            whereCondition += ' AND transaction_type = ?';
            queryParams.push(type);
        }

        // Get total count
        const [countResult] = await dbPool.execute(`
            SELECT COUNT(*) as total FROM credit_transactions ${whereCondition}
        `, queryParams);
        const totalTransactions = countResult[0].total;

        // Get transactions
        const [transactions] = await dbPool.execute(`
            SELECT 
                id,
                transaction_type,
                amount,
                balance_before,
                balance_after,
                reference_type,
                reference_id,
                description,
                payment_method,
                created_at
            FROM credit_transactions
            ${whereCondition}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        `, [...queryParams, parseInt(limit), offset]);

        res.json({
            success: true,
            data: {
                transactions,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: totalTransactions,
                    totalPages: Math.ceil(totalTransactions / parseInt(limit))
                }
            }
        });

    } catch (error) {
        console.error('Get transactions error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/payments/balance - Get Current Balance
router.get('/balance', requireAuth, async (req, res) => {
    try {
        const dbPool = getDbPool();
        if (!dbPool) {
            return res.status(503).json({ 
                success: false, 
                error: 'Database not available' 
            });
        }

        const userId = req.user.id;

        const [userResult] = await dbPool.execute(`
            SELECT 
                credits,
                total_spent,
                loyalty_points,
                (SELECT COUNT(*) FROM credit_transactions WHERE user_id = ? AND transaction_type = 'deposit') as total_deposits,
                (SELECT COALESCE(SUM(amount), 0) FROM credit_transactions WHERE user_id = ? AND transaction_type = 'deposit') as total_deposited
        `, [userId, userId]);

        if (userResult.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const balance = userResult[0];

        res.json({
            success: true,
            data: balance
        });

    } catch (error) {
        console.error('Get balance error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;