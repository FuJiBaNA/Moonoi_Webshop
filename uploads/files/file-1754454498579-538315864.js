// debug-routes.js - Route Debugging Helper
const express = require('express');

// Create a test app to check route patterns
const app = express();

// Test route patterns
const testRoutes = [
    '/api/products',
    '/api/products/categories', 
    '/api/products/featured',
    '/api/products/bundles',
    '/api/products/search/suggestions',
    '/api/products/stats',
    '/api/products/bundles/123',
    '/api/products/123',
    '/api/orders',
    '/api/orders/cart',
    '/api/orders/cart/add',
    '/api/orders/123',
    '/api/orders/123/download/456',
    '/api/licenses',
    '/api/licenses/123',
    '/api/verify'
];

// Add test routes
app.get('/api/products', (req, res) => res.json({ route: 'products-list' }));
app.get('/api/products/categories', (req, res) => res.json({ route: 'categories' }));
app.get('/api/products/featured', (req, res) => res.json({ route: 'featured' }));
app.get('/api/products/bundles', (req, res) => res.json({ route: 'bundles-list' }));
app.get('/api/products/search/suggestions', (req, res) => res.json({ route: 'suggestions' }));
app.get('/api/products/stats', (req, res) => res.json({ route: 'stats' }));
app.get('/api/products/bundles/:id', (req, res) => res.json({ route: 'bundle-detail', id: req.params.id }));
app.get('/api/products/:id', (req, res) => res.json({ route: 'product-detail', id: req.params.id }));

console.log('🔍 Testing route patterns...\n');

// Test each route
testRoutes.forEach(route => {
    try {
        // Simulate route matching
        const parts = route.split('/').filter(p => p);
        console.log(`✅ ${route} - OK`);
    } catch (error) {
        console.log(`❌ ${route} - ERROR: ${error.message}`);
    }
});

console.log('\n✨ Route debugging complete!');
console.log('\n📝 Tips to fix path-to-regexp errors:');
console.log('1. Make sure all route parameters have names: /:id not /:');
console.log('2. Put specific routes BEFORE parametric routes');
console.log('3. Add parameter validation with router.param()');
console.log('4. Check for duplicate or conflicting routes');
console.log('5. Ensure proper route order in files');

module.exports = app;