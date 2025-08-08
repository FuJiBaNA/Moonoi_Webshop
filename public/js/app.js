// app.js - Main Frontend JavaScript

// Global variables
let currentUser = null;
let authToken = null;

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

// Initialize application
function initializeApp() {
    // Load auth token from localStorage
    authToken = localStorage.getItem('authToken');
    
    // Check authentication status
    checkAuth();
    
    // Initialize components
    initializeComponents();
    
    // Setup event listeners
    setupEventListeners();
}

// Check authentication status
async function checkAuth() {
    if (!authToken) {
        showGuestNavigation();
        return;
    }

    try {
        const response = await fetch('/api/auth/me', {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });

        if (response.ok) {
            const data = await response.json();
            currentUser = data.user;
            showUserNavigation();
            updateUserDisplay();
        } else {
            // Token is invalid, remove it
            localStorage.removeItem('authToken');
            authToken = null;
            showGuestNavigation();
        }
    } catch (error) {
        console.error('Auth check error:', error);
        showGuestNavigation();
    }
}

// Show guest navigation
function showGuestNavigation() {
    const guestNav = document.getElementById('guestNav');
    const userNav = document.getElementById('userNav');
    
    if (guestNav) guestNav.style.display = 'block';
    if (userNav) userNav.style.display = 'none';
}

// Show user navigation
function showUserNavigation() {
    const guestNav = document.getElementById('guestNav');
    const userNav = document.getElementById('userNav');
    
    if (guestNav) guestNav.style.display = 'none';
    if (userNav) userNav.style.display = 'block';
}

// Update user display
function updateUserDisplay() {
    if (!currentUser) return;
    
    const usernameDisplay = document.getElementById('usernameDisplay');
    if (usernameDisplay) {
        usernameDisplay.textContent = currentUser.username;
    }
    
    // Update credits display if exists
    const creditsDisplay = document.getElementById('creditsDisplay');
    if (creditsDisplay) {
        creditsDisplay.textContent = `฿${parseFloat(currentUser.credits).toFixed(2)}`;
    }
    
    // Show admin menu if user is admin
    if (['admin', 'superadmin'].includes(currentUser.role)) {
        const adminMenus = document.querySelectorAll('.admin-only');
        adminMenus.forEach(menu => menu.style.display = 'block');
    }
}

// Initialize components
function initializeComponents() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Load cart count
    updateCartCount();
}

// Setup event listeners
function setupEventListeners() {
    // Search functionality
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(handleSearch, 300));
    }

    // Theme toggle
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
    }
}

// Handle search
async function handleSearch(event) {
    const query = event.target.value.trim();
    if (query.length < 2) {
        hideSearchResults();
        return;
    }

    try {
        const response = await fetch(`/api/search?q=${encodeURIComponent(query)}&limit=10`);
        const data = await response.json();
        
        if (data.success) {
            displaySearchResults(data.data);
        }
    } catch (error) {
        console.error('Search error:', error);
    }
}

// Display search results
function displaySearchResults(results) {
    const searchResults = document.getElementById('searchResults');
    if (!searchResults) return;

    let html = '';

    // Products
    if (results.products && results.products.length > 0) {
        html += '<h6 class="dropdown-header">สินค้า</h6>';
        results.products.forEach(product => {
            html += `
                <a class="dropdown-item" href="/product/${product.id}">
                    <div class="d-flex align-items-center">
                        <img src="${product.image_url || '/images/default-product.jpg'}" 
                             alt="${product.name}" class="me-2" style="width: 32px; height: 32px; object-fit: cover; border-radius: 4px;">
                        <div>
                            <div class="fw-medium">${product.name}</div>
                            <small class="text-muted">฿${product.final_price}</small>
                        </div>
                    </div>
                </a>
            `;
        });
    }

    // Categories
    if (results.categories && results.categories.length > 0) {
        if (html) html += '<div class="dropdown-divider"></div>';
        html += '<h6 class="dropdown-header">หมวดหมู่</h6>';
        results.categories.forEach(category => {
            html += `
                <a class="dropdown-item" href="/products?category=${category.id}">
                    <i class="${category.icon || 'fas fa-cube'} me-2"></i>
                    ${category.name} (${category.product_count})
                </a>
            `;
        });
    }

    if (html) {
        searchResults.innerHTML = html;
        searchResults.style.display = 'block';
    } else {
        searchResults.innerHTML = '<div class="dropdown-item">ไม่พบผลลัพธ์</div>';
        searchResults.style.display = 'block';
    }
}

// Hide search results
function hideSearchResults() {
    const searchResults = document.getElementById('searchResults');
    if (searchResults) {
        searchResults.style.display = 'none';
    }
}

// Cart functions
async function addToCart(productId, bundleId = null, quantity = 1) {
    if (!authToken) {
        showAlert('กรุณาเข้าสู่ระบบก่อนเพิ่มสินค้าลงตะกร้า', 'warning');
        setTimeout(() => {
            window.location.href = '/login';
        }, 2000);
        return;
    }

    const payload = { quantity };
    if (productId) payload.product_id = productId;
    if (bundleId) payload.bundle_id = bundleId;

    try {
        const response = await fetch('/api/orders/cart/add', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (data.success) {
            showAlert('เพิ่มสินค้าลงตะกร้าแล้ว', 'success');
            updateCartCount(data.data.cart_item_count);
            
            // Show cart preview if available
            if (data.data.cart) {
                showCartPreview(data.data.cart);
            }
        } else {
            showAlert(data.error || 'ไม่สามารถเพิ่มสินค้าได้', 'danger');
        }
    } catch (error) {
        console.error('Add to cart error:', error);
        showAlert('เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง', 'danger');
    }
}

// Update cart count
async function updateCartCount(count = null) {
    const cartCountElement = document.getElementById('cartCount');
    if (!cartCountElement) return;

    if (count !== null) {
        cartCountElement.textContent = count;
        return;
    }

    if (!authToken) {
        cartCountElement.textContent = '0';
        return;
    }

    try {
        const response = await fetch('/api/orders/cart', {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });

        const data = await response.json();
        if (data.success) {
            cartCountElement.textContent = data.data.cart_item_count || '0';
        }
    } catch (error) {
        console.error('Cart count error:', error);
    }
}

// Show cart preview
function showCartPreview(cart) {
    const cartPreview = document.getElementById('cartPreview');
    if (!cartPreview) return;

    const total = cart.reduce((sum, item) => sum + item.total_price, 0);
    
    let html = '';
    cart.forEach(item => {
        html += `
            <div class="cart-preview-item d-flex justify-content-between align-items-center py-2">
                <div>
                    <div class="fw-medium">${item.name}</div>
                    <small class="text-muted">จำนวน: ${item.quantity}</small>
                </div>
                <div class="text-end">
                    <div class="fw-medium">฿${item.total_price}</div>
                </div>
            </div>
        `;
    });

    html += `
        <div class="cart-preview-footer mt-2 pt-2 border-top">
            <div class="d-flex justify-content-between align-items-center mb-2">
                <strong>รวมทั้งหมด:</strong>
                <strong class="text-primary">฿${total.toFixed(2)}</strong>
            </div>
            <a href="/cart" class="btn btn-primary btn-sm w-100">ไปที่ตะกร้าสินค้า</a>
        </div>
    `;

    cartPreview.innerHTML = html;
}

// Authentication functions
async function login(email, password) {
    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                login: email,
                password: password
            })
        });

        const data = await response.json();

        if (data.success) {
            authToken = data.token;
            currentUser = data.user;
            localStorage.setItem('authToken', authToken);
            
            showAlert('เข้าสู่ระบบสำเร็จ', 'success');
            
            // Redirect to dashboard or previous page
            const returnUrl = new URLSearchParams(window.location.search).get('returnUrl') || '/dashboard';
            setTimeout(() => {
                window.location.href = returnUrl;
            }, 1500);
        } else {
            showAlert(data.error || 'ไม่สามารถเข้าสู่ระบบได้', 'danger');
        }
    } catch (error) {
        console.error('Login error:', error);
        showAlert('เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง', 'danger');
    }
}

async function register(username, email, password, confirmPassword) {
    if (password !== confirmPassword) {
        showAlert('รหัสผ่านไม่ตรงกัน', 'danger');
        return;
    }

    try {
        const response = await fetch('/api/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username,
                email,
                password,
                confirmPassword
            })
        });

        const data = await response.json();

        if (data.success) {
            authToken = data.token;
            currentUser = data.user;
            localStorage.setItem('authToken', authToken);
            
            showAlert('สมัครสมาชิกสำเร็จ', 'success');
            
            setTimeout(() => {
                window.location.href = '/dashboard';
            }, 1500);
        } else {
            showAlert(data.error || 'ไม่สามารถสมัครสมาชิกได้', 'danger');
        }
    } catch (error) {
        console.error('Register error:', error);
        showAlert('เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง', 'danger');
    }
}

function logout() {
    localStorage.removeItem('authToken');
    authToken = null;
    currentUser = null;
    
    showAlert('ออกจากระบบแล้ว', 'info');
    
    setTimeout(() => {
        window.location.href = '/';
    }, 1500);
}

// Request trial access
async function requestTrial(productId) {
    if (!authToken) {
        showAlert('กรุณาเข้าสู่ระบบก่อนขอทดลองใช้', 'warning');
        return;
    }

    try {
        const response = await fetch(`/api/products/${productId}/trial`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });

        const data = await response.json();

        if (data.success) {
            showAlert('ได้รับสิทธิ์ทดลองใช้แล้ว', 'success');
            
            // Show trial token
            showTrialToken(data.data);
        } else {
            showAlert(data.error || 'ไม่สามารถขอทดลองใช้ได้', 'danger');
        }
    } catch (error) {
        console.error('Trial request error:', error);
        showAlert('เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง', 'danger');
    }
}

// Show trial token modal
function showTrialToken(trialData) {
    const modal = new bootstrap.Modal(document.getElementById('trialTokenModal') || createTrialTokenModal());
    
    document.getElementById('trialTokenCode').textContent = trialData.trial_token;
    document.getElementById('trialProductName').textContent = trialData.product_name;
    document.getElementById('trialDuration').textContent = `${trialData.duration_hours} ชั่วโมง`;
    document.getElementById('trialExpires').textContent = new Date(trialData.expires_at).toLocaleString('th-TH');
    
    modal.show();
}

// Create trial token modal if it doesn't exist
function createTrialTokenModal() {
    const modalHtml = `
        <div class="modal fade" id="trialTokenModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">🆓 ได้รับสิทธิ์ทดลองใช้</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="alert alert-success">
                            <h6>ยินดีด้วย! คุณได้รับสิทธิ์ทดลองใช้สำหรับ</h6>
                            <strong id="trialProductName"></strong>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Trial Token:</label>
                            <div class="input-group">
                                <input type="text" class="form-control" id="trialTokenCode" readonly>
                                <button class="btn btn-outline-primary" onclick="copyToClipboard('trialTokenCode')">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>
                        </div>
                        
                        <div class="row">
                            <div class="col-6">
                                <strong>ระยะเวลา:</strong><br>
                                <span id="trialDuration"></span>
                            </div>
                            <div class="col-6">
                                <strong>หมดอายุ:</strong><br>
                                <span id="trialExpires"></span>
                            </div>
                        </div>
                        
                        <div class="alert alert-info mt-3">
                            <small>
                                <i class="fas fa-info-circle me-1"></i>
                                กรุณาเก็บ Trial Token นี้ไว้ใช้ในการเข้าถึง Script ในเซิร์ฟเวอร์ของคุณ
                            </small>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">ปิด</button>
                        <a href="/dashboard" class="btn btn-primary">ไปที่แดชบอร์ด</a>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    return document.getElementById('trialTokenModal');
}

// Copy to clipboard
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    element.select();
    element.setSelectionRange(0, 99999);
    
    try {
        document.execCommand('copy');
        showAlert('คัดลอกแล้ว', 'success');
    } catch (err) {
        console.error('Copy failed:', err);
        showAlert('ไม่สามารถคัดลอกได้', 'danger');
    }
}

// Utility functions
function showAlert(message, type = 'info', duration = 5000) {
    // Remove existing alerts
    const existingAlerts = document.querySelectorAll('.alert-floating');
    existingAlerts.forEach(alert => alert.remove());

    const alertHtml = `
        <div class="alert alert-${type} alert-floating position-fixed" 
             style="top: 20px; right: 20px; z-index: 9999; min-width: 300px;">
            <i class="fas fa-${getAlertIcon(type)} me-2"></i>
            ${message}
            <button type="button" class="btn-close" onclick="this.parentElement.remove()"></button>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', alertHtml);
    
    // Auto remove after duration
    if (duration > 0) {
        setTimeout(() => {
            const alert = document.querySelector('.alert-floating');
            if (alert) alert.remove();
        }, duration);
    }
}

function getAlertIcon(type) {
    const icons = {
        success: 'check-circle',
        danger: 'exclamation-circle',
        warning: 'exclamation-triangle',
        info: 'info-circle'
    };
    return icons[type] || 'info-circle';
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function formatPrice(price) {
    return `฿${parseFloat(price).toLocaleString('th-TH', { minimumFractionDigits: 2 })}`;
}

function formatDate(dateString) {
    return new Date(dateString).toLocaleString('th-TH');
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Theme functions
function toggleTheme() {
    const body = document.body;
    const isDark = body.classList.contains('dark-theme');
    
    if (isDark) {
        body.classList.remove('dark-theme');
        localStorage.setItem('theme', 'light');
    } else {
        body.classList.add('dark-theme');
        localStorage.setItem('theme', 'dark');
    }
}

function loadTheme() {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
        document.body.classList.add('dark-theme');
    }
}

// Initialize theme on load
document.addEventListener('DOMContentLoaded', loadTheme);

// Form validation helpers
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function validatePassword(password) {
    return password.length >= 6;
}

function validateRequired(value) {
    return value && value.trim().length > 0;
}

// Loading states
function showLoading(element) {
    const originalHtml = element.innerHTML;
    element.dataset.originalHtml = originalHtml;
    element.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>กำลังโหลด...';
    element.disabled = true;
}

function hideLoading(element) {
    if (element.dataset.originalHtml) {
        element.innerHTML = element.dataset.originalHtml;
        delete element.dataset.originalHtml;
    }
    element.disabled = false;
}

// Image lazy loading
function setupLazyLoading() {
    const images = document.querySelectorAll('img[data-src]');
    
    const imageObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const img = entry.target;
                img.src = img.dataset.src;
                img.classList.remove('lazy');
                observer.unobserve(img);
            }
        });
    });

    images.forEach(img => imageObserver.observe(img));
}

// Function to handle the token from URL after Discord login
function handleAuthTokenFromUrl() {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    if (token) {
        localStorage.setItem('authToken', token);
        // Clean the URL
        window.history.replaceState({}, document.title, window.location.pathname);
        showAlert('เข้าสู่ระบบด้วย Discord สำเร็จ!', 'success');
        // Reload to apply the new auth state
        setTimeout(() => window.location.reload(), 1500);
    }
}
// Call this function when the app initializes
document.addEventListener('DOMContentLoaded', handleAuthTokenFromUrl);


// Load tab data
async function loadTabData(tabName) {
    switch (tabName) {
        case 'overview':
            // ... existing
            break;
        case 'orders':
            // ... existing
            break;
        case 'licenses': // NEW
            await loadLicensesData();
            break;
        case 'transactions':
            // ... existing
            break;
        case 'profile':
            // ... existing
            break;
    }
}

// NEW: Load and render user licenses
async function loadLicensesData() {
    const container = document.getElementById('licensesList');
    container.innerHTML = `<div class="text-center py-5"><div class="spinner-border"></div></div>`;
    try {
        const response = await fetch('/api/licenses', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('authToken')}` }
        });
        const data = await response.json();
        if (!data.success || data.data.length === 0) {
            container.innerHTML = '<div class="text-center text-muted py-5">คุณยังไม่มี License</div>';
            return;
        }

        container.innerHTML = `
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>สินค้า</th>
                            <th>License Key</th>
                            <th>IP Address</th>
                            <th>สถานะ</th>
                            <th>จัดการ</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.data.map(license => `
                            <tr>
                                <td><strong>${license.product_name}</strong></td>
                                <td><code class="user-select-all">${license.license_key}</code></td>
                                <td>${license.ip_address ? `<code>${license.ip_address}</code>` : '<span class="text-muted">ยังไม่ได้ผูก IP</span>'}</td>
                                <td><span class="badge bg-${license.is_active ? 'success' : 'danger'}">${license.is_active ? 'Active' : 'Inactive'}</span></td>
                                <td>
                                    <button class="btn btn-sm btn-outline-primary" onclick="showChangeIpModal(${license.id}, '${license.ip_address || ''}')">
                                        <i class="fas fa-sync-alt me-1"></i> เปลี่ยน IP
                                    </button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    } catch (error) {
        container.innerHTML = '<div class="alert alert-danger">ไม่สามารถโหลดข้อมูล License ได้</div>';
        console.error('Load licenses error:', error);
    }
}

// NEW: Handle secure file download
function handleDownload(itemId, productName) {
    showAlert('กำลังเตรียมไฟล์ดาวน์โหลด...', 'info');
    const url = `/api/orders/download/${itemId}`;
    
    // Create a temporary anchor to trigger the download
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.setAttribute('download', productName || 'download'); // Set a default filename
    
    // Add the Authorization header via a different mechanism if needed,
    // for direct downloads, this is tricky. A common pattern is to generate a temporary,
    // single-use token and pass it as a query param. For simplicity, we'll assume
    // the cookie-based session from passportJS will handle auth for this GET request.
    // If using only JWT in headers, this approach needs a backend change.
    
    // For now, we will use a workaround of opening the URL which will rely on the session cookie
    window.open(url, '_blank');
}


// NEW: Show change IP modal
function showChangeIpModal(licenseId, currentIp) {
    document.getElementById('changeIpForm').reset();
    document.getElementById('changeIpLicenseId').value = licenseId;
    document.getElementById('currentIpAddress').value = currentIp || 'N/A';
    const modal = new bootstrap.Modal(document.getElementById('changeIpModal'));
    modal.show();
}

// NEW: Submit change IP request
async function submitChangeIp() {
    const btn = document.getElementById('submitChangeIpBtn');
    showLoading(btn);

    const licenseId = document.getElementById('changeIpLicenseId').value;
    const newIp = document.getElementById('newIpAddress').value;
    const reason = document.getElementById('changeIpReason').value;

    try {
        const response = await fetch(`/api/licenses/${licenseId}/change-ip`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('authToken')}`
            },
            body: JSON.stringify({ new_ip: newIp, reason: reason })
        });

        const data = await response.json();
        if (data.success) {
            showAlert('ส่งคำขอเปลี่ยน IP สำเร็จ!', 'success');
            bootstrap.Modal.getInstance(document.getElementById('changeIpModal')).hide();
            loadLicensesData(); // Refresh the license list
        } else {
            showAlert(data.error || 'เกิดข้อผิดพลาด', 'danger');
        }
    } catch (error) {
        showAlert('เกิดข้อผิดพลาดในการเชื่อมต่อ', 'danger');
    } finally {
        hideLoading(btn);
    }
}


// Initialize lazy loading after DOM is ready
document.addEventListener('DOMContentLoaded', setupLazyLoading);

// Export functions for global use
window.addToCart = addToCart;
window.requestTrial = requestTrial;
window.copyToClipboard = copyToClipboard;
window.showAlert = showAlert;
window.login = login;
window.register = register;
window.logout = logout;
window.formatPrice = formatPrice;
window.formatDate = formatDate;
window.formatFileSize = formatFileSize;

/** Announcements Banner **/
async function fetchAnnouncements() {
  try {
    const res = await fetch('/api/announcements');
    if (!res.ok) return [];
    const data = await res.json();
    return data.announcements || data.data || [];
  } catch(e) { return []; }
}
function renderAnnouncements(list) {
  if (!Array.isArray(list) || list.length === 0) return;
  const container = document.createElement('div');
  container.id = 'announcementsBanner';
  container.className = 'container my-2';
  list.slice(0,3).forEach(a => {
    const div = document.createElement('div');
    const typeMap = { info:'primary', warning:'warning', success:'success', danger:'danger' };
    const cls = typeMap[a.announcement_type] || 'primary';
    div.className = 'alert alert-' + cls + ' d-flex align-items-center';
    div.innerHTML = `<i class="fa fa-bullhorn me-2"></i><strong>${a.title || ''}</strong> &nbsp; ${a.content || ''}`;
    container.appendChild(div);
  });
  const anchor = document.querySelector('main') || document.body;
  anchor.prepend(container);
}
document.addEventListener('DOMContentLoaded', async () => {
  const anns = await fetchAnnouncements();
  renderAnnouncements(anns);
});
