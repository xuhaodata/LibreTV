// 兼容 Netlify 的密码保护功能

/**
 * 获取密码哈希 - 支持多种环境变量来源
 */
function getPasswordHash() {
    // 方法1: 从 window.__ENV__ 获取 (Vercel/Docker)
    if (window.__ENV__ && window.__ENV__.PASSWORD) {
        console.log('从 window.__ENV__ 获取密码');
        return window.__ENV__.PASSWORD;
    }
    
    // 方法2: 从全局变量获取 (Netlify 注入)
    if (window.NETLIFY_PASSWORD) {
        console.log('从 window.NETLIFY_PASSWORD 获取密码');
        return window.NETLIFY_PASSWORD;
    }
    
    // 方法3: 从 meta 标签获取 (手动注入)
    const metaTag = document.querySelector('meta[name="site-password"]');
    if (metaTag) {
        console.log('从 meta 标签获取密码');
        return metaTag.getAttribute('content');
    }
    
    // 方法4: 从 data 属性获取
    const bodyPassword = document.body.getAttribute('data-password');
    if (bodyPassword) {
        console.log('从 body data-password 获取密码');
        return bodyPassword;
    }
    
    // 方法5: 尝试从构建时注入的脚本获取
    if (window.BUILD_TIME_PASSWORD) {
        console.log('从构建时注入获取密码');
        return window.BUILD_TIME_PASSWORD;
    }
    
    console.log('未找到密码配置');
    return null;
}

/**
 * 检查是否设置了密码保护
 */
function isPasswordProtected() {
    const pwd = getPasswordHash();
    const isProtected = typeof pwd === 'string' && pwd.length === 64 && !/^0+$/.test(pwd);
    console.log('密码保护状态:', isProtected, '密码长度:', pwd ? pwd.length : 0);
    return isProtected;
}

/**
 * 检查用户是否已通过密码验证
 */
function isPasswordVerified() {
    try {
        // 如果没有设置密码保护，则视为已验证
        if (!isPasswordProtected()) {
            return true;
        }

        const verificationData = JSON.parse(localStorage.getItem(PASSWORD_CONFIG.localStorageKey) || '{}');
        const { verified, timestamp, passwordHash } = verificationData;
        
        // 获取当前环境中的密码哈希
        const currentHash = getPasswordHash();
        
        // 验证是否已验证、未过期，且密码哈希未更改
        if (verified && timestamp && passwordHash === currentHash) {
            const now = Date.now();
            const expiry = timestamp + PASSWORD_CONFIG.verificationTTL;
            return now < expiry;
        }
        
        return false;
    } catch (error) {
        console.error('验证密码状态时出错:', error);
        return false;
    }
}

// 在页面加载时尝试从多个来源获取密码
document.addEventListener('DOMContentLoaded', function() {
    // 尝试从 Netlify 构建时注入的环境变量获取密码
    // 这需要在构建脚本中设置
    
    // 检查是否有通过 URL 参数传递的密码（仅用于调试）
    const urlParams = new URLSearchParams(window.location.search);
    const debugPassword = urlParams.get('debug_password');
    if (debugPassword && debugPassword.length === 64) {
        window.NETLIFY_PASSWORD = debugPassword;
        console.log('使用调试密码');
    }
    
    // 调试信息
    console.log('=== 密码保护调试信息 ===');
    console.log('window.__ENV__:', window.__ENV__);
    console.log('window.NETLIFY_PASSWORD:', window.NETLIFY_PASSWORD);
    console.log('当前获取的密码哈希:', getPasswordHash());
    console.log('是否启用密码保护:', isPasswordProtected());
    console.log('是否已验证:', isPasswordVerified());
    console.log('========================');
});

window.isPasswordProtected = isPasswordProtected;
window.isPasswordVerified = isPasswordVerified;

/**
 * 验证用户输入的密码是否正确（异步，使用SHA-256哈希）
 */
async function verifyPassword(password) {
    const correctHash = getPasswordHash();
    if (!correctHash) return false;
    
    const inputHash = await sha256(password);
    const isValid = inputHash === correctHash;
    
    if (isValid) {
        const verificationData = {
            verified: true,
            timestamp: Date.now(),
            passwordHash: correctHash // 保存当前密码的哈希值
        };
        localStorage.setItem(PASSWORD_CONFIG.localStorageKey, JSON.stringify(verificationData));
    }
    return isValid;
}

// SHA-256实现，可用Web Crypto API
async function sha256(message) {
    if (window.crypto && crypto.subtle && crypto.subtle.digest) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    // HTTP 下调用原始 js‑sha256
    if (typeof window._jsSha256 === 'function') {
        return window._jsSha256(message);
    }
    throw new Error('No SHA-256 implementation available.');
}

/**
 * 显示密码验证弹窗
 */
function showPasswordModal() {
    const passwordModal = document.getElementById('passwordModal');
    if (passwordModal) {
        // 防止出现豆瓣区域滚动条
        const doubanArea = document.getElementById('doubanArea');
        if (doubanArea) {
            doubanArea.classList.add('hidden');
        }

        passwordModal.style.display = 'flex';
        
        // 确保输入框获取焦点
        setTimeout(() => {
            const passwordInput = document.getElementById('passwordInput');
            if (passwordInput) {
                passwordInput.focus();
            }
        }, 100);
    }
}

/**
 * 隐藏密码验证弹窗
 */
function hidePasswordModal() {
    const passwordModal = document.getElementById('passwordModal');
    if (passwordModal) {
        passwordModal.style.display = 'none';

        // 如果启用豆瓣区域则显示豆瓣区域
        if (localStorage.getItem('doubanEnabled') === 'true') {
            const doubanArea = document.getElementById('doubanArea');
            if (doubanArea) {
                doubanArea.classList.remove('hidden');
                if (typeof initDouban === 'function') {
                    initDouban();
                }
            }
        }
    }
}

/**
 * 显示密码错误信息
 */
function showPasswordError() {
    const errorElement = document.getElementById('passwordError');
    if (errorElement) {
        errorElement.classList.remove('hidden');
    }
}

/**
 * 隐藏密码错误信息
 */
function hidePasswordError() {
    const errorElement = document.getElementById('passwordError');
    if (errorElement) {
        errorElement.classList.add('hidden');
    }
}

/**
 * 处理密码提交事件（异步）
 */
async function handlePasswordSubmit() {
    const passwordInput = document.getElementById('passwordInput');
    const password = passwordInput ? passwordInput.value.trim() : '';
    if (await verifyPassword(password)) {
        hidePasswordError();
        hidePasswordModal();

        // 触发密码验证成功事件
        document.dispatchEvent(new CustomEvent('passwordVerified'));
    } else {
        showPasswordError();
        if (passwordInput) {
            passwordInput.value = '';
            passwordInput.focus();
        }
    }
}

/**
 * 初始化密码验证系统（需适配异步事件）
 */
function initPasswordProtection() {
    console.log('初始化密码保护系统');
    
    if (!isPasswordProtected()) {
        console.log('未启用密码保护');
        return; // 如果未设置密码保护，则不进行任何操作
    }
    
    console.log('密码保护已启用');
    
    // 如果未验证密码，则显示密码验证弹窗
    if (!isPasswordVerified()) {
        console.log('显示密码验证弹窗');
        showPasswordModal();
        
        // 设置密码提交按钮事件监听
        const submitButton = document.getElementById('passwordSubmitBtn');
        if (submitButton) {
            submitButton.addEventListener('click', handlePasswordSubmit);
        }
        
        // 设置密码输入框回车键监听
        const passwordInput = document.getElementById('passwordInput');
        if (passwordInput) {
            passwordInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    handlePasswordSubmit();
                }
            });
        }
    } else {
        console.log('密码已验证');
    }
}

// 在页面加载完成后初始化密码保护
document.addEventListener('DOMContentLoaded', initPasswordProtection);
