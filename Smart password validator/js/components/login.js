/**
 * AUTHGUARD - Advanced Data Structures (ADS)
 * Login & Registration Simulator Component
 * 
 * Features:
 * - Tabbed interface for Sign In and Account Registration
 * - Salt + SHA-256 verification
 * - Dynamic failed attempt counter (X / 5) with warning indicators
 * - 60-second lockout cooldown countdown timer
 * - Quick-fill demo account buttons
 * - Active authenticated user session banner with simulated 2FA
 */

class LoginComponent {
    constructor() {
        this.currentTab = 'login'; // 'login' or 'register'
        this.lockoutInterval = null;

        this.initElements();
        this.initEventListeners();
        this.updateSessionBanner();
    }

    initElements() {
        // Tab buttons
        this.tabLoginBtn = document.getElementById('auth-tab-login');
        this.tabRegisterBtn = document.getElementById('auth-tab-register');
        this.panelLogin = document.getElementById('auth-panel-login');
        this.panelRegister = document.getElementById('auth-panel-register');

        // Login inputs
        this.loginUsernameInput = document.getElementById('login-username');
        this.loginPasswordInput = document.getElementById('login-password');
        this.loginToggleEye = document.getElementById('login-toggle-eye');
        this.loginSubmitBtn = document.getElementById('login-submit-btn');
        this.loginAlertBox = document.getElementById('login-alert-box');
        this.loginAttemptsBadge = document.getElementById('login-attempts-badge');

        // Registration inputs
        this.regUsernameInput = document.getElementById('reg-username');
        this.regPasswordInput = document.getElementById('reg-password');
        this.regConfirmPasswordInput = document.getElementById('reg-confirm-password');
        this.regToggleEye1 = document.getElementById('reg-toggle-eye-1');
        this.regToggleEye2 = document.getElementById('reg-toggle-eye-2');
        this.regSubmitBtn = document.getElementById('reg-submit-btn');
        this.regAlertBox = document.getElementById('reg-alert-box');
        this.regStrengthBar = document.getElementById('reg-strength-bar');
        this.regStrengthText = document.getElementById('reg-strength-text');

        // Session Card
        this.sessionContainer = document.getElementById('auth-session-container');
        this.sessionUser = document.getElementById('session-username');
        this.sessionToken = document.getElementById('session-token');
        this.sessionHash = document.getElementById('session-hash');
        this.sessionSalt = document.getElementById('session-salt');
        this.sessionTier = document.getElementById('session-tier');
        this.sessionLogoutBtn = document.getElementById('session-logout-btn');

        // 2FA Simulator inside session
        this.btnGenerateOtp = document.getElementById('session-btn-otp');
        this.otpDisplay = document.getElementById('session-otp-display');
    }

    initEventListeners() {
        // Tab switching
        if (this.tabLoginBtn && this.tabRegisterBtn) {
            this.tabLoginBtn.addEventListener('click', () => this.switchTab('login'));
            this.tabRegisterBtn.addEventListener('click', () => this.switchTab('register'));
        }

        // Show/Hide password toggles
        if (this.loginToggleEye) {
            this.loginToggleEye.addEventListener('click', () => {
                const isPassword = this.loginPasswordInput.type === 'password';
                this.loginPasswordInput.type = isPassword ? 'text' : 'password';
                this.loginToggleEye.innerHTML = isPassword ? '<i class="fa-solid fa-eye-slash"></i>' : '<i class="fa-solid fa-eye"></i>';
            });
        }

        if (this.regToggleEye1) {
            this.regToggleEye1.addEventListener('click', () => {
                const isPassword = this.regPasswordInput.type === 'password';
                this.regPasswordInput.type = isPassword ? 'text' : 'password';
                this.regToggleEye1.innerHTML = isPassword ? '<i class="fa-solid fa-eye-slash"></i>' : '<i class="fa-solid fa-eye"></i>';
            });
        }

        if (this.regToggleEye2) {
            this.regToggleEye2.addEventListener('click', () => {
                const isPassword = this.regConfirmPasswordInput.type === 'password';
                this.regConfirmPasswordInput.type = isPassword ? 'text' : 'password';
                this.regToggleEye2.innerHTML = isPassword ? '<i class="fa-solid fa-eye-slash"></i>' : '<i class="fa-solid fa-eye"></i>';
            });
        }

        // Real-time register password strength
        if (this.regPasswordInput) {
            this.regPasswordInput.addEventListener('input', () => {
                const val = this.regPasswordInput.value;
                if (!val) {
                    if (this.regStrengthBar) this.regStrengthBar.style.width = '0%';
                    if (this.regStrengthText) this.regStrengthText.textContent = '';
                    return;
                }
                const entropy = CryptoUtils.calculateEntropy(val);
                if (this.regStrengthBar) {
                    const widthMap = { 'Very Weak': 20, 'Weak': 40, 'Medium': 65, 'Strong': 85, 'Very Strong': 100 };
                    this.regStrengthBar.style.width = `${widthMap[entropy.tier] || 20}%`;
                    this.regStrengthBar.style.backgroundColor = entropy.color;
                }
                if (this.regStrengthText) {
                    this.regStrengthText.textContent = `${entropy.tier} (${entropy.entropy} bits)`;
                    this.regStrengthText.style.color = entropy.color;
                }
            });
        }

        // Login submit
        if (this.loginSubmitBtn) {
            this.loginSubmitBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.handleLogin();
            });
        }

        // Quick login demo chips
        document.querySelectorAll('.btn-quick-cred').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const user = btn.getAttribute('data-user');
                const pass = btn.getAttribute('data-pass');
                if (this.loginUsernameInput) this.loginUsernameInput.value = user;
                if (this.loginPasswordInput) this.loginPasswordInput.value = pass;
                this.switchTab('login');
                this.checkUserLockStatus(user);
                window.app.showToast(`Populated credentials for "${user}"`, 'info');
            });
        });

        // Register submit
        if (this.regSubmitBtn) {
            this.regSubmitBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.handleRegister();
            });
        }

        // Logout
        if (this.sessionLogoutBtn) {
            this.sessionLogoutBtn.addEventListener('click', () => {
                window.authService.logout();
                this.updateSessionBanner();
                window.app.showToast('You have been safely signed out.', 'info');
                if (window.dashboardComponent) window.dashboardComponent.refresh();
            });
        }

        // 2FA TOTP Generator button
        if (this.btnGenerateOtp) {
            this.btnGenerateOtp.addEventListener('click', () => {
                // Generate 6-digit TOTP
                const otp = Math.floor(100000 + Math.random() * 900000);
                if (this.otpDisplay) {
                    this.otpDisplay.textContent = otp;
                    this.otpDisplay.classList.add('pulse-glow');
                    setTimeout(() => this.otpDisplay.classList.remove('pulse-glow'), 600);
                }
                window.app.showToast('Simulated TOTP 2FA code generated!', 'success');
            });
        }
    }

    switchTab(tab) {
        this.currentTab = tab;
        if (tab === 'login') {
            this.tabLoginBtn.classList.add('active');
            this.tabRegisterBtn.classList.remove('active');
            this.panelLogin.classList.remove('hidden');
            this.panelRegister.classList.add('hidden');
        } else {
            this.tabRegisterBtn.classList.add('active');
            this.tabLoginBtn.classList.remove('active');
            this.panelRegister.classList.remove('hidden');
            this.panelLogin.classList.add('hidden');
        }
    }

    async handleLogin() {
        const username = this.loginUsernameInput.value.trim();
        const password = this.loginPasswordInput.value;

        if (!username || !password) {
            this.showLoginAlert('Please enter both username and password.', 'error');
            return;
        }

        // Visual computation state
        this.loginSubmitBtn.disabled = true;
        this.loginSubmitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Salting & Hashing SHA-256...';

        // Brief delay for pedagogical effect (showing the crypto process)
        await new Promise(r => setTimeout(r, 400));

        const result = await window.authService.login(username, password);

        this.loginSubmitBtn.disabled = false;
        this.loginSubmitBtn.innerHTML = '<i class="fa-solid fa-arrow-right-to-bracket"></i> Secure Sign In';

        if (result.success) {
            this.showLoginAlert(result.message, 'success');
            this.updateSessionBanner();
            window.app.showToast(`Authenticated as ${username}!`, 'success');
            if (this.loginPasswordInput) this.loginPasswordInput.value = '';
        } else {
            if (result.isLocked) {
                this.showLoginAlert(result.message, 'danger');
                this.startLockoutCountdown(result.remainingSeconds || 60);
            } else {
                this.showLoginAlert(result.message, 'error');
            }
        }

        this.checkUserLockStatus(username);
        if (window.dashboardComponent) window.dashboardComponent.refresh();
    }

    async handleRegister() {
        const username = this.regUsernameInput.value.trim();
        const password = this.regPasswordInput.value;
        const confirmPassword = this.regConfirmPasswordInput.value;

        this.regSubmitBtn.disabled = true;
        this.regSubmitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Hashing & Storing...';

        await new Promise(r => setTimeout(r, 350));

        const result = await window.authService.register(username, password, confirmPassword);

        this.regSubmitBtn.disabled = false;
        this.regSubmitBtn.innerHTML = '<i class="fa-solid fa-user-plus"></i> Create Account';

        if (result.success) {
            this.showRegisterAlert(result.message, 'success');
            window.app.showToast('Account registered successfully! You can now log in.', 'success');
            this.regUsernameInput.value = '';
            this.regPasswordInput.value = '';
            this.regConfirmPasswordInput.value = '';
            if (this.regStrengthBar) this.regStrengthBar.style.width = '0%';
            if (this.regStrengthText) this.regStrengthText.textContent = '';
            
            // Auto switch to login tab after 1.5s
            setTimeout(() => {
                this.switchTab('login');
                if (this.loginUsernameInput) this.loginUsernameInput.value = username;
            }, 1200);
        } else {
            this.showRegisterAlert(result.message, 'error');
        }

        if (window.dashboardComponent) window.dashboardComponent.refresh();
    }

    checkUserLockStatus(username) {
        if (!username) return;
        const users = window.authService.getUsers();
        const user = users[username.toLowerCase()];

        if (user && this.loginAttemptsBadge) {
            const attempts = user.failedAttempts || 0;
            if (user.isLocked) {
                this.loginAttemptsBadge.innerHTML = `<span class="text-rose-400 font-bold"><i class="fa-solid fa-lock"></i> ACCOUNT LOCKED (5/5)</span>`;
            } else if (attempts > 0) {
                this.loginAttemptsBadge.innerHTML = `<span class="text-amber-400 font-medium"><i class="fa-solid fa-triangle-exclamation"></i> Attempts: ${attempts}/5</span>`;
            } else {
                this.loginAttemptsBadge.innerHTML = `<span class="text-emerald-400 font-medium"><i class="fa-solid fa-shield-check"></i> Attempts: 0/5 (Clear)</span>`;
            }
        }
    }

    startLockoutCountdown(seconds) {
        if (this.lockoutInterval) clearInterval(this.lockoutInterval);
        let rem = seconds;

        this.lockoutInterval = setInterval(() => {
            rem--;
            if (rem <= 0) {
                clearInterval(this.lockoutInterval);
                this.showLoginAlert('Lockout expired! You may attempt to sign in again.', 'info');
                this.checkUserLockStatus(this.loginUsernameInput.value);
            } else {
                this.showLoginAlert(`ACCOUNT LOCKED! Security cooldown in progress: ${rem}s remaining.`, 'danger');
            }
        }, 1000);
    }

    showLoginAlert(message, type) {
        if (!this.loginAlertBox) return;
        this.loginAlertBox.className = `alert-box alert-${type}`;
        this.loginAlertBox.innerHTML = `
            <i class="fa-solid ${type === 'success' ? 'fa-circle-check' : (type === 'danger' ? 'fa-shield-halved' : 'fa-circle-exclamation')}"></i>
            <span>${message}</span>
        `;
        this.loginAlertBox.classList.remove('hidden');
    }

    showRegisterAlert(message, type) {
        if (!this.regAlertBox) return;
        this.regAlertBox.className = `alert-box alert-${type}`;
        this.regAlertBox.innerHTML = `
            <i class="fa-solid ${type === 'success' ? 'fa-circle-check' : 'fa-circle-exclamation'}"></i>
            <span>${message}</span>
        `;
        this.regAlertBox.classList.remove('hidden');
    }

    updateSessionBanner() {
        const session = window.authService.getCurrentSession();
        if (session && this.sessionContainer) {
            this.sessionContainer.classList.remove('hidden');
            if (this.sessionUser) this.sessionUser.textContent = session.username;
            if (this.sessionToken) this.sessionToken.textContent = session.token;
            if (this.sessionHash) this.sessionHash.textContent = session.hashSnippet;
            if (this.sessionSalt) this.sessionSalt.textContent = session.saltSnippet + '...';
            if (this.sessionTier) this.sessionTier.textContent = `${session.tier} (${session.entropy} bits)`;
        } else if (this.sessionContainer) {
            this.sessionContainer.classList.add('hidden');
        }
    }
}

// Global exposure
if (typeof window !== 'undefined') {
    window.LoginComponent = LoginComponent;
}
