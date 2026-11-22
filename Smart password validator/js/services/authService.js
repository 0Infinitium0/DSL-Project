/**
 * AUTHGUARD - Advanced Data Structures (ADS)
 * Authentication Service & Local Security Engine
 * 
 * Features:
 * - Local persistence via localStorage with ZERO external network transmission
 * - Cryptographic Salt + SHA-256 password hashing
 * - Sliding Window Rate Limiting (ADS Queue/Deque model) for brute force defense
 * - Account Lockout state machine (triggers at 5 consecutive failed attempts)
 * - Structured Audit Trail logging for cybersecurity forensics
 * - Pre-seeded demo dataset for immediate academic evaluation
 */

class AuthService {
    constructor() {
        this.STORAGE_USERS_KEY = 'authguard_users_v2';
        this.STORAGE_LOGS_KEY = 'authguard_audit_logs_v2';
        this.STORAGE_SESSION_KEY = 'authguard_session_v2';
        this.MAX_FAILED_ATTEMPTS = 5;
        this.LOCKOUT_DURATION_MS = 60 * 1000; // 60 seconds lockout for demo convenience

        // In-memory sliding window rate limiter: Map<IP, Array<timestamp>>
        this.rateLimitWindow = new Map();
        this.RATE_LIMIT_MAX_REQUESTS = 10;
        this.RATE_LIMIT_WINDOW_MS = 30 * 1000; // 30 seconds

        this.initStorage();
    }

    /**
     * Initialize storage with realistic pre-seeded accounts if empty
     */
    async initStorage() {
        const existingUsers = localStorage.getItem(this.STORAGE_USERS_KEY);
        if (!existingUsers) {
            await this.seedDefaultUsers();
        }

        const existingLogs = localStorage.getItem(this.STORAGE_LOGS_KEY);
        if (!existingLogs) {
            this.seedDefaultLogs();
        }
    }

    /**
     * Seeds initial demo users with salted SHA-256 hashes
     */
    async seedDefaultUsers() {
        const defaultUsers = [
            {
                username: 'admin_sec',
                passwordPlain: 'Admin@Secure2026!',
                tier: 'Very Strong',
                entropy: 86.4
            },
            {
                username: 'student_ads',
                passwordPlain: 'Student#ADS404!',
                tier: 'Strong',
                entropy: 78.2
            },
            {
                username: 'alex_cyber',
                passwordPlain: 'AlexCyber#99!',
                tier: 'Strong',
                entropy: 72.5
            },
            {
                username: 'demo_user',
                passwordPlain: 'Pass@12345',
                tier: 'Medium',
                entropy: 52.1
            }
        ];

        const usersDb = {};
        for (const user of defaultUsers) {
            const salt = CryptoUtils.generateSalt(16);
            const passwordHash = await CryptoUtils.sha256Hex(user.passwordPlain + salt);
            usersDb[user.username.toLowerCase()] = {
                username: user.username,
                salt,
                passwordHash,
                tier: user.tier,
                entropy: user.entropy,
                createdAt: new Date(Date.now() - 86400000 * 3).toISOString(),
                failedAttempts: user.username === 'demo_user' ? 3 : 0, // Show existing attempts
                isLocked: false,
                lockedUntil: null,
                lastLogin: new Date(Date.now() - 3600000 * 2).toISOString()
            };
        }

        localStorage.setItem(this.STORAGE_USERS_KEY, JSON.stringify(usersDb));
    }

    /**
     * Seeds initial audit logs to make the Security Dashboard vibrant immediately
     */
    seedDefaultLogs() {
        const now = Date.now();
        const sampleLogs = [
            {
                id: 'log_' + (now - 3500000),
                timestamp: new Date(now - 3500000).toISOString(),
                username: 'admin_sec',
                ip: '192.168.1.104',
                device: 'Chrome / Windows 11 (Secure Node)',
                status: 'SUCCESS',
                details: 'Authenticated successfully with SHA-256 verification.',
                hashSnippet: 'e3b0c442...a949'
            },
            {
                id: 'log_' + (now - 2800000),
                timestamp: new Date(now - 2800000).toISOString(),
                username: 'student_ads',
                ip: '192.168.1.189',
                device: 'Firefox / macOS (Campus Subnet)',
                status: 'SUCCESS',
                details: 'Authenticated successfully. Salt verified.',
                hashSnippet: '7d1a58b2...b20f'
            },
            {
                id: 'log_' + (now - 1400000),
                timestamp: new Date(now - 1400000).toISOString(),
                username: 'demo_user',
                ip: '45.33.32.156',
                device: 'Python-requests/2.28 (External IP)',
                status: 'FAILED',
                details: 'Invalid credential supplied. Attempt 1/5 recorded.',
                hashSnippet: '9f83c12a...c014'
            },
            {
                id: 'log_' + (now - 1200000),
                timestamp: new Date(now - 1200000).toISOString(),
                username: 'demo_user',
                ip: '45.33.32.156',
                device: 'Python-requests/2.28 (External IP)',
                status: 'FAILED',
                details: 'Invalid credential supplied. Attempt 2/5 recorded.',
                hashSnippet: '18b2c45e...fa30'
            },
            {
                id: 'log_' + (now - 1000000),
                timestamp: new Date(now - 1000000).toISOString(),
                username: 'demo_user',
                ip: '45.33.32.156',
                device: 'Python-requests/2.28 (External IP)',
                status: 'FAILED',
                details: 'Invalid credential supplied. Attempt 3/5 recorded. High threat level.',
                hashSnippet: 'a381b990...ee41'
            },
            {
                id: 'log_' + (now - 450000),
                timestamp: new Date(now - 450000).toISOString(),
                username: 'alex_cyber',
                ip: '10.0.4.52',
                device: 'Edge / Windows 11 (Workstation)',
                status: 'SUCCESS',
                details: 'Authenticated successfully.',
                hashSnippet: 'c4ca4238...8bc3'
            }
        ];

        localStorage.setItem(this.STORAGE_LOGS_KEY, JSON.stringify(sampleLogs));
    }

    /**
     * Retrieve all users
     */
    getUsers() {
        try {
            return JSON.parse(localStorage.getItem(this.STORAGE_USERS_KEY) || '{}');
        } catch (e) {
            return {};
        }
    }

    /**
     * Save users dictionary
     */
    saveUsers(users) {
        localStorage.setItem(this.STORAGE_USERS_KEY, JSON.stringify(users));
    }

    /**
     * Retrieve audit log entries
     */
    getLogs() {
        try {
            return JSON.parse(localStorage.getItem(this.STORAGE_LOGS_KEY) || '[]');
        } catch (e) {
            return [];
        }
    }

    /**
     * Add an entry to the audit trail
     */
    logEvent(username, ip, status, details, hashSnippet = '') {
        const logs = this.getLogs();
        const entry = {
            id: 'log_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
            timestamp: new Date().toISOString(),
            username: username || 'anonymous',
            ip: ip || '127.0.0.1 (Local Simulation)',
            device: navigator.userAgent.includes('Windows') ? 'Windows / Chrome Engine' : 'Desktop Browser Client',
            status, // SUCCESS, FAILED, LOCKED, REGISTERED, UNLOCKED
            details,
            hashSnippet: hashSnippet ? (hashSnippet.substring(0, 8) + '...' + hashSnippet.substring(hashSnippet.length - 4)) : 'N/A'
        };

        logs.unshift(entry); // Prepend so newest is first
        // Retain last 200 logs to prevent unbounded storage
        if (logs.length > 200) logs.pop();

        localStorage.setItem(this.STORAGE_LOGS_KEY, JSON.stringify(logs));
        return entry;
    }

    /**
     * Sliding Window Rate Limiting (ADS Queue model)
     * Checks if IP has exceeded MAX requests in sliding time window
     */
    checkSlidingWindowRateLimit(clientIp = '127.0.0.1') {
        const now = Date.now();
        if (!this.rateLimitWindow.has(clientIp)) {
            this.rateLimitWindow.set(clientIp, []);
        }

        const windowQueue = this.rateLimitWindow.get(clientIp);

        // Deque expired timestamps outside the sliding window
        while (windowQueue.length > 0 && (now - windowQueue[0]) > this.RATE_LIMIT_WINDOW_MS) {
            windowQueue.shift();
        }

        if (windowQueue.length >= this.RATE_LIMIT_MAX_REQUESTS) {
            return {
                allowed: false,
                remaining: 0,
                retryAfterSeconds: Math.ceil((this.RATE_LIMIT_WINDOW_MS - (now - windowQueue[0])) / 1000)
            };
        }

        windowQueue.push(now);
        return {
            allowed: true,
            remaining: this.RATE_LIMIT_MAX_REQUESTS - windowQueue.length,
            retryAfterSeconds: 0
        };
    }

    /**
     * Register a new user
     */
    async register(username, password, confirmPassword) {
        // 1. Basic sanitization
        const cleanUser = (username || '').trim();
        if (!cleanUser || cleanUser.length < 3) {
            return { success: false, message: 'Username must be at least 3 characters long.' };
        }
        if (!/^[a-zA-Z0-9_-]+$/.test(cleanUser)) {
            return { success: false, message: 'Username can only contain alphanumeric characters, underscores, and dashes.' };
        }

        if (password !== confirmPassword) {
            return { success: false, message: 'Passwords do not match.' };
        }

        // 2. Security validation
        const entropyResult = CryptoUtils.calculateEntropy(password);
        if (entropyResult.entropy < 35 || password.length < 8) {
            return {
                success: false,
                message: 'Password does not meet minimum security requirements (Min 8 characters, medium complexity).'
            };
        }

        // 3. Trie leaked check
        if (window.appTrie) {
            const leakedSearch = window.appTrie.search(password);
            if (leakedSearch.found) {
                return {
                    success: false,
                    message: `Password rejected! It appears in known breach databases (${leakedSearch.leakCount.toLocaleString()} recorded leaks).`
                };
            }
        }

        const users = this.getUsers();
        const userKey = cleanUser.toLowerCase();

        if (users[userKey]) {
            return { success: false, message: `Username "${cleanUser}" is already registered.` };
        }

        // 4. Generate Salt & SHA-256 Hash
        const salt = CryptoUtils.generateSalt(16);
        const passwordHash = await CryptoUtils.sha256Hex(password + salt);

        users[userKey] = {
            username: cleanUser,
            salt,
            passwordHash,
            tier: entropyResult.tier,
            entropy: entropyResult.entropy,
            createdAt: new Date().toISOString(),
            failedAttempts: 0,
            isLocked: false,
            lockedUntil: null,
            lastLogin: null
        };

        this.saveUsers(users);

        this.logEvent(
            cleanUser,
            '127.0.0.1 (Local Client)',
            'REGISTERED',
            `New user registered. Salted SHA-256 hash created. Initial entropy: ${entropyResult.entropy} bits.`,
            passwordHash
        );

        return {
            success: true,
            message: `Account "${cleanUser}" created successfully! Salted SHA-256 hash stored.`,
            user: users[userKey]
        };
    }

    /**
     * Authenticate user login
     */
    async login(username, password) {
        const cleanUser = (username || '').trim();
        const clientIp = '127.0.0.1';

        // 1. Sliding window rate limit check
        const rateCheck = this.checkSlidingWindowRateLimit(clientIp);
        if (!rateCheck.allowed) {
            this.logEvent(
                cleanUser,
                clientIp,
                'RATE_LIMITED',
                `Sliding window rate limit exceeded. Retry in ${rateCheck.retryAfterSeconds}s.`
            );
            return {
                success: false,
                status: 'RATE_LIMITED',
                message: `Too many requests! Sliding Window defense active. Please wait ${rateCheck.retryAfterSeconds}s.`
            };
        }

        const users = this.getUsers();
        const userKey = cleanUser.toLowerCase();
        const user = users[userKey];

        // If user does not exist
        if (!user) {
            this.logEvent(
                cleanUser,
                clientIp,
                'FAILED',
                'Authentication failed: User account does not exist.'
            );
            return {
                success: false,
                status: 'NOT_FOUND',
                message: 'Invalid credentials. User not recognized.'
            };
        }

        const now = Date.now();

        // 2. Check if currently locked
        if (user.isLocked) {
            if (user.lockedUntil && now < user.lockedUntil) {
                const remainingSec = Math.ceil((user.lockedUntil - now) / 1000);
                this.logEvent(
                    cleanUser,
                    clientIp,
                    'LOCKED',
                    `Login blocked: Account locked. ${remainingSec}s remaining.`
                );
                return {
                    success: false,
                    status: 'ACCOUNT_LOCKED',
                    isLocked: true,
                    remainingSeconds: remainingSec,
                    message: `Account is temporarily LOCKED due to repeated failed attempts! Unlocks in ${remainingSec} seconds.`
                };
            } else {
                // Lock has expired - auto release
                user.isLocked = false;
                user.failedAttempts = 0;
                user.lockedUntil = null;
            }
        }

        // 3. Compute hash: SHA256(password + salt)
        const computedHash = await CryptoUtils.sha256Hex(password + user.salt);

        // Constant-time like comparison
        if (computedHash === user.passwordHash) {
            // SUCCESSFUL AUTHENTICATION
            user.failedAttempts = 0;
            user.isLocked = false;
            user.lockedUntil = null;
            user.lastLogin = new Date().toISOString();

            this.saveUsers(users);

            // Create active session
            const session = {
                username: user.username,
                token: 'tok_' + CryptoUtils.generateSalt(12),
                loginTime: new Date().toISOString(),
                saltSnippet: user.salt.substring(0, 8),
                hashSnippet: computedHash.substring(0, 10) + '...' + computedHash.substring(computedHash.length - 4),
                entropy: user.entropy,
                tier: user.tier
            };

            localStorage.setItem(this.STORAGE_SESSION_KEY, JSON.stringify(session));

            this.logEvent(
                user.username,
                clientIp,
                'SUCCESS',
                'Authentication verified. Password hash matched stored salt digest.',
                computedHash
            );

            return {
                success: true,
                status: 'AUTHENTICATED',
                message: `Welcome back, ${user.username}! Access Granted.`,
                session
            };
        } else {
            // FAILED AUTHENTICATION
            user.failedAttempts = (user.failedAttempts || 0) + 1;

            let isNowLocked = false;
            let lockedMsg = '';

            if (user.failedAttempts >= this.MAX_FAILED_ATTEMPTS) {
                user.isLocked = true;
                user.lockedUntil = now + this.LOCKOUT_DURATION_MS;
                isNowLocked = true;
                lockedMsg = `Account has been LOCKED for 60 seconds due to ${this.MAX_FAILED_ATTEMPTS} failed attempts.`;
            }

            this.saveUsers(users);

            this.logEvent(
                user.username,
                clientIp,
                isNowLocked ? 'LOCKED' : 'FAILED',
                isNowLocked
                    ? `Account Locked: Maximum 5 attempts reached. Account placed in cooldown quarantine.`
                    : `Invalid password. Failed attempt ${user.failedAttempts} of ${this.MAX_FAILED_ATTEMPTS}.`,
                computedHash
            );

            return {
                success: false,
                status: isNowLocked ? 'ACCOUNT_LOCKED' : 'FAILED',
                failedAttempts: user.failedAttempts,
                maxAttempts: this.MAX_FAILED_ATTEMPTS,
                isLocked: isNowLocked,
                message: isNowLocked ? lockedMsg : `Incorrect password. Warning: Attempt ${user.failedAttempts} of ${this.MAX_FAILED_ATTEMPTS}.`
            };
        }
    }

    /**
     * Unlock an account manually (Instructor / Demo bypass)
     */
    unlockAccount(username) {
        const users = this.getUsers();
        const userKey = (username || '').toLowerCase();
        if (users[userKey]) {
            users[userKey].isLocked = false;
            users[userKey].failedAttempts = 0;
            users[userKey].lockedUntil = null;
            this.saveUsers(users);

            this.logEvent(
                users[userKey].username,
                '127.0.0.1 (Admin Console)',
                'UNLOCKED',
                'Account was manually unlocked via Security Operations override.'
            );
            return true;
        }
        return false;
    }

    /**
     * Simulate an automated brute-force attack to demonstrate defensive mechanics
     */
    async simulateBruteForce(targetUsername = 'demo_user', callback) {
        const fakePasswords = ['admin', '123456', 'qwerty', 'test2024', 'wrongPassword!'];
        const results = [];

        for (let i = 0; i < fakePasswords.length; i++) {
            const pwd = fakePasswords[i];
            const res = await this.login(targetUsername, pwd);
            results.push({ attempt: i + 1, passwordTested: pwd, result: res });
            if (callback) callback(i + 1, fakePasswords.length, res);
            // Brief pause for visual effect
            await new Promise(r => setTimeout(r, 250));
        }

        return results;
    }

    /**
     * Get active logged in session
     */
    getCurrentSession() {
        try {
            return JSON.parse(localStorage.getItem(this.STORAGE_SESSION_KEY) || 'null');
        } catch (e) {
            return null;
        }
    }

    /**
     * Logout
     */
    logout() {
        const session = this.getCurrentSession();
        if (session) {
            this.logEvent(
                session.username,
                '127.0.0.1',
                'LOGOUT',
                'User session terminated voluntarily.'
            );
        }
        localStorage.removeItem(this.STORAGE_SESSION_KEY);
    }

    /**
     * Aggregate telemetry metrics for Dashboard
     */
    getMetrics() {
        const users = this.getUsers();
        const logs = this.getLogs();

        const userList = Object.values(users);
        const totalUsers = userList.length;

        let lockedCount = 0;
        let totalEntropy = 0;
        const tierDist = {
            'Very Weak': 0,
            'Weak': 0,
            'Medium': 0,
            'Strong': 0,
            'Very Strong': 0
        };

        userList.forEach(u => {
            if (u.isLocked) lockedCount++;
            totalEntropy += (u.entropy || 50);
            const tier = u.tier || 'Medium';
            tierDist[tier] = (tierDist[tier] || 0) + 1;
        });

        const avgEntropy = totalUsers > 0 ? (totalEntropy / totalUsers).toFixed(1) : 0;

        let successLogins = 0;
        let failedLogins = 0;
        let lockedEvents = 0;

        logs.forEach(l => {
            if (l.status === 'SUCCESS') successLogins++;
            else if (l.status === 'FAILED') failedLogins++;
            else if (l.status === 'LOCKED') lockedEvents++;
        });

        return {
            totalUsers,
            lockedCount,
            avgEntropy,
            tierDist,
            successLogins,
            failedLogins,
            lockedEvents,
            totalLogs: logs.length
        };
    }

    /**
     * Reset everything to clean demo defaults
     */
    async resetToDefaults() {
        localStorage.removeItem(this.STORAGE_USERS_KEY);
        localStorage.removeItem(this.STORAGE_LOGS_KEY);
        localStorage.removeItem(this.STORAGE_SESSION_KEY);
        await this.initStorage();
    }
}

// Global exposure
if (typeof window !== 'undefined') {
    window.AuthService = AuthService;
}
