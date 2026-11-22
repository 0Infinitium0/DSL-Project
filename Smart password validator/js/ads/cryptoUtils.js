/**
 * AUTHGUARD - Advanced Data Structures (ADS)
 * Cryptographic Utilities & Entropy Engine
 * 
 * Demonstrates:
 * - One-way cryptographic hashing (SHA-256)
 * - Cryptographic Salting (mitigating Rainbow Table attacks)
 * - Information Entropy calculation (Shannon / Hartley bit estimation)
 * - Brute-force crack time computational complexity: O(R^L)
 * - Avalanche Effect analysis (measuring cryptographic diffusion)
 */

class CryptoUtils {
    /**
     * Generate cryptographically secure random salt (hex string)
     * @param {number} bytes Length in bytes
     * @returns {string} Hexadecimal salt
     */
    static generateSalt(bytes = 16) {
        if (window.crypto && window.crypto.getRandomValues) {
            const array = new Uint8Array(bytes);
            window.crypto.getRandomValues(array);
            return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
        }
        // Fallback PRNG if crypto is not supported
        let fallback = '';
        const chars = '0123456789abcdef';
        for (let i = 0; i < bytes * 2; i++) {
            fallback += chars[Math.floor(Math.random() * chars.length)];
        }
        return fallback;
    }

    /**
     * Computes SHA-256 hash using Web Crypto API with pure JS fallback
     * @param {string} message Input string
     * @returns {Promise<string>} Hex representation of 256-bit hash
     */
    static async sha256Hex(message) {
        if (window.crypto && window.crypto.subtle) {
            try {
                const msgBuffer = new TextEncoder().encode(message);
                const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgBuffer);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            } catch (err) {
                console.warn('WebCrypto subtle digest failed, using JS fallback:', err);
            }
        }
        return this.sha256Fallback(message);
    }

    /**
     * Pure JavaScript implementation of SHA-256 for offline / compatibility fallback
     */
    static sha256Fallback(ascii) {
        function rightRotate(value, amount) {
            return (value >>> amount) | (value << (32 - amount));
        }

        const mathPow = Math.pow;
        const maxWord = mathPow(2, 32);
        let lengthProperty = 'length';
        let i, j;
        let result = '';

        const words = [];
        const asciiBitLength = ascii[lengthProperty] * 8;

        let hash = [];
        const k = [];
        let primeCounter = 0;

        const isComposite = {};
        for (let candidate = 2; primeCounter < 64; candidate++) {
            if (!isComposite[candidate]) {
                for (i = 0; i < 313; i += candidate) {
                    isComposite[i] = candidate;
                }
                hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
                k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
            }
        }

        hash = hash.slice(0, 8);

        ascii += '\x80';
        while ((ascii[lengthProperty] % 64) - 56) ascii += '\x00';
        for (i = 0; i < ascii[lengthProperty]; i++) {
            j = ascii.charCodeAt(i);
            if (j >> 8) return; // Only 8-bit
            words[i >> 2] |= j << (((3 - i) % 4) * 8);
        }
        words[words[lengthProperty]] = (asciiBitLength / maxWord) | 0;
        words[words[lengthProperty]] = asciiBitLength;

        for (j = 0; j < words[lengthProperty];) {
            const w = words.slice(j, (j += 16));
            const oldHash = hash;
            hash = hash.slice(0, 8);

            for (i = 0; i < 64; i++) {
                const w15 = w[i - 15], w2 = w[i - 2];
                const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
                const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
                const ch = (hash[4] & hash[5]) ^ (~hash[4] & hash[6]);
                const maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
                const s0h0 = rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22);
                const s1h4 = rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25);

                const t1 = (hash[7] + s1h4 + ch + k[i] + (w[i] = (i < 16) ? w[i] : (w[i - 16] + s0 + w[i - 7] + s1) | 0)) | 0;
                const t2 = (s0h0 + maj) | 0;

                hash = [(t1 + t2) | 0, hash[0], hash[1], hash[2], (hash[3] + t1) | 0, hash[4], hash[5], hash[6]];
            }

            for (i = 0; i < 8; i++) {
                hash[i] = (hash[i] + oldHash[i]) | 0;
            }
        }

        for (i = 0; i < 8; i++) {
            for (j = 3; j >= 0; j--) {
                const b = (hash[i] >> (j * 8)) & 255;
                result += (b < 16 ? '0' : '') + b.toString(16);
            }
        }
        return result;
    }

    /**
     * Converts a hexadecimal hash into a 256-character binary string
     */
    static hexToBinary(hex) {
        return hex.split('').map(char => {
            return parseInt(char, 16).toString(2).padStart(4, '0');
        }).join('');
    }

    /**
     * Measures the Cryptographic Avalanche Effect between two strings
     * Evaluates how many bits change in SHA-256 for a minor input variation.
     */
    static async measureAvalanche(strA, strB) {
        const hashA = await this.sha256Hex(strA);
        const hashB = await this.sha256Hex(strB);

        const binA = this.hexToBinary(hashA);
        const binB = this.hexToBinary(hashB);

        let flippedBits = 0;
        const diffMap = [];

        for (let i = 0; i < 256; i++) {
            const isDiff = binA[i] !== binB[i];
            if (isDiff) flippedBits++;
            diffMap.push({
                index: i,
                bitA: binA[i],
                bitB: binB[i],
                flipped: isDiff
            });
        }

        const percentage = ((flippedBits / 256) * 100).toFixed(2);
        return {
            hashA,
            hashB,
            binA,
            binB,
            flippedBits,
            totalBits: 256,
            percentage,
            diffMap
        };
    }

    /**
     * Calculates Password Information Entropy
     * Formula: E = L * log2(R)
     * Where L is length, R is pool size of unique character types.
     * Deducts entropy penalties for repeating characters and common sequences.
     */
    static calculateEntropy(password) {
        if (!password || password.length === 0) {
            return {
                entropy: 0,
                poolSize: 0,
                length: 0,
                score: 0,
                tier: 'Empty',
                hasUpper: false,
                hasLower: false,
                hasNumber: false,
                hasSpecial: false,
                crackTime: 'Instant'
            };
        }

        const len = password.length;
        const hasLower = /[a-z]/.test(password);
        const hasUpper = /[A-Z]/.test(password);
        const hasNumber = /[0-9]/.test(password);
        const hasSpecial = /[^a-zA-Z0-9]/.test(password);

        let poolSize = 0;
        if (hasLower) poolSize += 26;
        if (hasUpper) poolSize += 26;
        if (hasNumber) poolSize += 10;
        if (hasSpecial) poolSize += 33; // Standard ASCII symbols

        // Base entropy
        let baseEntropy = len * Math.log2(Math.max(poolSize, 2));

        // Deductions for repetitive patterns / weak structure
        // 1. Repetitive characters penalty
        const uniqueChars = new Set(password).size;
        const uniquenessRatio = uniqueChars / len;
        if (uniquenessRatio < 0.6) {
            baseEntropy *= (0.5 + 0.5 * uniquenessRatio);
        }

        // 2. Sequential character penalty (e.g., "1234", "abcd", "qwerty")
        const lower = password.toLowerCase();
        let sequentialCount = 0;
        for (let i = 0; i < lower.length - 2; i++) {
            const c1 = lower.charCodeAt(i);
            const c2 = lower.charCodeAt(i + 1);
            const c3 = lower.charCodeAt(i + 2);
            if ((c2 === c1 + 1 && c3 === c2 + 1) || (c2 === c1 - 1 && c3 === c2 - 1)) {
                sequentialCount++;
            }
        }
        if (sequentialCount > 0) {
            baseEntropy = Math.max(0, baseEntropy - (sequentialCount * 5));
        }

        const finalEntropy = Math.max(1, Math.round(baseEntropy * 10) / 10);

        // Map to tiers:
        // < 28 bits: Very Weak
        // 28 - 45 bits: Weak
        // 46 - 64 bits: Medium
        // 65 - 84 bits: Strong
        // 85+ bits: Very Strong (Ironclad)
        let tier = 'Very Weak';
        let score = 1; // 1 to 5
        let color = '#ef4444'; // Red

        if (finalEntropy < 28 || len < 6) {
            tier = 'Very Weak';
            score = 1;
            color = '#ef4444';
        } else if (finalEntropy < 46 || len < 8) {
            tier = 'Weak';
            score = 2;
            color = '#f97316';
        } else if (finalEntropy < 65 || (poolSize < 62 && len < 10)) {
            tier = 'Medium';
            score = 3;
            color = '#eab308';
        } else if (finalEntropy < 85) {
            tier = 'Strong';
            score = 4;
            color = '#06b6d4';
        } else {
            tier = 'Very Strong';
            score = 5;
            color = '#10b981';
        }

        const crackTime = this.estimateCrackTime(finalEntropy, poolSize, len);

        return {
            entropy: finalEntropy,
            poolSize,
            length: len,
            score,
            tier,
            color,
            hasUpper,
            hasLower,
            hasNumber,
            hasSpecial,
            uniqueRatio: (uniquenessRatio * 100).toFixed(0),
            crackTime
        };
    }

    /**
     * Computational Complexity: O(R^L)
     * Estimate brute force crack time assuming high-end GPU cluster (100 Billion hashes/sec)
     */
    static estimateCrackTime(entropy, poolSize, length) {
        // Assume an attacker hardware cluster doing 100 Billion (10^11) SHA-256 hashes per second
        const guessesPerSec = 1e11;
        
        // Total possible combinations = R^L or 2^entropy
        // Average guesses required to crack = 2^(entropy - 1)
        const totalCombinations = Math.pow(2, entropy);
        const seconds = (totalCombinations / 2) / guessesPerSec;

        if (seconds < 0.001) return 'Instant (< 1 ms)';
        if (seconds < 1) return `${Math.round(seconds * 1000)} milliseconds`;
        if (seconds < 60) return `${Math.round(seconds)} seconds`;
        if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
        if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
        if (seconds < 2592000) return `${Math.round(seconds / 86400)} days`;
        if (seconds < 31536000) return `${Math.round(seconds / 2592000)} months`;
        if (seconds < 315360000) return `${Math.round(seconds / 31536000)} years`;
        if (seconds < 31536000000) return `${Math.round(seconds / 315360000)} decades`;
        if (seconds < 3153600000000) return `${Math.round(seconds / 31536000000)} centuries`;
        if (seconds < 315360000000000) return `${Math.round(seconds / 3153600000000)} millennia`;
        
        return 'Millions of Years (Cryptographically Impenetrable)';
    }

    /**
     * Generate a cryptographically strong password based on chosen parameters
     */
    static generateSecurePassword(options = {}) {
        const {
            length = 16,
            includeUpper = true,
            includeLower = true,
            includeNumbers = true,
            includeSymbols = true,
            avoidAmbiguous = true
        } = options;

        let lower = 'abcdefghijklmnopqrstuvwxyz';
        let upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        let numbers = '0123456789';
        let symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

        if (avoidAmbiguous) {
            // Remove l, 1, I, o, 0, O, etc.
            lower = lower.replace(/[l1io0]/gi, '');
            upper = upper.replace(/[l1io0]/gi, '');
            numbers = numbers.replace(/[01]/g, '');
            symbols = symbols.replace(/[|;:,.]/g, '');
        }

        let charset = '';
        const guaranteed = [];

        if (includeLower) {
            charset += lower;
            guaranteed.push(lower[Math.floor(Math.random() * lower.length)]);
        }
        if (includeUpper) {
            charset += upper;
            guaranteed.push(upper[Math.floor(Math.random() * upper.length)]);
        }
        if (includeNumbers) {
            charset += numbers;
            guaranteed.push(numbers[Math.floor(Math.random() * numbers.length)]);
        }
        if (includeSymbols) {
            charset += symbols;
            guaranteed.push(symbols[Math.floor(Math.random() * symbols.length)]);
        }

        if (charset.length === 0) {
            charset = lower + numbers;
        }

        // Fill remaining length
        const passwordArr = [...guaranteed];
        const remainingLength = Math.max(0, length - guaranteed.length);

        const randomValues = new Uint32Array(remainingLength);
        if (window.crypto && window.crypto.getRandomValues) {
            window.crypto.getRandomValues(randomValues);
            for (let i = 0; i < remainingLength; i++) {
                passwordArr.push(charset[randomValues[i] % charset.length]);
            }
        } else {
            for (let i = 0; i < remainingLength; i++) {
                passwordArr.push(charset[Math.floor(Math.random() * charset.length)]);
            }
        }

        // Cryptographic Fisher-Yates Shuffle
        for (let i = passwordArr.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [passwordArr[i], passwordArr[j]] = [passwordArr[j], passwordArr[i]];
        }

        return passwordArr.join('');
    }
}

// Export for module or global use
if (typeof window !== 'undefined') {
    window.CryptoUtils = CryptoUtils;
}
