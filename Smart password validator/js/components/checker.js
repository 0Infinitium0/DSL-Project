/**
 * AUTHGUARD - Advanced Data Structures (ADS)
 * Password Strength Checker & Generator Component
 * 
 * Features:
 * - Real-time entropy & pattern analysis
 * - Dynamic 5-tier strength gauge with glowing animations
 * - Live security requirement checklist
 * - Trie-based breached substring detection
 * - Brute-force crack time complexity estimation O(R^L)
 * - Cryptographically secure password generator
 * - Clipboard copy with toast feedback
 */

class PasswordCheckerComponent {
    constructor() {
        this.input = document.getElementById('checker-password-input');
        this.toggleBtn = document.getElementById('checker-toggle-visibility');
        this.clearBtn = document.getElementById('checker-clear-input');
        this.strengthBar = document.getElementById('checker-strength-progress');
        this.strengthTierText = document.getElementById('checker-strength-tier');
        this.strengthScoreText = document.getElementById('checker-strength-score');
        this.entropyVal = document.getElementById('checker-entropy-val');
        this.crackTimeVal = document.getElementById('checker-crack-time');
        this.lengthVal = document.getElementById('checker-length-val');
        this.poolVal = document.getElementById('checker-pool-val');

        // Checklist elements
        this.chkLength = document.getElementById('chk-length');
        this.chkUpper = document.getElementById('chk-upper');
        this.chkLower = document.getElementById('chk-lower');
        this.chkNumber = document.getElementById('chk-number');
        this.chkSpecial = document.getElementById('chk-special');
        this.chkTrie = document.getElementById('chk-trie');

        // Suggestions box
        this.suggestionsBox = document.getElementById('checker-suggestions-list');

        // Generator elements
        this.genLengthSlider = document.getElementById('gen-length-slider');
        this.genLengthDisplay = document.getElementById('gen-length-display');
        this.genUpperCheck = document.getElementById('gen-chk-upper');
        this.genLowerCheck = document.getElementById('gen-chk-lower');
        this.genNumbersCheck = document.getElementById('gen-chk-numbers');
        this.genSymbolsCheck = document.getElementById('gen-chk-symbols');
        this.genAvoidAmbiguous = document.getElementById('gen-chk-ambiguous');
        this.genGenerateBtn = document.getElementById('gen-btn-generate');
        this.genCopyBtn = document.getElementById('gen-btn-copy');
        this.genOutput = document.getElementById('gen-password-output');

        this.initEventListeners();
        this.generateNewPassword(); // initial generated password
    }

    initEventListeners() {
        if (this.input) {
            this.input.addEventListener('input', () => this.analyzePassword(this.input.value));
        }

        if (this.toggleBtn) {
            this.toggleBtn.addEventListener('click', () => {
                const isPassword = this.input.type === 'password';
                this.input.type = isPassword ? 'text' : 'password';
                this.toggleBtn.innerHTML = isPassword ? '<i class="fa-solid fa-eye-slash"></i>' : '<i class="fa-solid fa-eye"></i>';
            });
        }

        if (this.clearBtn) {
            this.clearBtn.addEventListener('click', () => {
                this.input.value = '';
                this.analyzePassword('');
                this.input.focus();
            });
        }

        if (this.genLengthSlider) {
            this.genLengthSlider.addEventListener('input', (e) => {
                if (this.genLengthDisplay) {
                    this.genLengthDisplay.textContent = e.target.value;
                }
                this.generateNewPassword();
            });
        }

        [this.genUpperCheck, this.genLowerCheck, this.genNumbersCheck, this.genSymbolsCheck, this.genAvoidAmbiguous].forEach(el => {
            if (el) {
                el.addEventListener('change', () => this.generateNewPassword());
            }
        });

        if (this.genGenerateBtn) {
            this.genGenerateBtn.addEventListener('click', () => {
                this.generateNewPassword();
                // Visual glitch/bounce effect
                this.genOutput.classList.add('pulse-glow');
                setTimeout(() => this.genOutput.classList.remove('pulse-glow'), 400);
            });
        }

        if (this.genCopyBtn) {
            this.genCopyBtn.addEventListener('click', () => {
                const text = this.genOutput.value;
                if (!text) return;
                navigator.clipboard.writeText(text).then(() => {
                    window.app.showToast('Copied to clipboard!', 'success');
                }).catch(() => {
                    // Fallback
                    this.genOutput.select();
                    document.execCommand('copy');
                    window.app.showToast('Copied to clipboard!', 'success');
                });
            });
        }

        // Test in input button
        const testInInputBtn = document.getElementById('gen-btn-use-generated');
        if (testInInputBtn) {
            testInInputBtn.addEventListener('click', () => {
                if (this.input && this.genOutput) {
                    this.input.value = this.genOutput.value;
                    this.analyzePassword(this.input.value);
                    window.app.showToast('Generated password loaded into security chamber!', 'info');
                    this.input.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }
            });
        }
    }

    /**
     * Core password analysis engine combining Entropy math + Trie search + Bloom Filter verification
     */
    analyzePassword(password) {
        if (!password) {
            this.resetDisplay();
            return;
        }

        const entropyData = CryptoUtils.calculateEntropy(password);

        // ADS Trie check: Check if whole password or substrings are in breached dictionary
        let trieMatch = null;
        let containedLeaks = [];
        if (window.appTrie) {
            const exactSearch = window.appTrie.search(password);
            if (exactSearch.found) {
                trieMatch = exactSearch;
            }
            containedLeaks = window.appTrie.findContainedBreachedWords(password);
        }

        // ADS Bloom Filter check
        let bloomResult = null;
        if (window.appBloomFilter) {
            bloomResult = window.appBloomFilter.query(password);
        }

        // Adjust score if breached in Trie
        let finalTier = entropyData.tier;
        let finalScore = entropyData.score;
        let finalColor = entropyData.color;

        if (trieMatch) {
            finalTier = 'Compromised (Breached)';
            finalScore = 1;
            finalColor = '#ef4444';
        }

        // Update progress bar
        const percentageMap = {
            'Very Weak': 20,
            'Weak': 40,
            'Medium': 65,
            'Strong': 85,
            'Very Strong': 100,
            'Compromised (Breached)': 15
        };

        const progressPercent = percentageMap[finalTier] || 20;
        if (this.strengthBar) {
            this.strengthBar.style.width = `${progressPercent}%`;
            this.strengthBar.style.backgroundColor = finalColor;
            this.strengthBar.style.boxShadow = `0 0 15px ${finalColor}88`;
        }

        if (this.strengthTierText) {
            this.strengthTierText.textContent = finalTier;
            this.strengthTierText.style.color = finalColor;
        }

        if (this.strengthScoreText) {
            this.strengthScoreText.textContent = `${finalScore}/5`;
        }

        if (this.entropyVal) {
            this.entropyVal.textContent = `${entropyData.entropy} bits`;
        }

        if (this.crackTimeVal) {
            this.crackTimeVal.textContent = trieMatch ? 'Instant (< 1 ms - In Trie Wordlist)' : entropyData.crackTime;
            this.crackTimeVal.style.color = trieMatch ? '#ef4444' : finalColor;
        }

        if (this.lengthVal) {
            this.lengthVal.textContent = `${password.length} chars`;
        }

        if (this.poolVal) {
            this.poolVal.textContent = `${entropyData.poolSize} chars`;
        }

        // Update Checklist
        this.updateChecklistItem(this.chkLength, password.length >= 8, `${password.length}/8 characters`);
        this.updateChecklistItem(this.chkUpper, entropyData.hasUpper);
        this.updateChecklistItem(this.chkLower, entropyData.hasLower);
        this.updateChecklistItem(this.chkNumber, entropyData.hasNumber);
        this.updateChecklistItem(this.chkSpecial, entropyData.hasSpecial);

        const isCleanOfTrie = !trieMatch && containedLeaks.length === 0;
        let trieStatusMsg = 'No dictionary match';
        if (trieMatch) {
            trieStatusMsg = `Compromised (${trieMatch.leakCount.toLocaleString()} leaks)`;
        } else if (containedLeaks.length > 0) {
            trieStatusMsg = `Contains pattern: "${containedLeaks[0].word}"`;
        }
        this.updateChecklistItem(this.chkTrie, isCleanOfTrie, trieStatusMsg);

        // Generate dynamic recommendations
        this.renderSuggestions(password, entropyData, trieMatch, containedLeaks);
    }

    updateChecklistItem(element, passed, customText) {
        if (!element) return;
        const icon = element.querySelector('.chk-icon');
        const badge = element.querySelector('.chk-badge');

        if (passed) {
            element.classList.remove('failed');
            element.classList.add('passed');
            if (icon) icon.innerHTML = '<i class="fa-solid fa-circle-check text-emerald-400"></i>';
        } else {
            element.classList.remove('passed');
            element.classList.add('failed');
            if (icon) icon.innerHTML = '<i class="fa-solid fa-circle-xmark text-rose-500"></i>';
        }

        if (badge && customText) {
            badge.textContent = customText;
        }
    }

    renderSuggestions(password, entropy, trieMatch, containedLeaks) {
        if (!this.suggestionsBox) return;
        const suggestions = [];

        if (trieMatch) {
            suggestions.push({
                icon: 'fa-triangle-exclamation',
                type: 'danger',
                text: `CRITICAL: This exact password appears in public leak datasets (${trieMatch.leakCount.toLocaleString()} times). Attackers check this first in wordlist attacks!`
            });
        }

        if (containedLeaks.length > 0 && !trieMatch) {
            suggestions.push({
                icon: 'fa-database',
                type: 'warning',
                text: `ADS Trie Alert: Found common breached substring "${containedLeaks.map(c => c.word).join(', ')}". Replace with non-dictionary phrases.`
            });
        }

        if (password.length < 12) {
            suggestions.push({
                icon: 'fa-ruler-combined',
                type: 'info',
                text: `Increasing length from ${password.length} to 14+ characters increases entropy exponentially: O(R^14) vs O(R^${password.length}).`
            });
        }

        if (!entropy.hasSpecial) {
            suggestions.push({
                icon: 'fa-hashtag',
                type: 'info',
                text: 'Add symbols (!@#$%^&*) to expand the character pool size R from 62 to 95.'
            });
        }

        if (!entropy.hasNumber) {
            suggestions.push({
                icon: 'fa-arrow-up-1-9',
                type: 'info',
                text: 'Incorporate numbers scattered unpredictably across the string.'
            });
        }

        if (entropy.entropy >= 75 && !trieMatch) {
            suggestions.push({
                icon: 'fa-shield-halved',
                type: 'success',
                text: 'Excellent entropy! This password exceeds modern enterprise and defense requirements.'
            });
        }

        if (suggestions.length === 0) {
            suggestions.push({
                icon: 'fa-circle-check',
                type: 'success',
                text: 'Password meets recommended standards.'
            });
        }

        this.suggestionsBox.innerHTML = suggestions.map(s => `
            <li class="suggestion-item suggestion-${s.type}">
                <i class="fa-solid ${s.icon}"></i>
                <span>${s.text}</span>
            </li>
        `).join('');
    }

    resetDisplay() {
        if (this.strengthBar) {
            this.strengthBar.style.width = '0%';
            this.strengthBar.style.boxShadow = 'none';
        }
        if (this.strengthTierText) {
            this.strengthTierText.textContent = 'Awaiting Input';
            this.strengthTierText.style.color = '#94a3b8';
        }
        if (this.strengthScoreText) this.strengthScoreText.textContent = '0/5';
        if (this.entropyVal) this.entropyVal.textContent = '0 bits';
        if (this.crackTimeVal) {
            this.crackTimeVal.textContent = 'Instant';
            this.crackTimeVal.style.color = '#94a3b8';
        }
        if (this.lengthVal) this.lengthVal.textContent = '0 chars';
        if (this.poolVal) this.poolVal.textContent = '0 chars';

        [this.chkLength, this.chkUpper, this.chkLower, this.chkNumber, this.chkSpecial, this.chkTrie].forEach(el => {
            this.updateChecklistItem(el, false);
        });

        if (this.suggestionsBox) {
            this.suggestionsBox.innerHTML = `
                <li class="suggestion-item suggestion-info">
                    <i class="fa-solid fa-lightbulb"></i>
                    <span>Type a password above to trigger real-time ADS entropy math and Trie dictionary screening.</span>
                </li>
            `;
        }
    }

    generateNewPassword() {
        const length = parseInt(this.genLengthSlider ? this.genLengthSlider.value : 16, 10);
        const options = {
            length,
            includeUpper: this.genUpperCheck ? this.genUpperCheck.checked : true,
            includeLower: this.genLowerCheck ? this.genLowerCheck.checked : true,
            includeNumbers: this.genNumbersCheck ? this.genNumbersCheck.checked : true,
            includeSymbols: this.genSymbolsCheck ? this.genSymbolsCheck.checked : true,
            avoidAmbiguous: this.genAvoidAmbiguous ? this.genAvoidAmbiguous.checked : true
        };

        const generated = CryptoUtils.generateSecurePassword(options);
        if (this.genOutput) {
            this.genOutput.value = generated;
        }
    }
}

// Global exposure
if (typeof window !== 'undefined') {
    window.PasswordCheckerComponent = PasswordCheckerComponent;
}
