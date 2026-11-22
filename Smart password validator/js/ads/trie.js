/**
 * AUTHGUARD - Advanced Data Structures (ADS)
 * Trie (Prefix Tree) Implementation for Leaked Password & Dictionary Detection
 * 
 * ADS Features:
 * - O(L) Search & Insertion where L is string length, invariant of dictionary size N
 * - Prefix matching for security autocomplete & common root detection
 * - Substring detection for finding breached password components
 * - Traversal path recording for live interactive visualizer
 */

class TrieNode {
    constructor(char = '') {
        this.char = char;
        this.children = new Map(); // Map character -> TrieNode
        this.isEndOfWord = false;
        this.frequency = 0;        // Commonality rank in breached databases
        this.leakCount = 0;        // Simulated breach appearance count
    }
}

class Trie {
    constructor() {
        this.root = new TrieNode();
        this.wordCount = 0;
        this.nodeCount = 1; // Root node
        this.initDefaultDictionary();
    }

    /**
     * Inserts a word into the Trie - O(L) time complexity
     * @param {string} word The word to insert
     * @param {number} leakCount Breached occurrence frequency
     */
    insert(word, leakCount = 1000) {
        if (!word) return;
        const normalized = word.toLowerCase().trim();
        let current = this.root;

        for (let i = 0; i < normalized.length; i++) {
            const char = normalized[i];
            if (!current.children.has(char)) {
                const newNode = new TrieNode(char);
                current.children.set(char, newNode);
                this.nodeCount++;
            }
            current = current.children.get(char);
        }

        if (!current.isEndOfWord) {
            current.isEndOfWord = true;
            this.wordCount++;
        }
        current.leakCount = Math.max(current.leakCount, leakCount);
    }

    /**
     * Searches for exact word in Trie - O(L) time complexity
     * @param {string} word
     * @returns {object} { found: boolean, leakCount: number, path: Array<string> }
     */
    search(word) {
        if (!word) return { found: false, leakCount: 0, path: [] };
        const normalized = word.toLowerCase().trim();
        let current = this.root;
        const path = ['ROOT'];

        for (let i = 0; i < normalized.length; i++) {
            const char = normalized[i];
            if (!current.children.has(char)) {
                return { found: false, leakCount: 0, path };
            }
            current = current.children.get(char);
            path.push(char);
        }

        return {
            found: current.isEndOfWord,
            leakCount: current.isEndOfWord ? current.leakCount : 0,
            path
        };
    }

    /**
     * Checks if any word starts with the given prefix - O(P) time complexity
     * @param {string} prefix
     * @returns {boolean}
     */
    startsWith(prefix) {
        if (!prefix) return true;
        const normalized = prefix.toLowerCase().trim();
        let current = this.root;

        for (let i = 0; i < normalized.length; i++) {
            const char = normalized[i];
            if (!current.children.has(char)) return false;
            current = current.children.get(char);
        }
        return true;
    }

    /**
     * Finds common breached words embedded within a password
     * E.g. "Dragon123!" contains "dragon" and "123"
     * @param {string} password 
     * @returns {Array<object>} Array of matched breached substrings
     */
    findContainedBreachedWords(password) {
        if (!password) return [];
        const normalized = password.toLowerCase();
        const matches = [];

        // Check all substrings of length >= 3
        const minLen = 3;
        for (let start = 0; start < normalized.length; start++) {
            let current = this.root;
            for (let end = start; end < normalized.length; end++) {
                const char = normalized[end];
                if (!current.children.has(char)) break;
                current = current.children.get(char);

                if (current.isEndOfWord && (end - start + 1) >= minLen) {
                    const matchedWord = normalized.substring(start, end + 1);
                    matches.push({
                        word: matchedWord,
                        start,
                        end,
                        leakCount: current.leakCount
                    });
                }
            }
        }

        // Deduplicate and return strongest matches
        return matches.filter((m, idx, self) => 
            idx === self.findIndex(t => t.word === m.word)
        );
    }

    /**
     * Step-by-step search recording each node traversal for interactive visualization
     */
    traceSearch(word) {
        const normalized = (word || '').toLowerCase();
        const steps = [];
        let current = this.root;

        steps.push({
            char: 'ROOT',
            status: 'root',
            availableChildren: Array.from(current.children.keys())
        });

        for (let i = 0; i < normalized.length; i++) {
            const char = normalized[i];
            if (current.children.has(char)) {
                current = current.children.get(char);
                steps.push({
                    char,
                    status: 'matched',
                    isEndOfWord: current.isEndOfWord,
                    leakCount: current.leakCount,
                    availableChildren: Array.from(current.children.keys())
                });
            } else {
                steps.push({
                    char,
                    status: 'missed',
                    isEndOfWord: false,
                    leakCount: 0,
                    availableChildren: Array.from(current.children.keys())
                });
                return { steps, found: false, leakCount: 0 };
            }
        }

        return {
            steps,
            found: current.isEndOfWord,
            leakCount: current.isEndOfWord ? current.leakCount : 0
        };
    }

    /**
     * Exports a hierarchical snapshot of the Trie for interactive D3 / SVG graph rendering
     * @param {number} maxDepth Maximum depth to serialize to avoid huge DOMs
     */
    serializeSubtree(node = this.root, char = 'ROOT', depth = 0, maxDepth = 4) {
        const result = {
            name: char === 'ROOT' ? 'ROOT [Trie]' : char,
            isEnd: node.isEndOfWord,
            leakCount: node.leakCount,
            children: []
        };

        if (depth < maxDepth) {
            // Sort children alphabetically for clean rendering
            const keys = Array.from(node.children.keys()).sort();
            for (const key of keys) {
                const childNode = node.children.get(key);
                result.children.push(this.serializeSubtree(childNode, key, depth + 1, maxDepth));
            }
        }

        return result;
    }

    /**
     * Preloads realistic real-world breached passwords (from RockYou / SecLists top breaches)
     */
    initDefaultDictionary() {
        const commonBreachedPasswords = [
            // Top globally breached
            { word: '123456', leaks: 34500000 },
            { word: 'password', leaks: 28900000 },
            { word: '123456789', leaks: 18200000 },
            { word: '12345678', leaks: 14200000 },
            { word: '12345', leaks: 12000000 },
            { word: 'qwerty', leaks: 11500000 },
            { word: '111111', leaks: 9400000 },
            { word: '1234567', leaks: 8100000 },
            { word: 'dragon', leaks: 5900000 },
            { word: 'welcome', leaks: 5600000 },
            { word: 'football', leaks: 4700000 },
            { word: 'monkey', leaks: 4400000 },
            { word: 'sunshine', leaks: 4100000 },
            { word: 'master', leaks: 3900000 },
            { word: 'computer', leaks: 3700000 },
            { word: 'iloveyou', leaks: 3500000 },
            { word: 'princess', leaks: 3400000 },
            { word: 'admin', leaks: 3300000 },
            { word: 'administrator', leaks: 3100000 },
            { word: 'secret', leaks: 2900000 },
            { word: 'shadow', leaks: 2700000 },
            { word: 'baseball', leaks: 2600000 },
            { word: 'superman', leaks: 2500000 },
            { word: 'starwars', leaks: 2400000 },
            { word: 'batman', leaks: 2300000 },
            { word: 'pass123', leaks: 2200000 },
            { word: 'test', leaks: 2100000 },
            { word: 'testing', leaks: 2000000 },
            { word: 'login', leaks: 1900000 },
            { word: 'access', leaks: 1800000 },
            { word: 'server', leaks: 1700000 },
            { word: 'security', leaks: 1650000 },
            { word: 'hunter2', leaks: 1600000 },
            { word: 'hacker', leaks: 1550000 },
            { word: 'root', leaks: 1500000 },
            { word: 'letmein', leaks: 1450000 },
            { word: 'trustno1', leaks: 1400000 },
            { word: 'default', leaks: 1350000 },
            { word: 'guest', leaks: 1300000 },
            { word: 'oracle', leaks: 1250000 },
            { word: 'cisco', leaks: 1200000 },
            { word: 'coffee', leaks: 1150000 },
            { word: 'matrix', leaks: 1100000 },
            { word: 'system', leaks: 1050000 },
            { word: 'changeit', leaks: 1000000 },
            { word: 'database', leaks: 980000 },
            { word: 'college', leaks: 950000 },
            { word: 'student', leaks: 920000 },
            { word: 'engineer', leaks: 890000 },
            { word: 'project', leaks: 860000 },
            { word: 'summer', leaks: 840000 },
            { word: 'winter', leaks: 820000 },
            { word: 'freedom', leaks: 800000 },
            { word: 'killer', leaks: 780000 },
            { word: 'buster', leaks: 760000 },
            { word: 'diamond', leaks: 740000 },
            { word: 'cookie', leaks: 720000 },
            { word: 'orange', leaks: 700000 },
            { word: 'purple', leaks: 680000 },
            { word: 'thunder', leaks: 660000 }
        ];

        commonBreachedPasswords.forEach(item => {
            this.insert(item.word, item.leaks);
        });
    }
}

// Global exposure
if (typeof window !== 'undefined') {
    window.Trie = Trie;
    window.TrieNode = TrieNode;
}
