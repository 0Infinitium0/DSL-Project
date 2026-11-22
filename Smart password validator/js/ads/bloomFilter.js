/**
 * AUTHGUARD - Advanced Data Structures (ADS)
 * Bloom Filter (Probabilistic Space-Efficient Set Membership)
 * 
 * ADS Features:
 * - O(k) query & insertion complexity where k is number of hash functions
 * - Space complexity: O(m) bits (dramatically smaller than raw dictionary storage)
 * - 0% False Negatives guaranteed (if filter says "No", item is definitely clean)
 * - Measurable & tunable False Positive rate: p ≈ (1 - e^(-kn/m))^k
 * - Interactive bit-array visualization for academic demonstration
 */

class BloomFilter {
    /**
     * @param {number} size Number of bits (m)
     * @param {number} hashCount Number of independent hash functions (k)
     */
    constructor(size = 128, hashCount = 3) {
        this.size = size;
        this.hashCount = hashCount;
        this.bitArray = new Uint8Array(this.size); // 0 or 1 for each bit
        this.insertedElements = new Set();
        this.initBreachedSignatures();
    }

    /**
     * Hash Function 1: FNV-1a (Fowler-Noll-Vo) 32-bit hash
     */
    hash1(str) {
        let hash = 2166136261;
        for (let i = 0; i < str.length; i++) {
            hash ^= str.charCodeAt(i);
            hash = Math.imul(hash, 16777619);
        }
        return Math.abs(hash % this.size);
    }

    /**
     * Hash Function 2: DJB2 (Daniel J. Bernstein) hash
     */
    hash2(str) {
        let hash = 5381;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) + hash) + str.charCodeAt(i);
            hash = hash & hash; // Convert to 32bit integer
        }
        return Math.abs(hash % this.size);
    }

    /**
     * Hash Function 3: SDBM hash
     */
    hash3(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = str.charCodeAt(i) + (hash << 6) + (hash << 16) - hash;
        }
        return Math.abs(hash % this.size);
    }

    /**
     * Generates k distinct bit positions using double-hashing technique:
     * gi(x) = (h1(x) + i * h2(x) + i^2 * h3(x)) % m
     */
    getBitIndices(str) {
        const s = str.toLowerCase();
        const h1 = this.hash1(s);
        const h2 = this.hash2(s);
        const h3 = this.hash3(s);

        const indices = [];
        for (let i = 0; i < this.hashCount; i++) {
            const index = Math.abs((h1 + i * h2 + i * i * h3) % this.size);
            indices.push(index);
        }
        return {
            indices,
            rawHashes: [h1, h2, h3]
        };
    }

    /**
     * Add element to Bloom Filter - O(k) complexity
     */
    add(str) {
        if (!str) return [];
        const { indices } = this.getBitIndices(str);
        indices.forEach(idx => {
            this.bitArray[idx] = 1;
        });
        this.insertedElements.add(str.toLowerCase());
        return indices;
    }

    /**
     * Query element in Bloom Filter - O(k) complexity
     * @returns {object} { definitelyNotPresent: boolean, possiblyPresent: boolean, indices: Array<number> }
     */
    query(str) {
        if (!str) return { definitelyNotPresent: true, possiblyPresent: false, indices: [] };
        const { indices, rawHashes } = this.getBitIndices(str);
        
        let allBitsSet = true;
        const bitDetails = [];

        indices.forEach(idx => {
            const isSet = this.bitArray[idx] === 1;
            if (!isSet) allBitsSet = false;
            bitDetails.push({
                index: idx,
                isSet
            });
        });

        return {
            possiblyPresent: allBitsSet,
            definitelyNotPresent: !allBitsSet,
            indices,
            rawHashes,
            bitDetails,
            estimatedFalsePositiveRate: this.calculateFalsePositiveRate()
        };
    }

    /**
     * Theoretical False Positive Probability:
     * p ≈ (1 - e^(-k * n / m))^k
     */
    calculateFalsePositiveRate() {
        const n = this.insertedElements.size;
        const m = this.size;
        const k = this.hashCount;
        if (m === 0) return 1;
        const exponent = (-k * n) / m;
        const p = Math.pow(1 - Math.exp(exponent), k);
        return Math.max(0, Math.min(1, p));
    }

    /**
     * Returns current bit occupancy percentage
     */
    getBitOccupancy() {
        let setBits = 0;
        for (let i = 0; i < this.size; i++) {
            if (this.bitArray[i] === 1) setBits++;
        }
        return {
            setBits,
            totalBits: this.size,
            percentage: ((setBits / this.size) * 100).toFixed(1)
        };
    }

    /**
     * Preload high-risk breached signatures into Bloom Filter
     */
    initBreachedSignatures() {
        const breachedHashes = [
            'password', '123456', '123456789', 'admin', 'qwerty',
            'football', 'iloveyou', 'sunshine', 'princess', 'welcome',
            'dragon', 'master', 'monkey', 'starwars', 'baseball',
            'test1234', 'superman', 'root1234', 'hunter2', 'pass1234',
            'shadow', 'letmein', 'trustno1', 'secret12', 'charlie'
        ];

        breachedHashes.forEach(pwd => this.add(pwd));
    }
}

// Global exposure
if (typeof window !== 'undefined') {
    window.BloomFilter = BloomFilter;
}
