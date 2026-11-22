# AUTHGUARD – ADS Project Viva Questions & Answers Cheat Sheet

---

### Q1: What is the primary objective of this project?
**Answer:** To demonstrate how **Advanced Data Structures (ADS)** and algorithms—specifically Tries, Bloom Filters, Cryptographic Hash Tables, and Sliding Window Queues—are used in real-world authentication to prevent dictionary attacks, credential stuffing, and brute force intrusions.

---

### Q2: Which Data Structures are implemented in AUTHGUARD?
**Answer:**
1. **Trie (Prefix Tree):** For $\mathcal{O}(L)$ detection of breached dictionary passwords and substrings.
2. **Bloom Filter:** A space-efficient bit-array using 3 hash functions for $\mathcal{O}(k)$ probabilistic breach screening.
3. **Hash Table (Salted SHA-256):** For $\mathcal{O}(1)$ secure password verification with rainbow table defense.
4. **Queue / Deque:** For $\mathcal{O}(1)$ amortized sliding-window rate limiting.

---

### Q3: Why use a Trie instead of an Array or List to check breached passwords?
**Answer:**
* **Array Search:** Takes $\mathcal{O}(N \cdot L)$ where $N$ is dictionary size (e.g., 10 million passwords).
* **Trie Search:** Takes $\mathcal{O}(L)$ where $L$ is only the length of the candidate password (e.g., 8–12 operations), completely independent of $N$. This is over $1,000,000\times$ faster.

---

### Q4: What is a Bloom Filter? Can it have False Negatives?
**Answer:**
* It is a space-efficient probabilistic data structure that tests set membership using $k$ hash functions over $m$ bits.
* **False Negatives:** **IMPOSSIBLE (0%)**. If any hashed bit is `0`, the item is definitively NOT in the set.
* **False Positives:** Possible ($p \approx (1 - e^{-kn/m})^k$), meaning an item might be flagged as breached even if it isn't, which can then be verified via the Trie or Hash Table.

---

### Q5: Why is password salting necessary if we already use SHA-256?
**Answer:**
Hashing alone ($\mathcal{H}(P)$) is vulnerable to **Rainbow Table attacks** (precomputed hash lookups). A unique 16-byte random salt $S$ ensures $\mathcal{H}(P \parallel S)$ is unique per user, forcing attackers to compute a separate $2^{128}$ table for every single account.

---

### Q6: What is the "Avalanche Effect" in cryptographic hashing?
**Answer:**
A property where changing a single character or bit in the input causes approximately **50% of the output hash bits to flip** unpredictably (Strict Avalanche Criterion). This prevents attackers from guessing passwords through incremental statistical analysis.

---

### Q7: How does the Sliding Window Rate Limiting algorithm work?
**Answer:**
It uses a **Queue of timestamps** for each IP address. When a request arrives, expired timestamps older than 30 seconds are dequeued ($\mathcal{O}(1)$ amortized). If the queue length exceeds 10 requests within that window, further attempts are throttled.

---

### Q8: How is Password Entropy calculated and what does it represent?
**Answer:**
* **Formula:** $E = L \cdot \log_2(R)$ bits ($L$ = length, $R$ = character pool size).
* **Meaning:** It measures the randomness and unpredictability of the password.
* **Brute Force Key Space:** $\mathcal{O}(R^L)$ or $2^E$ combinations. An entropy $> 80$ bits takes millions of years to crack on high-end GPU clusters ($10^{11}\text{ hashes/sec}$).

---

### Q9: How does the account lockout mechanism function?
**Answer:**
Each user profile tracks `failedAttempts`. On 5 consecutive incorrect passwords, the account state switches to `isLocked = true` with a 60-second cooldown timestamp (`lockedUntil`). A correct login immediately resets `failedAttempts` to 0.

---

### Q10: Where and how are credentials stored in this demo?
**Answer:**
Credentials are stored client-side in the browser's `localStorage` as `{ username, salt, passwordHash }`. Plaintext passwords are never stored or transmitted over any network, strictly following zero-knowledge local simulation principles.
