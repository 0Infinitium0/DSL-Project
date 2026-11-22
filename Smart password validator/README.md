# AUTHGUARD – Smart Login & Password Security System
> **College Project: Advanced Data Structures (ADS)**  
> **Topic:** Practical Application of Data Structures & Cryptographic Algorithms in Real-World Authentication & Cyber Defense

---

## 🛡️ Project Overview

**AUTHGUARD** is a modern, fully functional cybersecurity web application engineered to demonstrate how fundamental and advanced computer science data structures power real-world identity defense and authentication systems.

Modern identity systems handle millions of credential checks per second while defending against automated brute-force attacks, dictionary wordlist intrusions (e.g., RockYou datasets), and credential stuffing. Standard naive algorithms fail to meet real-time performance and security constraints. **AUTHGUARD** implements and visualizes the exact data structures and algorithms that solve these challenges:

1. **Tries (Prefix Trees)**: For $O(L)$ instant detection of breached passwords and dictionary substrings.
2. **Bloom Filters**: Space-efficient probabilistic set membership with $O(k)$ query time and a guaranteed **0% False Negative Rate**.
3. **Cryptographically Salted Hash Tables (SHA-256)**: Constant-time $O(1)$ authentication with proof of the **Avalanche Effect** (diffusion).
4. **Sliding Window Queues**: For $O(1)$ amortized rate limiting against brute-force attacks.
5. **Information Entropy ($E = L \cdot \log_2 R$)**: Measuring passwords against exponential brute-force crack complexity $O(R^L)$.

---

## 🚀 Key Features

### 1. High-Performance Cybersecurity SaaS Design
- **Theme:** Midnight Navy (`#060814`) with glassmorphism backdrops (`backdrop-filter: blur(16px)`).
- **Accents:** Neon Electric Blue, Cyber Cyan, Neon Purple, and Threat Alert Crimsons.
- **Visuals:** Interactive HTML5 Cyber Particle Mesh reacting to cursor movements, glowing telemetry badges, and live audit telemetry.
- **Responsive:** Fluid layouts for Desktop (1440px+), Laptop (1024px), Tablet (768px), and Mobile (480px).

### 2. Password Strength & Entropy Analyzer
- Real-time **Information Entropy calculation** in bits ($E = L \cdot \log_2 R$).
- 5-Tier dynamic security meter: *Very Weak*, *Weak*, *Medium*, *Strong*, *Very Strong*, plus a dedicated *Compromised (Breached)* alert.
- Real-time cryptographic checklist:
  - Minimum 8 characters (12+ recommended for 80+ bits entropy).
  - Uppercase letters ($+26$ pool).
  - Lowercase letters ($+26$ pool).
  - Numerical digits ($+10$ pool).
  - Special ASCII characters ($+33$ pool).
  - **ADS Trie Check**: Queries the embedded breached dictionary in $O(L)$ time.
- Actionable recommendations tailored to the detected structural weaknesses.
- Brute-force crack time estimator showing computational complexity against modern GPU clusters ($10^{11}$ hashes/sec).

### 3. Cryptographically Secure Password Generator
- Built using the browser's **Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)** via `window.crypto.getRandomValues`.
- Custom length slider (8 to 32 characters).
- Toggles for Uppercase, Lowercase, Numbers, Symbols, and Ambiguous character exclusion (`l`, `1`, `I`, `0`, `O`).
- Cryptographic **Fisher-Yates shuffle algorithm** ensuring uniform distribution without bias.
- One-click copy with animated toast notifications.

### 4. Secure Login & Registration Simulator
- **Zero Plaintext Storage:** Passwords are never stored raw. Every registered account receives a 16-byte cryptographically random hex salt.
- **SHA-256 Cryptographic Hashing:** Computes `SHA256(password + salt)` locally via the Web Crypto API (with synchronous JS fallback).
- **Local Sandbox Persistence:** Stored safely in `localStorage` with zero external network transmission.
- **Sliding-Window Rate Limiting:** Enforces request quotas within a 30-second rolling queue to stop automated bot scripts.
- **Account Lockout State Machine:**
  - Tracks failed login attempts per account.
  - Automatically quarantines accounts after **5 consecutive failed attempts**.
  - 60-second cooldown lock with live second-by-second countdown timer.
  - Resets attempt counter to 0 immediately upon verified password digest match.
- **Active User Session State:**
  - Displays authenticated user profile, session token, SHA-256 hash snippet, and salt snippet.
  - Simulated **Two-Factor Authentication (2FA / TOTP)** code generator.

### 5. Security Operations Center (Dashboard)
- Real-time KPI Metric Cards:
  - Total Registered Demo Users
  - Successful Logins
  - Failed Login Attempts
  - Currently Locked Accounts
  - Fleet Average Password Entropy
- **Interactive Chart.js Visualizations:**
  - Password Strength Distribution (Doughnut Chart)
  - Security Event Trends (Bar Chart)
- **Interactive Forensic Audit Trail:**
  - Searchable by username, IP address, status, or details.
  - Filterable by event status (`ALL`, `SUCCESS`, `FAILED`, `LOCKED`, `REGISTERED`).
  - Pre-seeded with realistic audit history for immediate evaluation.
  - Includes timestamp, simulated IP, client device, glowing status badge, and hash snippet.
- **Simulation Controls:**
  - *Simulate Brute Force Attack:* Launches an automated dictionary attack against `demo_user` to demonstrate account quarantine in real time.
  - *Unlock All:* Administrative security override for presentation convenience.
  - *Inject Network Traffic:* Generates realistic external anomalies.
  - *Export JSON Report:* Downloads a complete structured forensic security report.
  - *Reset DB:* Restores the system to pristine educational defaults.

### 6. Interactive ADS Architecture Laboratory ("About ADS")
- **Trie (Prefix Tree) Visualizer:**
  - Trace any word hop-by-hop ($O(L)$ traversal).
  - Displays interactive SVG prefix branch.
  - Visualizes why searching a Trie takes only $L$ hops regardless of dictionary size.
- **Bloom Filter Laboratory:**
  - Interactive 128-bit memory register showing individual bit indices.
  - Demonstrates 3 independent hash functions (FNV-1a, DJB2, SDBM) mapping strings to bit cells.
  - Proves the mathematical guarantee: **0% False Negatives**.
  - Calculates theoretical False Positive probabilities ($p \approx (1 - e^{-kn/m})^k$).
- **Cryptographic Avalanche Effect Demo:**
  - Side-by-side comparison of two strings with a 1-character difference (e.g. `Passguard2026` vs `Passguard2027`).
  - Live 256-bit binary diffusion matrix with inverted bits highlighted.
  - Measures Hamming distance and proves that ~50% of hash bits flip on any input change.
- **Algorithmic Complexity Benchmark Table:**
  - Detailed comparison of Trie, Bloom Filter, Hash Table, Sliding Window Queue, Linear Search, and Brute Force Key Space.

---

## 🧠 Advanced Data Structures Deep-Dive

### 1. Trie (Prefix Tree)
```
                  [ROOT]
                /   |   \
              'a'  'p'  '1'
              /     |     \
            'd'    'a'    '2'
            /       |       \
          'm'      's'      '3'
          /         |         \
        'i'        's'        '4'
        /           |           \
      'n'          'w'          '5'
   (BREACH)         |             \
                   'o'            '6'
                    |          (BREACH)
                   'r'
                    |
                   'd'
                (BREACH)
```
- **Time Complexity:**
  - Search: $\mathcal{O}(L)$
  - Insertion: $\mathcal{O}(L)$
  - Prefix Match: $\mathcal{O}(P)$
- **Why it matters:** In breach detection (e.g. HaveIBeenPwned with 1+ billion compromised passwords), checking whether an 8-character password exists using linear search on an array requires up to $10,000,000 \times 8$ character comparisons ($\mathcal{O}(N \cdot L)$). With a Trie, lookup terminates in exactly **8 operations** ($\mathcal{O}(L)$), providing a **$1,000,000\times$ speedup**.

---

### 2. Bloom Filter (Probabilistic Set Membership)
```
String: "password"
   ├── Hash 1: FNV-1a(str) % 128 ──> Bit 42  [Set to 1]
   ├── Hash 2: DJB2(str)   % 128 ──> Bit 87  [Set to 1]
   └── Hash 3: SDBM(str)   % 128 ──> Bit 104 [Set to 1]

Bit Register:
[0][0]...[1]...[1]...[1]...[0][0]
          ^      ^     ^
         #42    #87   #104
```
- **Properties:**
  - Size: $m = 128$ bits
  - Hash count: $k = 3$ independent hash functions
  - Time Complexity: $\mathcal{O}(k)$ (constant time lookup)
  - Space Complexity: $\mathcal{O}(m)$ bits (orders of magnitude smaller than string storage)
- **Mathematical Formula for False Positive Rate:**
  $$p \approx \left(1 - e^{-\frac{k \cdot n}{m}}\right)^k$$
- **Core Guarantee:** If any of the $k$ bits is `0`, the element is **guaranteed 100% NOT in the set**. Zero False Negatives.

---

### 3. Cryptographic Salting & Hash Tables (SHA-256)
- **One-Way Trapdoor Function:**
  $$\text{Hash} = \mathcal{H}(\text{Password} \parallel \text{Salt})$$
- **Strict Avalanche Criterion (SAC):** A function satisfies SAC if, whenever a single input bit is complemented, each of the output bits changes with a probability of 50%.
- **Rainbow Table Defense:** Precomputed rainbow tables rely on fixed mappings $\mathcal{H}(P) \to H$. By prepending a 16-byte random salt $S_i$, the attacker must compute a distinct $2^{128}$ rainbow table for *every individual user*, making precomputation infeasible.

---

### 4. Sliding Window Rate Limiting (Queue / Deque)
- **Model:** A rolling timestamp queue $[t_1, t_2, \dots, t_n]$ maintained per IP address.
- **Eviction Rule:** While $t_{\text{current}} - t_{\text{head}} > \Delta T$, dequeue $t_{\text{head}}$.
- **Complexity:** Amortized $\mathcal{O}(1)$ time per authentication request.
- **Threshold:** Maximum 10 requests per 30-second window.

---

### 5. Information Entropy & Brute Force Complexity
- **Hartley-Shannon Information Entropy:**
  $$E = L \cdot \log_2(R)$$
  Where $L$ is password length, and $R$ is character set cardinality:
  - Lowercase only: $R = 26$
  - Alphanumeric: $R = 26 + 26 + 10 = 62$
  - Full printable ASCII: $R = 95$
- **Brute Force Key Space:**
  $$\text{Key Space} = R^L = 2^E$$
- **Computational Work Factor:**
  $$\text{Time to Crack} = \frac{2^{E-1}}{\text{Guesses per Second}}$$
  Assuming an attacker GPU cluster computing $10^{11}$ (100 Billion) hashes/sec:
  - 6-character lowercase ($E \approx 28$ bits): $< 1.3$ milliseconds.
  - 16-character complex ($E \approx 105$ bits): $> 10^{13}$ years.

---

## 📂 Project Directory Structure

```
c:\Users\balbi\OneDrive\Desktop\Smart password validator\
├── index.html                   # Complete semantic SPA layout and all view panels
├── README.md                    # Academic ADS report & documentation
├── css/
│   └── style.css                # Cybersecurity design system, glassmorphism, animations
├── js/
│   ├── app.js                   # Application bootstrap, routing, toast & particle canvas
│   ├── ads/
│   │   ├── trie.js              # Trie data structure & breached dictionary detection
│   │   ├── bloomFilter.js       # Bloom filter, bit array, & 3 hashing functions
│   │   └── cryptoUtils.js       # SHA-256 Web Crypto, entropy math, CSPRNG generator
│   ├── services/
│   │   └── authService.js       # Local auth engine, salting, sliding-window rate limit, audit log
│   └── components/
│       ├── checker.js           # Password strength testing UI & generator controller
│       ├── login.js             # Sign in/register simulator & lockout countdown controller
│       ├── dashboard.js         # Security analytics, Chart.js graphs, & forensic audit table
│       └── adsLab.js            # Interactive Trie, Bloom filter, & Avalanche visualizers
```

---

## 🧪 Demo Credentials (Pre-Seeded)

The simulator comes pre-loaded with sample accounts so evaluators and instructors can test immediately:

| Username | Password | Role / Complexity | Initial State |
| :--- | :--- | :--- | :--- |
| `admin_sec` | `Admin@Secure2026!` | SecOps Admin (Very Strong, 86 bits) | Active (0 failed attempts) |
| `student_ads` | `Student#ADS404!` | Academic Demo (Strong, 78 bits) | Active (0 failed attempts) |
| `demo_user` | `Pass@12345` | Test User (Medium, 52 bits) | Pre-loaded with 3/5 failed attempts |

---

## 💻 How to Run the Website

1. **Direct Browser Execution (No server required):**
   - Simply double-click `index.html` or drag it into any modern web browser (Google Chrome, Microsoft Edge, Mozilla Firefox, Brave, Safari).
   - The application is 100% self-contained with CDN dependencies for icons and charts, and graceful offline fallbacks.

2. **Local HTTP Server (Optional):**
   - If you prefer running via a local server:
     ```bash
     # Using Python:
     python -m http.server 8000
     # Or using Node.js:
     npx serve .
     ```
   - Then open `http://localhost:8000` in your browser.

---

## 🎓 Academic Submission Details
- **Subject:** Advanced Data Structures (ADS)
- **Project Title:** AUTHGUARD – Smart Login & Password Security System
- **Technologies Used:** HTML5, CSS3 (Modern Glassmorphism & Cyber Theme), Vanilla ES6+ JavaScript, Web Crypto API, Chart.js, FontAwesome.
- **Algorithms Implemented:**
  - Prefix Tree (Trie) Search & Substring Matching ($\mathcal{O}(L)$)
  - Bloom Filter k-Hash Bit-Array Mapping ($\mathcal{O}(k)$)
  - Cryptographic Salted SHA-256 One-Way Hashing ($\mathcal{O}(1)$)
  - Sliding Window Queue Rate Limiter ($\mathcal{O}(1)$ amortized)
  - Hartley-Shannon Information Entropy Analysis ($E = L \cdot \log_2 R$)
  - Fisher-Yates CSPRNG Uniform Shuffling
