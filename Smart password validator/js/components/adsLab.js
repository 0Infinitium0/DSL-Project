/**
 * AUTHGUARD - Advanced Data Structures (ADS)
 * Interactive Laboratory Component
 * 
 * Demonstrations:
 * 1. Trie Prefix Tree Search Visualizer with O(L) traversal steps
 * 2. Bloom Filter bit-array & multi-hash bit mapping
 * 3. Cryptographic Avalanche Effect (SHA-256 diffusion matrix)
 * 4. Algorithmic Complexity Benchmarking
 */

class AdsLabComponent {
    constructor() {
        this.initTrieVisualizer();
        this.initBloomFilterVisualizer();
        this.initAvalancheVisualizer();
    }

    /* -------------------------------------------------------------
       1. TRIE INTERACTIVE VISUALIZER
       ------------------------------------------------------------- */
    initTrieVisualizer() {
        this.trieInput = document.getElementById('ads-trie-input');
        this.trieSearchBtn = document.getElementById('ads-trie-btn-search');
        this.trieInsertBtn = document.getElementById('ads-trie-btn-insert');
        this.trieStepsContainer = document.getElementById('ads-trie-steps');
        this.trieResultBox = document.getElementById('ads-trie-result');
        this.trieStatsWordCount = document.getElementById('ads-trie-word-count');
        this.trieStatsNodeCount = document.getElementById('ads-trie-node-count');
        this.trieCanvas = document.getElementById('ads-trie-canvas');

        if (this.trieSearchBtn) {
            this.trieSearchBtn.addEventListener('click', () => this.visualizeTrieSearch());
        }

        if (this.trieInsertBtn) {
            this.trieInsertBtn.addEventListener('click', () => {
                const word = (this.trieInput ? this.trieInput.value : '').trim();
                if (!word) return;
                window.appTrie.insert(word, 50000);
                window.app.showToast(`Inserted "${word}" into Trie!`, 'success');
                this.updateTrieStats();
                this.visualizeTrieSearch();
            });
        }

        if (this.trieInput) {
            this.trieInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') this.visualizeTrieSearch();
            });
            // Auto run with 'admin' initially
            setTimeout(() => {
                if (this.trieInput && !this.trieInput.value) {
                    this.trieInput.value = 'admin';
                    this.visualizeTrieSearch();
                }
            }, 300);
        }

        this.updateTrieStats();
    }

    updateTrieStats() {
        if (this.trieStatsWordCount && window.appTrie) {
            this.trieStatsWordCount.textContent = window.appTrie.wordCount.toLocaleString();
        }
        if (this.trieStatsNodeCount && window.appTrie) {
            this.trieStatsNodeCount.textContent = window.appTrie.nodeCount.toLocaleString();
        }
    }

    visualizeTrieSearch() {
        const query = (this.trieInput ? this.trieInput.value : '').trim();
        if (!query) return;

        const trace = window.appTrie.traceSearch(query);
        this.renderTrieSteps(query, trace);
        this.renderTrieSvgTree(query, trace);
    }

    renderTrieSteps(query, trace) {
        if (!this.trieStepsContainer) return;

        let stepsHtml = `
            <div class="trie-complexity-tag">
                <span class="badge-cyan">Traversal Complexity: O(L) = ${trace.steps.length - 1} character hops</span>
                <span class="text-xs text-slate-400">Word length L = ${query.length}</span>
            </div>
            <div class="trie-steps-flow">
        `;

        trace.steps.forEach((step, idx) => {
            const isRoot = step.status === 'root';
            const isMatched = step.status === 'matched';
            const isMiss = step.status === 'missed';

            const statusClass = isRoot ? 'step-root' : (isMatched ? 'step-matched' : 'step-missed');
            const icon = isRoot ? 'fa-network-wired' : (isMatched ? 'fa-check' : 'fa-xmark');

            stepsHtml += `
                <div class="trie-step-node ${statusClass}">
                    <div class="step-index">Step ${idx}</div>
                    <div class="step-char"><i class="fa-solid ${icon} text-xs mr-1"></i> '${step.char}'</div>
                    <div class="step-meta">
                        ${isRoot ? 'Trie Root' : (step.isEndOfWord ? '<span class="text-emerald-400 font-bold">[End of Word]</span>' : 'Intermediate Node')}
                    </div>
                </div>
            `;

            if (idx < trace.steps.length - 1) {
                stepsHtml += `<div class="trie-step-arrow"><i class="fa-solid fa-arrow-right"></i></div>`;
            }
        });

        stepsHtml += `</div>`;
        this.trieStepsContainer.innerHTML = stepsHtml;

        // Render result summary
        if (this.trieResultBox) {
            if (trace.found) {
                this.trieResultBox.className = 'trie-result-banner banner-found';
                this.trieResultBox.innerHTML = `
                    <div class="flex items-center gap-3">
                        <i class="fa-solid fa-triangle-exclamation text-2xl text-rose-400"></i>
                        <div>
                            <div class="font-bold text-rose-300">BREACHED WORD IDENTIFIED IN TRIE</div>
                            <div class="text-xs text-slate-300">
                                "${query}" exists in the leaked database with ${trace.leakCount.toLocaleString()} documented breaches.
                                Found in O(${query.length}) operations.
                            </div>
                        </div>
                    </div>
                `;
            } else {
                this.trieResultBox.className = 'trie-result-banner banner-clean';
                this.trieResultBox.innerHTML = `
                    <div class="flex items-center gap-3">
                        <i class="fa-solid fa-circle-check text-2xl text-emerald-400"></i>
                        <div>
                            <div class="font-bold text-emerald-300">NO EXACT TRIE MATCH DETECTED</div>
                            <div class="text-xs text-slate-300">
                                "${query}" was not found as a complete breached word in the default dictionary.
                                Search terminated in ${trace.steps.length - 1} character lookups.
                            </div>
                        </div>
                    </div>
                `;
            }
        }
    }

    renderTrieSvgTree(query, trace) {
        if (!this.trieCanvas) return;
        // Simple SVG prefix-branch visualizer
        const chars = query.split('');
        const width = 600;
        const height = 140;
        const startX = 60;
        const y = 70;
        const gap = Math.min(85, (width - 120) / Math.max(1, chars.length));

        let svgContent = `
            <svg viewBox="0 0 ${width} ${height}" class="w-full h-auto">
                <defs>
                    <linearGradient id="edgeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.7"/>
                        <stop offset="100%" stop-color="#a855f7" stop-opacity="0.9"/>
                    </linearGradient>
                </defs>
        `;

        // Draw Root Node
        svgContent += `
            <circle cx="${startX}" cy="${y}" r="22" fill="#0f172a" stroke="#38bdf8" stroke-width="2.5" />
            <text x="${startX}" y="${y + 5}" text-anchor="middle" fill="#38bdf8" font-size="11" font-weight="bold">ROOT</text>
        `;

        let curX = startX;
        chars.forEach((c, i) => {
            const nextX = curX + gap;
            const isLast = i === chars.length - 1;
            const isMatch = trace.found && isLast;

            // Edge
            svgContent += `
                <line x1="${curX + 22}" y1="${y}" x2="${nextX - 22}" y2="${y}" stroke="url(#edgeGrad)" stroke-width="2" />
            `;

            // Node
            const strokeColor = isMatch ? '#ef4444' : '#a855f7';
            const fillColor = isMatch ? 'rgba(239, 68, 68, 0.2)' : '#0f172a';
            const textColor = isMatch ? '#f87171' : '#c084fc';

            svgContent += `
                <circle cx="${nextX}" cy="${y}" r="20" fill="${fillColor}" stroke="${strokeColor}" stroke-width="2" />
                <text x="${nextX}" y="${y + 5}" text-anchor="middle" fill="${textColor}" font-size="14" font-family="monospace" font-weight="bold">${c}</text>
            `;

            if (isLast && trace.found) {
                svgContent += `
                    <text x="${nextX}" y="${y + 36}" text-anchor="middle" fill="#f87171" font-size="9" font-weight="bold">MATCH</text>
                `;
            }

            curX = nextX;
        });

        svgContent += `</svg>`;
        this.trieCanvas.innerHTML = svgContent;
    }

    /* -------------------------------------------------------------
       2. BLOOM FILTER VISUALIZER
       ------------------------------------------------------------- */
    initBloomFilterVisualizer() {
        this.bloomInput = document.getElementById('ads-bloom-input');
        this.bloomTestBtn = document.getElementById('ads-bloom-btn-test');
        this.bloomAddBtn = document.getElementById('ads-bloom-btn-add');
        this.bloomBitArrayGrid = document.getElementById('ads-bloom-grid');
        this.bloomHashesDisplay = document.getElementById('ads-bloom-hashes');
        this.bloomResultVerdict = document.getElementById('ads-bloom-verdict');
        this.bloomOccupancyText = document.getElementById('ads-bloom-occupancy');
        this.bloomFpText = document.getElementById('ads-bloom-fp-rate');

        if (this.bloomTestBtn) {
            this.bloomTestBtn.addEventListener('click', () => this.visualizeBloomQuery());
        }

        if (this.bloomAddBtn) {
            this.bloomAddBtn.addEventListener('click', () => {
                const word = (this.bloomInput ? this.bloomInput.value : '').trim();
                if (!word) return;
                window.appBloomFilter.add(word);
                window.app.showToast(`Inserted "${word}" into Bloom Filter! Bits updated.`, 'success');
                this.visualizeBloomQuery();
            });
        }

        if (this.bloomInput) {
            this.bloomInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') this.visualizeBloomQuery();
            });
            setTimeout(() => {
                if (this.bloomInput && !this.bloomInput.value) {
                    this.bloomInput.value = 'password';
                    this.visualizeBloomQuery();
                }
            }, 350);
        }

        this.renderBloomBitArray();
    }

    renderBloomBitArray(highlightIndices = []) {
        if (!this.bloomBitArrayGrid || !window.appBloomFilter) return;

        const bf = window.appBloomFilter;
        let cellsHtml = '';

        for (let i = 0; i < bf.size; i++) {
            const isSet = bf.bitArray[i] === 1;
            const isHighlighted = highlightIndices.includes(i);

            let cellClass = 'bloom-bit-cell';
            if (isSet) cellClass += ' bit-set';
            if (isHighlighted) cellClass += ' bit-highlight';

            cellsHtml += `
                <div class="${cellClass}" title="Bit ${i}: ${isSet ? '1 (Set)' : '0 (Empty)'}">
                    <span class="bit-index">${i}</span>
                    <span class="bit-val">${bf.bitArray[i]}</span>
                </div>
            `;
        }

        this.bloomBitArrayGrid.innerHTML = cellsHtml;

        const occ = bf.getBitOccupancy();
        if (this.bloomOccupancyText) {
            this.bloomOccupancyText.textContent = `${occ.setBits} / ${occ.totalBits} bits set (${occ.percentage}%)`;
        }

        const fpRate = (bf.calculateFalsePositiveRate() * 100).toFixed(2);
        if (this.bloomFpText) {
            this.bloomFpText.textContent = `${fpRate}%`;
        }
    }

    visualizeBloomQuery() {
        const query = (this.bloomInput ? this.bloomInput.value : '').trim();
        if (!query || !window.appBloomFilter) return;

        const result = window.appBloomFilter.query(query);
        this.renderBloomBitArray(result.indices);

        if (this.bloomHashesDisplay) {
            this.bloomHashesDisplay.innerHTML = `
                <div class="hash-result-pill">
                    <span class="label">h1 (FNV-1a)</span>
                    <span class="raw">0x${result.rawHashes[0].toString(16)}</span>
                    <span class="arrow">→</span>
                    <span class="index">Bit [${result.indices[0]}]</span>
                </div>
                <div class="hash-result-pill">
                    <span class="label">h2 (DJB2)</span>
                    <span class="raw">0x${result.rawHashes[1].toString(16)}</span>
                    <span class="arrow">→</span>
                    <span class="index">Bit [${result.indices[1]}]</span>
                </div>
                <div class="hash-result-pill">
                    <span class="label">h3 (SDBM)</span>
                    <span class="raw">0x${result.rawHashes[2].toString(16)}</span>
                    <span class="arrow">→</span>
                    <span class="index">Bit [${result.indices[2]}]</span>
                </div>
            `;
        }

        if (this.bloomResultVerdict) {
            if (result.definitelyNotPresent) {
                this.bloomResultVerdict.className = 'bloom-verdict verdict-negative';
                this.bloomResultVerdict.innerHTML = `
                    <div class="verdict-title"><i class="fa-solid fa-circle-check"></i> 100% DEFINITELY NOT IN SET</div>
                    <div class="verdict-desc">
                        At least one hashed bit (${result.bitDetails.filter(b => !b.isSet).map(b => b.index).join(', ')}) was '0'.
                        ADS Theorem: A Bloom Filter guarantees ZERO FALSE NEGATIVES.
                    </div>
                `;
            } else {
                this.bloomResultVerdict.className = 'bloom-verdict verdict-positive';
                this.bloomResultVerdict.innerHTML = `
                    <div class="verdict-title"><i class="fa-solid fa-triangle-exclamation"></i> POSSIBLY IN SET (Probable Match)</div>
                    <div class="verdict-desc">
                        All 3 hashed bit indices [${result.indices.join(', ')}] evaluate to '1'.
                        Item is either in the dataset or a collision occurred (${(result.estimatedFalsePositiveRate * 100).toFixed(2)}% FP chance).
                    </div>
                `;
            }
        }
    }

    /* -------------------------------------------------------------
       3. AVALANCHE EFFECT VISUALIZER (SHA-256 DIFFUSION)
       ------------------------------------------------------------- */
    initAvalancheVisualizer() {
        this.inputA = document.getElementById('ads-avalanche-input-a');
        this.inputB = document.getElementById('ads-avalanche-input-b');
        this.btnCompare = document.getElementById('ads-avalanche-btn-compare');
        this.avalancheStatsPercent = document.getElementById('ads-avalanche-percent');
        this.avalancheStatsBits = document.getElementById('ads-avalanche-bits');
        this.avalancheHashA = document.getElementById('ads-avalanche-hash-a');
        this.avalancheHashB = document.getElementById('ads-avalanche-hash-b');
        this.avalancheMatrix = document.getElementById('ads-avalanche-matrix');

        if (this.btnCompare) {
            this.btnCompare.addEventListener('click', () => this.visualizeAvalanche());
        }

        if (this.inputA && this.inputB) {
            [this.inputA, this.inputB].forEach(input => {
                input.addEventListener('input', () => this.visualizeAvalanche());
            });
        }

        setTimeout(() => this.visualizeAvalanche(), 400);
    }

    async visualizeAvalanche() {
        const textA = (this.inputA ? this.inputA.value : 'Passguard2026') || 'Passguard2026';
        const textB = (this.inputB ? this.inputB.value : 'Passguard2027') || 'Passguard2027';

        const result = await CryptoUtils.measureAvalanche(textA, textB);

        if (this.avalancheStatsPercent) {
            this.avalancheStatsPercent.textContent = `${result.percentage}%`;
        }
        if (this.avalancheStatsBits) {
            this.avalancheStatsBits.textContent = `${result.flippedBits} / 256 bits`;
        }
        if (this.avalancheHashA) {
            this.avalancheHashA.textContent = result.hashA;
        }
        if (this.avalancheHashB) {
            this.avalancheHashB.textContent = result.hashB;
        }

        if (this.avalancheMatrix) {
            // Render 256 bit comparison matrix
            let cells = '';
            result.diffMap.forEach(d => {
                const cellClass = d.flipped ? 'bit-flipped' : 'bit-same';
                cells += `
                    <div class="avalanche-cell ${cellClass}" title="Bit ${d.index}: A=${d.bitA}, B=${d.bitB} (${d.flipped ? 'FLIPPED' : 'EQUAL'})">
                    </div>
                `;
            });
            this.avalancheMatrix.innerHTML = cells;
        }
    }
}

// Global exposure
if (typeof window !== 'undefined') {
    window.AdsLabComponent = AdsLabComponent;
}
