/**
 * AUTHGUARD - Advanced Data Structures (ADS)
 * Security Dashboard & Analytics Component
 * 
 * Features:
 * - Dynamic KPI metric cards with neon glows
 * - Chart.js visualizations for Password Distribution and Security Events
 * - Real-time audit log viewer with live search and filter
 * - Automated brute-force attack simulator demonstrating lockout mechanics
 * - JSON forensic report export
 */

class DashboardComponent {
    constructor() {
        this.strengthChart = null;
        this.activityChart = null;
        this.initElements();
        this.initCharts();
        this.refresh();
    }

    initElements() {
        // KPI metric containers
        this.kpiTotalUsers = document.getElementById('dash-total-users');
        this.kpiSuccessLogins = document.getElementById('dash-success-logins');
        this.kpiFailedLogins = document.getElementById('dash-failed-logins');
        this.kpiLockedAccounts = document.getElementById('dash-locked-accounts');
        this.kpiAvgEntropy = document.getElementById('dash-avg-entropy');

        // Logs table
        this.logsTableBody = document.getElementById('dash-logs-tbody');
        this.searchInput = document.getElementById('dash-search-logs');
        this.statusFilter = document.getElementById('dash-filter-status');

        // Action buttons
        this.btnSimulateBruteForce = document.getElementById('dash-btn-bruteforce');
        this.btnUnlockAccounts = document.getElementById('dash-btn-unlock');
        this.btnSeedData = document.getElementById('dash-btn-seed');
        this.btnExport = document.getElementById('dash-btn-export');
        this.btnReset = document.getElementById('dash-btn-reset');

        if (this.searchInput) {
            this.searchInput.addEventListener('input', () => this.renderLogs());
        }

        if (this.statusFilter) {
            this.statusFilter.addEventListener('change', () => this.renderLogs());
        }

        if (this.btnSimulateBruteForce) {
            this.btnSimulateBruteForce.addEventListener('click', () => this.runBruteForceSimulation());
        }

        if (this.btnUnlockAccounts) {
            this.btnUnlockAccounts.addEventListener('click', () => {
                const users = window.authService.getUsers();
                let unlockedCount = 0;
                Object.values(users).forEach(u => {
                    if (u.isLocked) {
                        window.authService.unlockAccount(u.username);
                        unlockedCount++;
                    }
                });
                window.app.showToast(`Unlocked ${unlockedCount} account(s) via security override.`, 'success');
                this.refresh();
            });
        }

        if (this.btnSeedData) {
            this.btnSeedData.addEventListener('click', () => {
                this.injectSimulatedTraffic();
            });
        }

        if (this.btnExport) {
            this.btnExport.addEventListener('click', () => {
                this.exportAuditReport();
            });
        }

        if (this.btnReset) {
            this.btnReset.addEventListener('click', async () => {
                if (confirm('Reset demo database to original state?')) {
                    await window.authService.resetToDefaults();
                    window.app.showToast('Database reset to clean educational baseline.', 'info');
                    this.refresh();
                    if (window.loginComponent) window.loginComponent.updateSessionBanner();
                }
            });
        }
    }

    refresh() {
        this.renderMetrics();
        this.updateCharts();
        this.renderLogs();
    }

    renderMetrics() {
        const metrics = window.authService.getMetrics();

        if (this.kpiTotalUsers) this.kpiTotalUsers.textContent = metrics.totalUsers;
        if (this.kpiSuccessLogins) this.kpiSuccessLogins.textContent = metrics.successLogins;
        if (this.kpiFailedLogins) this.kpiFailedLogins.textContent = metrics.failedLogins;
        if (this.kpiLockedAccounts) this.kpiLockedAccounts.textContent = metrics.lockedCount;
        if (this.kpiAvgEntropy) this.kpiAvgEntropy.textContent = `${metrics.avgEntropy} bits`;
    }

    initCharts() {
        if (typeof Chart === 'undefined') {
            console.warn('Chart.js not yet loaded, will retry on demand');
            return;
        }

        // Configure Chart.js dark cyber defaults
        Chart.defaults.color = '#94a3b8';
        Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.08)';
        Chart.defaults.font.family = "'Inter', sans-serif";

        const canvasStrength = document.getElementById('chart-strength-dist');
        if (canvasStrength) {
            const ctx = canvasStrength.getContext('2d');
            this.strengthChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong'],
                    datasets: [{
                        data: [0, 0, 1, 2, 1],
                        backgroundColor: [
                            '#ef4444', // Red
                            '#f97316', // Orange
                            '#eab308', // Yellow
                            '#06b6d4', // Cyan
                            '#10b981'  // Emerald
                        ],
                        borderWidth: 2,
                        borderColor: '#060814',
                        hoverOffset: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                boxWidth: 12,
                                padding: 15,
                                color: '#cbd5e1'
                            }
                        },
                        tooltip: {
                            backgroundColor: '#0f172a',
                            borderColor: '#38bdf8',
                            borderWidth: 1,
                            padding: 10,
                            bodyFont: { size: 13 }
                        }
                    },
                    cutout: '68%'
                }
            });
        }

        const canvasActivity = document.getElementById('chart-activity-trends');
        if (canvasActivity) {
            const ctx = canvasActivity.getContext('2d');
            this.activityChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ['Successful', 'Failed Attempts', 'Locked Out', 'Registered'],
                    datasets: [{
                        label: 'Event Count',
                        data: [3, 4, 1, 4],
                        backgroundColor: [
                            'rgba(16, 185, 129, 0.8)', // Green
                            'rgba(239, 68, 68, 0.8)',   // Red
                            'rgba(249, 115, 22, 0.8)',  // Orange
                            'rgba(59, 130, 246, 0.8)'   // Blue
                        ],
                        borderColor: [
                            '#10b981',
                            '#ef4444',
                            '#f97316',
                            '#3b82f6'
                        ],
                        borderWidth: 1.5,
                        borderRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { precision: 0, color: '#94a3b8' },
                            grid: { color: 'rgba(255, 255, 255, 0.05)' }
                        },
                        x: {
                            ticks: { color: '#cbd5e1' },
                            grid: { display: false }
                        }
                    },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: '#0f172a',
                            borderColor: '#a855f7',
                            borderWidth: 1
                        }
                    }
                }
            });
        }
    }

    updateCharts() {
        if (!this.strengthChart && !this.activityChart && typeof Chart !== 'undefined') {
            this.initCharts();
        }

        const metrics = window.authService.getMetrics();

        if (this.strengthChart) {
            this.strengthChart.data.datasets[0].data = [
                metrics.tierDist['Very Weak'] || 0,
                metrics.tierDist['Weak'] || 0,
                metrics.tierDist['Medium'] || 0,
                metrics.tierDist['Strong'] || 0,
                metrics.tierDist['Very Strong'] || 0
            ];
            this.strengthChart.update();
        }

        if (this.activityChart) {
            this.activityChart.data.datasets[0].data = [
                metrics.successLogins,
                metrics.failedLogins,
                metrics.lockedEvents,
                metrics.totalUsers
            ];
            this.activityChart.update();
        }
    }

    renderLogs() {
        if (!this.logsTableBody) return;

        const logs = window.authService.getLogs();
        const searchQuery = (this.searchInput ? this.searchInput.value : '').toLowerCase().trim();
        const filterStatus = (this.statusFilter ? this.statusFilter.value : 'ALL');

        const filtered = logs.filter(log => {
            if (filterStatus !== 'ALL' && log.status !== filterStatus) return false;
            if (!searchQuery) return true;
            return (
                log.username.toLowerCase().includes(searchQuery) ||
                log.ip.toLowerCase().includes(searchQuery) ||
                log.details.toLowerCase().includes(searchQuery) ||
                log.status.toLowerCase().includes(searchQuery)
            );
        });

        if (filtered.length === 0) {
            this.logsTableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center py-6 text-slate-500">
                        <i class="fa-solid fa-inbox text-2xl mb-2"></i>
                        <p>No audit trail records matched the current criteria.</p>
                    </td>
                </tr>
            `;
            return;
        }

        const statusBadges = {
            'SUCCESS': '<span class="status-badge badge-success"><i class="fa-solid fa-check"></i> SUCCESS</span>',
            'FAILED': '<span class="status-badge badge-danger"><i class="fa-solid fa-xmark"></i> FAILED</span>',
            'LOCKED': '<span class="status-badge badge-warning"><i class="fa-solid fa-lock"></i> LOCKED</span>',
            'REGISTERED': '<span class="status-badge badge-info"><i class="fa-solid fa-user-plus"></i> REGISTERED</span>',
            'UNLOCKED': '<span class="status-badge badge-cyan"><i class="fa-solid fa-lock-open"></i> UNLOCKED</span>',
            'RATE_LIMITED': '<span class="status-badge badge-purple"><i class="fa-solid fa-gauge-high"></i> RATE LIMITED</span>',
            'LOGOUT': '<span class="status-badge badge-secondary"><i class="fa-solid fa-right-from-bracket"></i> LOGOUT</span>'
        };

        this.logsTableBody.innerHTML = filtered.map(log => {
            const date = new Date(log.timestamp);
            const timeFormatted = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
            const dateFormatted = date.toLocaleDateString([], { month: 'short', day: 'numeric' });

            const badge = statusBadges[log.status] || `<span class="status-badge badge-secondary">${log.status}</span>`;

            return `
                <tr class="log-row">
                    <td class="whitespace-nowrap font-mono text-xs text-slate-400">
                        ${dateFormatted} ${timeFormatted}
                    </td>
                    <td class="font-semibold text-slate-200">
                        <span class="user-pill"><i class="fa-solid fa-user text-xs"></i> ${log.username}</span>
                    </td>
                    <td class="font-mono text-xs text-cyan-400">
                        ${log.ip}
                    </td>
                    <td>
                        ${badge}
                    </td>
                    <td class="text-xs text-slate-300 max-w-xs truncate" title="${log.details}">
                        ${log.details}
                    </td>
                    <td class="font-mono text-xs text-slate-500">
                        <code>${log.hashSnippet || 'N/A'}</code>
                    </td>
                </tr>
            `;
        }).join('');
    }

    async runBruteForceSimulation() {
        if (!this.btnSimulateBruteForce) return;
        this.btnSimulateBruteForce.disabled = true;
        this.btnSimulateBruteForce.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Attacking...';

        window.app.showToast('Initiating automated dictionary brute-force attack on "demo_user"...', 'warning');

        await window.authService.simulateBruteForce('demo_user', (attempt, total, res) => {
            this.refresh();
            if (res.isLocked) {
                window.app.showToast(`ATTACK DEFENDED! Account "demo_user" was quarantined and LOCKED after 5 attempts!`, 'error');
            }
        });

        this.btnSimulateBruteForce.disabled = false;
        this.btnSimulateBruteForce.innerHTML = '<i class="fa-solid fa-skull-crossbones"></i> Simulate Brute Force';
        this.refresh();
    }

    injectSimulatedTraffic() {
        const ips = ['198.51.100.24', '203.0.113.88', '192.168.1.55', '172.16.0.4', '10.8.0.12'];
        const targets = ['admin_sec', 'student_ads', 'root_super', 'guest'];
        const randomIp = ips[Math.floor(Math.random() * ips.length)];
        const randomTarget = targets[Math.floor(Math.random() * targets.length)];

        window.authService.logEvent(
            randomTarget,
            randomIp,
            'FAILED',
            `Credential stuffing simulation detected via IP anomaly analysis.`
        );

        window.app.showToast(`Injected external security event from ${randomIp}`, 'info');
        this.refresh();
    }

    exportAuditReport() {
        const logs = window.authService.getLogs();
        const users = window.authService.getUsers();
        const metrics = window.authService.getMetrics();

        const report = {
            system: 'AUTHGUARD Smart Login & Security Engine',
            subject: 'Advanced Data Structures (ADS) Term Project',
            exportTimestamp: new Date().toISOString(),
            dataStructuresApplied: [
                'Trie (Prefix Tree) for O(L) breached dictionary detection',
                'Bloom Filter for O(k) probabilistic credential matching',
                'Hash Tables with SHA-256 + Salt for O(1) secure authentication',
                'Sliding Window Queue for O(1) rate limiting & brute-force defense'
            ],
            metricsSummary: metrics,
            registeredAccountsCount: Object.keys(users).length,
            auditTrail: logs
        };

        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `authguard_security_audit_${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        window.app.showToast('Security audit report exported to JSON!', 'success');
    }
}

// Global exposure
if (typeof window !== 'undefined') {
    window.DashboardComponent = DashboardComponent;
}
