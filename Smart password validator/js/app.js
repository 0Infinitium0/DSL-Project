/**
 * AUTHGUARD – Smart Login & Password Security System
 * Main Application Orchestrator & UI Controller
 * 
 * College Project: Advanced Data Structures (ADS)
 */

class App {
    constructor() {
        this.currentView = 'home';
        this.initCanvasBackground();
        this.initNavigation();
        this.initToastSystem();
        this.initADSInstances();
    }

    /**
     * Initialize Global ADS Instances and Components
     */
    initADSInstances() {
        // 1. Data Structures
        window.appTrie = new Trie();
        window.appBloomFilter = new BloomFilter(128, 3);
        window.authService = new AuthService();

        // 2. UI Components
        window.checkerComponent = new PasswordCheckerComponent();
        window.loginComponent = new LoginComponent();
        window.dashboardComponent = new DashboardComponent();
        window.adsLabComponent = new AdsLabComponent();

        console.log('%c AUTHGUARD ADS Engine Initialized ', 'background: #0f172a; color: #38bdf8; font-weight: bold; border: 1px solid #38bdf8; padding: 4px 8px;');
    }

    /**
     * SPA View Routing & Tab Switching
     */
    initNavigation() {
        const navLinks = document.querySelectorAll('.nav-link');
        const views = document.querySelectorAll('.app-view');
        const mobileMenuBtn = document.getElementById('btn-mobile-menu');
        const mobileMenu = document.getElementById('mobile-nav-drawer');

        // Route handler
        const switchView = (targetViewId) => {
            const cleanId = (targetViewId || 'home').replace('#', '');
            const targetView = document.getElementById(`view-${cleanId}`);

            if (!targetView) return;

            views.forEach(v => {
                v.classList.remove('active');
                v.setAttribute('aria-hidden', 'true');
            });

            targetView.classList.add('active');
            targetView.setAttribute('aria-hidden', 'false');

            // Update nav link active classes
            navLinks.forEach(link => {
                const href = link.getAttribute('href');
                if (href === `#${cleanId}`) {
                    link.classList.add('active');
                } else {
                    link.classList.remove('active');
                }
            });

            this.currentView = cleanId;
            window.location.hash = `#${cleanId}`;

            // Close mobile menu if open
            if (mobileMenu && !mobileMenu.classList.contains('hidden')) {
                mobileMenu.classList.add('hidden');
            }

            // Scroll to top of view
            window.scrollTo({ top: 0, behavior: 'smooth' });

            // Trigger component refreshes when their view opens
            if (cleanId === 'dashboard' && window.dashboardComponent) {
                window.dashboardComponent.refresh();
            } else if (cleanId === 'ads' && window.adsLabComponent) {
                window.adsLabComponent.updateTrieStats();
            }
        };

        // Click handlers on links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', (e) => {
                const href = anchor.getAttribute('href');
                if (href && href.startsWith('#')) {
                    e.preventDefault();
                    switchView(href);
                }
            });
        });

        // Hash change event (back/forward browser buttons)
        window.addEventListener('hashchange', () => {
            const hash = window.location.hash || '#home';
            switchView(hash);
        });

        // Mobile drawer toggle
        if (mobileMenuBtn && mobileMenu) {
            mobileMenuBtn.addEventListener('click', () => {
                mobileMenu.classList.toggle('hidden');
            });
        }

        // Handle initial hash on page load
        const initialHash = window.location.hash || '#home';
        switchView(initialHash);
    }

    /**
     * Floating Toast Notification Center
     */
    initToastSystem() {
        this.toastContainer = document.getElementById('toast-container');
        if (!this.toastContainer) {
            this.toastContainer = document.createElement('div');
            this.toastContainer.id = 'toast-container';
            this.toastContainer.className = 'toast-container';
            document.body.appendChild(this.toastContainer);
        }
    }

    showToast(message, type = 'info', duration = 3500) {
        if (!this.toastContainer) return;

        const toast = document.createElement('div');
        toast.className = `toast-item toast-${type}`;

        const icons = {
            success: 'fa-circle-check',
            error: 'fa-circle-exclamation',
            warning: 'fa-triangle-exclamation',
            info: 'fa-circle-info'
        };

        toast.innerHTML = `
            <div class="toast-icon">
                <i class="fa-solid ${icons[type] || 'fa-bell'}"></i>
            </div>
            <div class="toast-content">
                <p class="toast-message">${message}</p>
            </div>
            <button class="toast-close" aria-label="Close Notification">&times;</button>
        `;

        toast.querySelector('.toast-close').addEventListener('click', () => {
            toast.classList.add('toast-fadeout');
            setTimeout(() => toast.remove(), 250);
        });

        this.toastContainer.appendChild(toast);

        // Auto remove
        setTimeout(() => {
            if (toast.parentElement) {
                toast.classList.add('toast-fadeout');
                setTimeout(() => toast.remove(), 250);
            }
        }, duration);
    }

    /**
     * Interactive Cyber Particle Canvas Background
     */
    initCanvasBackground() {
        const canvas = document.getElementById('cyber-particles-canvas');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        let width = canvas.width = window.innerWidth;
        let height = canvas.height = window.innerHeight;

        const particles = [];
        const particleCount = Math.min(65, Math.floor((width * height) / 18000));

        let mouse = { x: null, y: null, radius: 120 };

        window.addEventListener('mousemove', (e) => {
            mouse.x = e.x;
            mouse.y = e.y;
        });

        window.addEventListener('mouseout', () => {
            mouse.x = null;
            mouse.y = null;
        });

        window.addEventListener('resize', () => {
            width = canvas.width = window.innerWidth;
            height = canvas.height = window.innerHeight;
        });

        // Particle Class
        class Particle {
            constructor() {
                this.x = Math.random() * width;
                this.y = Math.random() * height;
                this.size = Math.random() * 2 + 1;
                this.baseX = this.x;
                this.baseY = this.y;
                this.speedX = (Math.random() - 0.5) * 0.7;
                this.speedY = (Math.random() - 0.5) * 0.7;
                this.color = Math.random() > 0.5 ? '#38bdf8' : (Math.random() > 0.5 ? '#a855f7' : '#06b6d4');
            }

            draw() {
                ctx.beginPath();
                ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
                ctx.fillStyle = this.color;
                ctx.shadowBlur = 8;
                ctx.shadowColor = this.color;
                ctx.fill();
            }

            update() {
                this.x += this.speedX;
                this.y += this.speedY;

                // Bounce off edges
                if (this.x < 0 || this.x > width) this.speedX *= -1;
                if (this.y < 0 || this.y > height) this.speedY *= -1;

                // Mouse interaction
                if (mouse.x != null && mouse.y != null) {
                    const dx = mouse.x - this.x;
                    const dy = mouse.y - this.y;
                    const distance = Math.sqrt(dx * dx + dy * dy);
                    if (distance < mouse.radius) {
                        const force = (mouse.radius - distance) / mouse.radius;
                        const directionX = (dx / distance) * force * 3;
                        const directionY = (dy / distance) * force * 3;
                        this.x -= directionX;
                        this.y -= directionY;
                    }
                }
            }
        }

        for (let i = 0; i < particleCount; i++) {
            particles.push(new Particle());
        }

        function connectParticles() {
            for (let a = 0; a < particles.length; a++) {
                for (let b = a + 1; b < particles.length; b++) {
                    const dx = particles[a].x - particles[b].x;
                    const dy = particles[a].y - particles[b].y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 130) {
                        const opacity = 1 - (dist / 130);
                        ctx.strokeStyle = `rgba(56, 189, 248, ${opacity * 0.22})`;
                        ctx.lineWidth = 0.8;
                        ctx.beginPath();
                        ctx.moveTo(particles[a].x, particles[a].y);
                        ctx.lineTo(particles[b].x, particles[b].y);
                        ctx.stroke();
                    }
                }
            }
        }

        function animate() {
            ctx.clearRect(0, 0, width, height);
            for (let i = 0; i < particles.length; i++) {
                particles[i].draw();
                particles[i].update();
            }
            connectParticles();
            requestAnimationFrame(animate);
        }

        animate();
    }
}

// Bootstrap once DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.app = new App();
});
