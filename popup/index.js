class AuthUI {
    constructor() {
        this.loginForm = document.getElementById('loginForm');
        this.logoutForm = document.getElementById('logoutForm');
        this.passwordInput = document.getElementById('passwordInput');
        this.loginButton = document.getElementById('loginButton');
        this.logoutButton = document.getElementById('logoutButton');
        
        this.setupEventListeners();
        this.checkInitialState();
    }

    async checkInitialState() {
        const response = await browser.runtime.sendMessage({ type: 'getLoginState' });
        this.updateUI(response.isLoggedIn);
    }

    setupEventListeners() {
        this.loginButton.addEventListener('click', () => this.handleLogin());
        this.logoutButton.addEventListener('click', () => this.handleLogout());
    }

    async handleLogin() {
        const password = this.passwordInput.value;
        if (!password) return;

        const response = await browser.runtime.sendMessage({
            type: 'login',
            password: password
        });

        if (response.success) {
            this.updateUI(true);
            this.passwordInput.value = '';
        }
    }

    async handleLogout() {
        const response = await browser.runtime.sendMessage({ type: 'logout' });
        if (response.success) {
            this.updateUI(false);
        }
    }

    updateUI(isLoggedIn) {
        this.loginForm.style.display = isLoggedIn ? 'none' : 'block';
        this.logoutForm.style.display = isLoggedIn ? 'block' : 'none';
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new AuthUI();
});