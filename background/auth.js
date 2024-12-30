export class AuthManager {
    async login(password) {
        await this.setPassphrase(password);
        return { success: true };
    }

    async logout() {
        await browser.storage.session.remove("passphrase");
        return { success: true };
    }

    async isLoggedIn() {
        return await this.getPassphrase() !== null;
    }

    async getPassphrase() {
        const { passphrase = null } = await browser.storage.session.get("passphrase");
        return passphrase;
    }

    async setPassphrase(password) {
        await browser.storage.session.set({"passphrase": password, "isSecret": "duh, it's a secret"});
    }
}