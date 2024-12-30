import { loadlibs } from './loadlibs.js';
import { handleCreate, handleGet } from './webauthn.js';
import { AuthManager } from './auth.js';

const auth = new AuthManager();

await loadlibs();

browser.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId === 0) {
        browser.scripting.executeScript({
            target: { tabId: details.tabId },
            files: ["content/webauthn.js"],
            injectImmediately: true,  // This replaces runAt: "document_start",
            world: "MAIN"
        });
    }
});

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.type) {
        case 'login':
            return auth.login(message.password).then((r) => (r));
        case 'logout':
            return auth.logout().then(r => r);
        case 'getLoginState':
            return auth.isLoggedIn().then(r => ({ isLoggedIn: r }));
        case 'create_credential':
            console.log("handling create");
            return handleCreate(message.options, message.hostname, auth)
                .then(response => ({ success: true, response: response }));
        case 'get_credential':
            console.log("handling get");
            return handleGet(message.options, message.hostname, auth)
                .then(response => ({ success: true, response: response }));
    }
});
