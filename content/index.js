let messenger = {
    createCredential(options) {
        console.log("received create request (messenger)");
        return new window.Promise((resolve, reject) => {
            const response = browser.runtime.sendMessage({
                type: 'create_credential',
                options: options,
                hostname: window.location.hostname
            });
            response.then((value) => resolve(cloneInto(value.response, window)));
            response.catch((error) => reject(cloneInto(error, window)));
        });
    },
    getCredential(options) {
        console.log("received get request (messenger)");
        return new window.Promise((resolve, reject) => {
            const response = browser.runtime.sendMessage({
                type: 'get_credential',
                options: options,
                hostname: window.location.hostname
            });
            response.then((value) => resolve(cloneInto(value.response, window)));
            response.catch((error) => reject(cloneInto(error, window)));
        });
    }
}


window.wrappedJSObject.messenger = cloneInto(messenger, window, {
    cloneFunctions: true,
});


console.log("content script loaded");