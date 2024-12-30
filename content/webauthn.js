(function () {
  // Store the original navigator.credentials if it exists
  const originalCredentials = navigator.credentials;

  // Create our custom WebAuthn implementation
  class WebAuthnCredential {
    constructor(options) {
      this.id = options.id;
      this.type = 'public-key';
      this.rawId = options.rawId;
      this.response = options.response;
    }
  }

  const browserCredentials = {
    create: navigator.credentials.create.bind(
      navigator.credentials,
    ),
    get: navigator.credentials.get.bind(navigator.credentials),
  };

  navigator.credentials.create = function create(options) {
    console.log("credentials.create called (content)");
    delete options.signal;
    result = window.messenger.createCredential(options).then(res => {
      res.getClientExtensionResults = () => { return {} };
      return res;
    })
    return result;
  }

  navigator.credentials.get = function get(options) {
    console.log("credentials.get called (content)");
    delete options.signal;
    result = window.messenger.getCredential(options).then(res => {
      if (res) {
        res.getClientExtensionResults = () => { return {} };
      }
      return res
    })
    return result;
  }

  console.log("webauthn loaded");
})();