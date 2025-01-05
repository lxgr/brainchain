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

  function addWebAuthnResponseProps(res) {
    if (res) {
      res.getClientExtensionResults = () => { return {} };
    }
    return res;
  }

  const maybeFallBackToBrowserGet = (res, options) => 
    res === null ? browserCredentials.get(options) : res;

  navigator.credentials.create = function create(options) {
    console.log("credentials.create called (content)");
    return window.messenger.createCredential({ publicKey: options.publicKey })
      .then(addWebAuthnResponseProps);
  }

  navigator.credentials.get = function get(options) {
    console.log("credentials.get called (content)");
    return window.messenger.getCredential({ publicKey: options.publicKey })
      .then(addWebAuthnResponseProps).then(r => maybeFallBackToBrowserGet(r, options));
  }

  console.log("webauthn loaded");
})();