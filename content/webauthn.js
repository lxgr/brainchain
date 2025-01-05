(function () {
  const originalCredentials = navigator.credentials;

  class WebAuthnCredential {
    constructor(options) {
      this.id = options.id;
      this.type = 'public-key';
      this.rawId = options.rawId;
      this.response = options.response;
    }
  }

  function addWebAuthnResponseProps(res) {
    if (res) {
      res.getClientExtensionResults = () => { return {} };
    }
    return res;
  }

  const browserCredentials = {
    create: navigator.credentials.create.bind(navigator.credentials),
    get: navigator.credentials.get.bind(navigator.credentials),
  };

  navigator.credentials.create = async function create(options) {
    console.log("credentials.create called (content)");
    try {
      return await browserCredentials.create(options);
    } catch (error) {
      if (error.name === 'AbortError') {
        console.log("Native WebAuthn aborted, falling back to Brainchain");
        return window.messenger.createCredential({ publicKey: options.publicKey })
          .then(addWebAuthnResponseProps);
      }
      throw error;
    }
  }

  navigator.credentials.get = async function get(options) {
    console.log("credentials.get called (content)");
    try {
      return await browserCredentials.get(options);
    } catch (error) {
      if (error.name === 'AbortError') {
        console.log("Native WebAuthn aborted, falling back to Brainchain");
        return window.messenger.getCredential({ publicKey: options.publicKey })
          .then(addWebAuthnResponseProps);
      }
      throw error;
    }
  }

  console.log("webauthn loaded");
})();