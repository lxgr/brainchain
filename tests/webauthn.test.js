// tests/fixtures.js
export const getMockWebAuthnOptions = (origin = 'example.com') => ({
    origin,
    options: {
        publicKey: {
            challenge: new Uint8Array([1, 2, 3, 4]),
            rp: {
                name: 'Example RP',
                id: origin,
            },
            user: {
                id: new Uint8Array([1]),
                name: 'test@example.com',
                displayName: 'Test User',
            },
            pubKeyCredParams: [{
                type: 'public-key',
                alg: -7 // ES256
            }],
            timeout: 60000,
            attestation: 'none'
        }
    }
});

export const MockAuth = {
    getPassphrase: () => 'test-passphrase'
};

// tests/webauthn.test.js
import { assert, assertEquals } from './test-runner.js';
import { handleCreate, newCredentialIdForRp, validateCredentialId } from '../background/webauthn.js';

export const webAuthnTests = {
    'WebAuthN Credential Creation': {
        'should create credentials with valid options': async () => {
            const mockWebAuthnOptions = getMockWebAuthnOptions();
            const result = await handleCreate(
                mockWebAuthnOptions.options,
                mockWebAuthnOptions.origin,
                MockAuth
            );
            
            assert(result.type === 'public-key', 'Credential type should be public-key');
            assert(result.rawId instanceof Uint8Array, 'rawId should be Uint8Array');
            assert(result.id, 'id should be present');
            assert(result.response.attestationObject, 'attestationObject should be present');
            assert(result.response.clientDataJSON, 'clientDataJSON should be present');
        },

        'should throw error when not logged in': async () => {
            const mockWebAuthnOptions = getMockWebAuthnOptions();
            const notLoggedInAuth = {
                getPassphrase: () => null
            };
            
            try {
                await handleCreate(
                    mockWebAuthnOptions.options,
                    mockWebAuthnOptions.origin,
                    notLoggedInAuth
                );
                throw new Error('Should have thrown error');
            } catch (error) {
                assertEquals(error.message, 'Not logged in');
            }
        },

        'different origins get different keys': async () => {
            const options1 = getMockWebAuthnOptions("example.com");
            const options2 = getMockWebAuthnOptions("example.net");
            const result1 = await handleCreate(
                options1.options,
                options1.origin,
                MockAuth
            );
            
            const result2 = await handleCreate(
                options2.options,
                options2.origin,
                MockAuth
            );
            
            assert(
                result1.rawId.some((byte, i) => byte !== result2.rawId[i]),
                'Credentials should be different for different origins!'
            );
        }
    },

    'create credentialID': {
        'should create non-nil credentialID': async () => {
            const rootSecret = new Uint8Array([1, 2, 3, 4]);
            const rpId = 'example.com';
            const credentialId = await newCredentialIdForRp(rootSecret, rpId);
            assert(credentialId, 'credentialId should be non-nil');
        },

        'credential IDs should be 64 byte long': async () => {
            const rootSecret = new Uint8Array([1, 2, 3, 4]);
            const rpId = 'example.com';
            const credentialId = await newCredentialIdForRp(rootSecret, rpId);
            assert(credentialId.length === 64, 'credentialId should be 64 bytes long');
        }
    },

    'validate credentialID': {
        'should validate correct credentialID': async () => {
            const rootSecret = new Uint8Array([1, 2, 3, 4]);
            const rpId = 'example.com';
            const credentialId = await newCredentialIdForRp(rootSecret, rpId);
            const isValid = await validateCredentialId(rootSecret, rpId, credentialId);
            assert(isValid, 'credentialId should be valid');
        },

        'should not validate incorrect credentialID': async () => {
            const rootSecret = new Uint8Array([1, 2, 3, 4]);
            const rpId = 'example.com';
            const credentialId = new Uint8Array([5, 6, 7, 8]); // Invalid credentialId
            const isValid = await validateCredentialId(rootSecret, rpId, credentialId);
            assert(!isValid, 'credentialId should be invalid');
        }
    }
};