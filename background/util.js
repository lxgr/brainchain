export const utils = {
    numberToBEUint16: (number) => {
        const buffer = new ArrayBuffer(2);
        const view = new DataView(buffer);
        view.setUint16(0, number, false);
        return new Uint8Array(buffer);
    },

    numberToBEUint32: (number) => {
        const buffer = new ArrayBuffer(4);
        const view = new DataView(buffer);
        view.setUint32(0, number, false);
        return new Uint8Array(buffer);
    },

    b64UrlToU8: (str) => Uint8Array.fromBase64(str, { alphabet: "base64url" }),

    sha256: async(data) => {
        const input = typeof data === 'string' 
            ? new TextEncoder().encode(data)
            : data;
        return new Uint8Array(await crypto.subtle.digest('SHA-256', input));
    }
};
