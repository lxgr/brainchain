export class ValidationError extends Error {
    constructor(message) {
        super(message);
        this.name = 'ValidationError';
    }
}

// Returns the effective rpId for the operation, validating it against the origin
export function validateRpId(rpId, origin) {
    try {
        const originUrl = new URL(origin);
        const effectiveDomain = originUrl.hostname;

        // If rpId is not provided, use the origin's effective domain
        if (!rpId) {
            return effectiveDomain;
        }

        // rpId must be a string
        if (typeof rpId !== 'string') {
            throw new ValidationError("RP ID must be a string");
        }

        // Convert both to lowercase for comparison
        rpId = rpId.toLowerCase();
        const domain = effectiveDomain.toLowerCase();

        // rpId must be equal to the effective domain or a registrable suffix of it
        if (rpId === domain || domain.endsWith('.' + rpId)) {
            return rpId;
        }

        throw new ValidationError("RP ID is not a valid registrable domain suffix of the origin's effective domain");
    } catch (e) {
        if (e instanceof ValidationError) {
            throw e;
        }
        throw new ValidationError("Invalid origin format");
    }
}