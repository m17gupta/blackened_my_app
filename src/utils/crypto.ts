import crypto from 'crypto';

const algorithm = 'aes-256-cbc';

// Read the 32-character key from .env (ENCRYPTION_KEY must be exactly 32 chars).
// We pad/slice defensively so a misconfigured key never crashes at startup.
const secretKey = (process.env.ENCRYPTION_KEY ?? 'default_32_char_key_change_me!!').padEnd(32).slice(0, 32);

export interface EncryptedPayload {
    iv: string;              // hex-encoded initialisation vector
    encryptedPassword: string; // hex-encoded ciphertext
}

/**
 * Encrypts a plaintext password using AES-256-CBC.
 * A fresh random IV is generated for every call, so identical passwords
 * produce different ciphertexts — this is intentional and correct.
 *
 * @returns An `EncryptedPayload` whose two fields can be joined as
 *          `iv:encryptedPassword` for single-column storage.
 */
export function encryptPassword(password: string): EncryptedPayload {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);

    let encrypted = cipher.update(password, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return {
        iv: iv.toString('hex'),
        encryptedPassword: encrypted,
    };
}

/**
 * Decrypts a ciphertext that was produced by `encryptPassword`.
 *
 * @param encryptedPassword  The hex-encoded ciphertext.
 * @param ivHex              The hex-encoded IV that was used during encryption.
 * @returns The original plaintext string.
 */
export function decryptPassword(encryptedPassword: string, ivHex: string): string {
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(algorithm, secretKey, iv);

    let decrypted = decipher.update(encryptedPassword, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

// ─── Convenience helpers used by the password controller ─────────────────────

/**
 * Serialise an `EncryptedPayload` into the single-column format we store in
 * Supabase: `"<ivHex>:<encryptedHex>"`.
 */
export function encryptToColumn(plaintext: string): string {
    const { iv, encryptedPassword } = encryptPassword(plaintext);
    return `${iv}:${encryptedPassword}`;
}

/**
 * Deserialise a column value produced by `encryptToColumn` and return the
 * plaintext, or `undefined` when the value is absent / a legacy bcrypt hash /
 * malformed.
 */
export function decryptFromColumn(columnValue: string | null | undefined): string | undefined {
    if (!columnValue) return undefined;
    // Legacy bcrypt hashes are one-way — cannot be decrypted.
    if (columnValue.startsWith('$2b$') || columnValue.startsWith('$2a$')) return undefined;
    try {
        const colonIdx = columnValue.indexOf(':');
        if (colonIdx === -1) return undefined;
        const ivHex = columnValue.slice(0, colonIdx);
        const encryptedHex = columnValue.slice(colonIdx + 1);
        return decryptPassword(encryptedHex, ivHex);
    } catch {
        return undefined;
    }
}
