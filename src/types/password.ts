// ─── Password Category Types ────────────────────────────────────────────────

/** A saved website login (URL + username + password) */
export interface WebsitePasswordType {
    type: "website";
    url: string;
    username: string;
    password: string;
}

/** A database user credential (host / port / db name / username / password) */
export interface DatabaseUsernameType {
    type: "database_username";
    host: string;
    port?: number;
    databaseName: string;
    username: string;
    password?: string;
}

/** A standalone password that is associated with a URL */
export interface PasswordWithURLType {
    type: "password_with_url";
    url: string;
    password: string;
    notes?: string;
}

/** Full database connection string or DSN */
export interface DatabaseConnectionType {
    type: "database_connection";
    connectionString: string;   // e.g. postgres://user:pass@host:5432/db
    host?: string;
    port?: number;
    databaseName?: string;
    username?: string;
    password?: string;
}

/** Credit card details */
export interface CreditCardType {
    type: "credit_card";
    cardholderName: string;
    cardNumber: string;         // store masked or encrypted – never plain text in production
    expiryMonth: number;        // 1–12
    expiryYear: number;         // e.g. 2027
    cvv?: string;
    billingAddress?: string;
    notes?: string;
}

/** Catch-all for any other credential that doesn't fit the above categories */
export interface GenericPasswordType {
    type: "generic";
    username?: string;
    password?: string;
    notes?: string;
}

// ─── Discriminated Union ─────────────────────────────────────────────────────

/**
 * Union of every concrete password payload.
 * Use the `type` discriminant to narrow to a specific shape.
 */
export type PasswordPayload =
    | WebsitePasswordType
    | DatabaseUsernameType
    | PasswordWithURLType
    | DatabaseConnectionType
    | CreditCardType
    | GenericPasswordType;

// ─── Valid category strings (mirrors the Postgres ENUM) ──────────────────────

export type PasswordCategory =
    | "website"
    | "database_username"
    | "password_with_url"
    | "database_connection"
    | "credit_card"
    | "generic";

// ─── Top-level Record ────────────────────────────────────────────────────────

/**
 * The full password record stored in the app.
 * `payload` carries the type-specific fields via a discriminated union,
 * so TypeScript will narrow the shape automatically when you check `payload.type`.
 */
export interface PasswordType {
    id: string;
    title: string;
    icon?: string;              // MaterialIcon name
    payload: PasswordPayload;   // ← discriminated union
    isShowPassword?: boolean;
    createdAt?: Date;
    updatedAt?: Date;
}

// ─── Request body shapes ─────────────────────────────────────────────────────

/** Body expected when creating a password record */
export interface CreatePasswordBody {
    title: string;
    icon?: string;
    payload: PasswordPayload;
    isShowPassword?: boolean;
}

/** Body expected when updating a password record (all fields optional) */
export interface UpdatePasswordBody {
    title?: string;
    icon?: string;
    payload?: PasswordPayload;
    isShowPassword?: boolean;
}
