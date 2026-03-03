import { Request, Response } from 'express';
import { supabase } from '../config/supabase.js';
import {
    PasswordPayload,
    PasswordCategory,
    CreatePasswordBody,
    UpdatePasswordBody,
} from '../types/password.js';
import bcrypt from 'bcryptjs';
// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Flatten a typed `PasswordPayload` into the column names the Supabase table uses.
 * Every key maps 1-to-1 with a column in the passwords table.
 */
async function payloadToColumns(payload: PasswordPayload): Promise<Record<string, unknown>> {
    const base: Record<string, unknown> = {};

    // Hash the password only inside the case branches where the field exists.
    // Accessing payload.password BEFORE the switch is a type error because
    // CreditCardType (and others) do not have a password field.
    switch (payload.type) {
        case 'website':
            base.url = payload.url;
            base.username = payload.username;
            base.password = await bcrypt.hash(payload.password, 10);
            break;

        case 'database_username':
            base.host = payload.host;
            base.port = payload.port ?? null;
            base.database_name = payload.databaseName;
            base.username = payload.username;
            base.password = payload.password
                ? await bcrypt.hash(payload.password, 10)
                : null;
            break;

        case 'password_with_url':
            base.url = payload.url;
            base.password = await bcrypt.hash(payload.password, 10);
            base.notes = payload.notes ?? null;
            break;

        case 'database_connection':
            base.connection_string = payload.connectionString;
            base.host = payload.host ?? null;
            base.port = payload.port ?? null;
            base.database_name = payload.databaseName ?? null;
            base.username = payload.username ?? null;
            base.password = payload.password
                ? await bcrypt.hash(payload.password, 10)
                : null;
            break;

        case 'credit_card':
            // No password field on CreditCardType
            base.cardholder_name = payload.cardholderName;
            base.card_number = payload.cardNumber;
            base.expiry_month = payload.expiryMonth;
            base.expiry_year = payload.expiryYear;
            base.cvv = payload.cvv ?? null;
            base.billing_address = payload.billingAddress ?? null;
            base.notes = payload.notes ?? null;
            break;

        case 'generic':
            base.username = payload.username ?? null;
            base.password = payload.password
                ? await bcrypt.hash(payload.password, 10)
                : null;
            base.notes = payload.notes ?? null;
            break;
    }

    return base;
}

/**
 * Re-assemble a Supabase row back into the typed `PasswordPayload` discriminated union.
 */
function rowToPayload(row: any): PasswordPayload {
    const t: PasswordCategory = row.type;

    switch (t) {
        case 'website':
            return { type: 'website', url: row.url, username: row.username, password: row.password };

        case 'database_username':
            return {
                type: 'database_username',
                host: row.host,
                port: row.port ?? undefined,
                databaseName: row.database_name,
                username: row.username,
                password: row.password ?? undefined,
            };

        case 'password_with_url':
            return {
                type: 'password_with_url',
                url: row.url,
                password: row.password,
                notes: row.notes ?? undefined,
            };

        case 'database_connection':
            return {
                type: 'database_connection',
                connectionString: row.connection_string,
                host: row.host ?? undefined,
                port: row.port ?? undefined,
                databaseName: row.database_name ?? undefined,
                username: row.username ?? undefined,
                password: row.password ?? undefined,
            };

        case 'credit_card':
            return {
                type: 'credit_card',
                cardholderName: row.cardholder_name,
                cardNumber: row.card_number,
                expiryMonth: row.expiry_month,
                expiryYear: row.expiry_year,
                cvv: row.cvv ?? undefined,
                billingAddress: row.billing_address ?? undefined,
                notes: row.notes ?? undefined,
            };

        case 'generic':
        default:
            return {
                type: 'generic',
                username: row.username ?? undefined,
                password: row.password ?? undefined,
                notes: row.notes ?? undefined,
            };
    }
}

/**
 * Convert a raw Supabase row into the clean `PasswordType` shape expected by
 * the mobile app.
 */
function rowToPasswordType(row: any) {
    return {
        id: row.id,
        title: row.title,
        icon: row.icon ?? undefined,
        payload: rowToPayload(row),
        isShowPassword: row.is_show_password,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    };
}

// ─── CRUD handlers ────────────────────────────────────────────────────────────

/**
 * GET /api/passwords
 * List all passwords that belong to the authenticated user.
 * The user_id is read from the JWT payload attached by the auth middleware.
 */
export const getPasswords = async (req: Request, res: Response) => {
    const userId = (req as any).user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    try {
        const { data, error } = await supabase
            .from('passwords')
            .select('*')
            .eq('user_id', userId)
            .order('created_at', { ascending: false });

        if (error) throw error;

        return res.status(200).json((data ?? []).map(rowToPasswordType));
    } catch (err: any) {
        console.error('getPasswords error:', err);
        return res.status(500).json({ error: err.message });
    }
};

/**
 * GET /api/passwords/:id
 * Fetch a single password record by its UUID.
 */
export const getPasswordById = async (req: Request, res: Response) => {
    const userId = (req as any).user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const { id } = req.params;

    try {
        const { data, error } = await supabase
            .from('passwords')
            .select('*')
            .eq('id', id)
            .eq('user_id', userId)
            .single();

        if (error) {
            if (error.code === 'PGRST116') {
                return res.status(404).json({ error: 'Password not found' });
            }
            throw error;
        }

        return res.status(200).json(rowToPasswordType(data));
    } catch (err: any) {
        console.error('getPasswordById error:', err);
        return res.status(500).json({ error: err.message });
    }
};

/**
 * POST /api/passwords
 * Create a new password record.
 *
 * Body: { title, icon?, payload: PasswordPayload, isShowPassword? }
 */
export const createPassword = async (req: Request, res: Response) => {
    const userId = (req as any).user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const body: CreatePasswordBody = req.body;

    if (!body.title || !body.payload?.type) {
        return res.status(400).json({ error: 'title and payload.type are required' });
    }

    const columns = await payloadToColumns(body.payload);

    try {
        const { data, error } = await supabase
            .from('passwords')
            .insert([{
                user_id: userId,
                title: body.title,
                icon: body.icon ?? null,
                type: body.payload.type,
                is_show_password: body.isShowPassword ?? false,
                ...columns,
            }])
            .select()
            .single();

        if (error) throw error;

        return res.status(201).json(rowToPasswordType(data));
    } catch (err: any) {
        console.error('createPassword error:', err);
        return res.status(500).json({ error: err.message });
    }
};

/**
 * PUT /api/passwords/:id
 * Replace / update a password record.
 *
 * Body: { title?, icon?, payload?: PasswordPayload, isShowPassword? }
 * Only the fields you pass will be updated (partial update supported).
 */
export const updatePassword = async (req: Request, res: Response) => {
    const userId = (req as any).user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const { id } = req.params;
    const body: UpdatePasswordBody = req.body;

    // Build the update object incrementally
    const updates: Record<string, unknown> = {
        updated_at: new Date().toISOString(),
    };

    if (body.title !== undefined) updates.title = body.title;
    if (body.icon !== undefined) updates.icon = body.icon;
    if (body.isShowPassword !== undefined) updates.is_show_password = body.isShowPassword;

    if (body.payload) {
        updates.type = body.payload.type;
        Object.assign(updates, await payloadToColumns(body.payload));
    }

    try {
        const { data, error } = await supabase
            .from('passwords')
            .update(updates)
            .eq('id', id)
            .eq('user_id', userId)
            .select()
            .single();

        if (error) {
            if (error.code === 'PGRST116') {
                return res.status(404).json({ error: 'Password not found' });
            }
            throw error;
        }

        return res.status(200).json(rowToPasswordType(data));
    } catch (err: any) {
        console.error('updatePassword error:', err);
        return res.status(500).json({ error: err.message });
    }
};

/**
 * DELETE /api/passwords/:id
 * Permanently remove a password record.
 */
export const deletePassword = async (req: Request, res: Response) => {
    const userId = (req as any).user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const { id } = req.params;

    try {
        const { error } = await supabase
            .from('passwords')
            .delete()
            .eq('id', id)
            .eq('user_id', userId);

        if (error) throw error;

        return res.status(200).json({ message: 'Password deleted successfully' });
    } catch (err: any) {
        console.error('deletePassword error:', err);
        return res.status(500).json({ error: err.message });
    }
};
