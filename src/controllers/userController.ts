import { Request, Response } from 'express';
import { supabase } from '../config/supabase.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const generateToken = (id: string) => {
    return jwt.sign({ id }, process.env.JWT_SECRET || 'supersecretkey', {
        expiresIn: '30d',
    });
};

export const handleUserAction = async (req: Request, res: Response) => {
    const { email, password } = req.body;
    console.log("email", email);
    console.log("password", password);
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
    }

    try {
        // Check if user exists in Supabase
        const { data: existingUser, error: checkError } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();
        console.log("existingUser", existingUser);
        if (checkError && checkError.code !== 'PGRST116') { // PGRST116 is "no rows found"
            throw checkError;
        }

        // LOGIN LOGIC
        if (existingUser) {
            const isPasswordValid = await bcrypt.compare(password, existingUser.password);
            if (!isPasswordValid) {
                return res.status(401).json({ error: 'Invalid password' });
            }

            const { password: _, ...userWithoutPassword } = existingUser;
            return res.status(200).json({
                message: 'User logged in',
                user: userWithoutPassword,
                token: generateToken(existingUser.id.toString()),
            });
        }

        // REGISTER LOGIC
        const hashedPassword = await bcrypt.hash(password, 10);
        const { data: newUser, error: createError } = await supabase
            .from('users')
            .insert([{ ...req.body, password: hashedPassword }])
            .select()
            .single();

        if (createError) throw createError;

        const { password: __, ...userWithoutPassword } = newUser;
        return res.status(201).json({
            message: 'User created',
            user: userWithoutPassword,
            token: generateToken(newUser.id.toString()),
        });

    } catch (error: any) {
        console.error('User Action Error:', error);
        return res.status(500).json({ error: error.message });
    }
};

export const getUsers = async (req: Request, res: Response) => {
    try {
        const { data: users, error } = await supabase
            .from('users')
            .select('id, name, email, dob, created_at, updated_at');

        if (error) throw error;

        return res.status(200).json(users);
    } catch (error: any) {
        return res.status(500).json({ error: error.message });
    }
};

// get all list of users
export const handleListUsers = async (req: Request, res: Response) => {
    try {
        const { data: users, error } = await supabase
            .from('users')
            .select('id, name, email,role, dob, created_at, updated_at');

        if (error) throw error;

        return res.status(200).json(users);
    } catch (error: any) {
        return res.status(500).json({ error: error.message });
    }
};
