import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import userRoutes from './routes/userRoutes.js';
import passwordRoutes from './routes/passwordRoutes.js';
import { supabase } from './config/supabase.js';

// Load env variables
dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api', userRoutes);
app.use('/api/passwords', passwordRoutes);

// Basic health check route
app.get('/', async (req, res) => {
    try {
        const { error } = await supabase.from('users').select('count', { count: 'exact', head: true });
        if (error) {
            return res.status(200).json({ status: 'partially_connected', error: error.message });
        }
        res.send('✅ E-commerce API is running and connected (V3 - Stable)...');
    } catch (err: any) {
        res.status(500).json({ status: 'error', error: err.message });
    }
});

const PORT = Number(process.env.PORT) || 5001;

// Skip listen on Vercel
if (!process.env.VERCEL) {
    app.listen(PORT, () => {
        console.log(`Server is running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
    });
}

export default app;
