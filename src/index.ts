import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import userRoutes from './routes/userRoutes';

// Load env variables
dotenv.config();

// Connect to Database & Test Supabase
import { supabase } from './config/supabase';

const testSupabase = async () => {
    try {
        const { error } = await supabase.from('users').select('count', { count: 'exact', head: true });
        if (error) {
            console.error('Supabase connection error:', error.message);
        } else {
            console.log('Supabase connected successfully');
        }
    } catch (err: any) {
        console.error('Failed to test Supabase connection:', err.message);
    }
};

// Test connection on startup
testSupabase();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api', userRoutes);

// Basic health check route
app.get('/', (req, res) => {
    res.send('E-commerce API is running...');
});

const PORT = Number(process.env.PORT) || 5001;

// Only listen locally, Vercel handles serverless execution
if (process.env.NODE_ENV !== 'production' || !process.env.VERCEL) {
    app.listen(PORT, () => {
        console.log(`Server is running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
    });
}

export default app;
