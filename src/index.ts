import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import userRoutes from './routes/userRoutes.js';
import passwordRoutes from './routes/passwordRoutes.js';
import { supabase } from './config/supabase.js';

// Load env variables
dotenv.config();

const app = express();

// ── CORS ─────────────────────────────────────────────────────────────────────
// Browsers block `credentials: 'include'` requests when the server responds
// with the wildcard `Access-Control-Allow-Origin: *`.
// We must list allowed origins explicitly and set `credentials: true`.
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS ?? '')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);

// Always allow common local dev ports so the app works out-of-the-box
const DEFAULT_DEV_ORIGINS = [
    'http://localhost:8081',   // Expo web
    'http://localhost:3000',   // Next.js / CRA
    'http://localhost:19006',  // Expo dev tools
    'http://127.0.0.1:8081',
    'http://127.0.0.1:3000',
    "https://blackened-my-app.vercel.app"
];

app.use(
    cors({
        origin: (origin, callback) => {
            // Allow server-to-server / curl requests (no Origin header)
            if (!origin) return callback(null, true);

            const allowed = [...DEFAULT_DEV_ORIGINS, ...ALLOWED_ORIGINS];
            if (allowed.includes(origin)) {
                return callback(null, origin); // reflect the exact origin
            }
            callback(new Error(`CORS: origin '${origin}' not allowed`));
        },
        credentials: true,          // required for cookies / Authorization header
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization'],
    })
);

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
