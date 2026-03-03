import express from 'express';
import {
    getPasswords,
    getPasswordById,
    createPassword,
    updatePassword,
    deletePassword,
} from '../controllers/passwordController.js';
import { authMiddleware } from '../middlewares/authMiddleware.js';


const router = express.Router();

// All password routes are protected – the JWT must be valid
router.use(authMiddleware);

// ── CRUD ──────────────────────────────────────────────────────────────────────
router.get('/', getPasswords);      // GET    /api/passwords
router.get('/:id', getPasswordById);   // GET    /api/passwords/:id
router.post('/', createPassword);    // POST   /api/passwords
router.put('/:id', updatePassword);    // PUT    /api/passwords/:id
router.delete('/:id', deletePassword);  // DELETE /api/passwords/:id

export default router;
