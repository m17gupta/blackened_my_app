import express from 'express';
import { handleUserAction, getUsers } from '../controllers/userController.js';

const router = express.Router();

// Match the existing API pattern observed in the mobile app's thunks
router.post('/login', handleUserAction);
router.get('/users', getUsers);

export default router;
