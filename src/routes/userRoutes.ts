import express from 'express';
import { handleUserAction, getUsers, handleListUsers } from '../controllers/userController.js';

const router = express.Router();

// Match the existing API pattern observed in the mobile app's thunks
router.post('/login', handleUserAction);
router.get('/users', getUsers);
router.get('/list-users', handleListUsers);

export default router;
