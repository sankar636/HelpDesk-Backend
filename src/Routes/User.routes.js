import { Router } from 'express';
import {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  updateAccountWithPassword,
  getUserProfile,
} from '../Controllers/User.controller.js'
import { verifyJWT } from '../Middlewares/auth.middleware.js';

const router = Router();

router.post('/register', registerUser);
router.post('/login', loginUser);
router.post('/logout', verifyJWT, logoutUser);
router.get('/profile', verifyJWT, getUserProfile);
router.post('/refresh-token', refreshAccessToken);
router.put('/account/update', verifyJWT, updateAccountWithPassword);

export default router;
