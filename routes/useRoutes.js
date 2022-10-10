import express from 'express';
import {changeUserPassword, loggedUser, sendResetPasswordEmail, userlogin, userRegistration} from '../controllers/userController.js';
import checkUserAuth from '../middlewares/auth_middleware.js';

const router = express.Router();

// Route level Middleware - To protect Route
router.use('/changepassword', checkUserAuth);
// when we hit the above route control will go to checkUserAuth middleware which will verify the user and then it will pass the control to the changeUSerPassword controller
router.use('/loggeduser', checkUserAuth);

// Public Routes
router.post('/register', userRegistration);
router.post('/login', userlogin);
router.post('/send-reset-password-email', sendResetPasswordEmail);


// Protected Routes
router.post('/changepassword', changeUserPassword);
router.get('/loggeduser', loggedUser);

export default router;