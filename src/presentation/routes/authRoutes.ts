import { Router } from 'express';
import { userAuthController } from '../../infrastructure/di/container';
import { tokenController } from '../../infrastructure/di/container';
import { otpController } from '../../infrastructure/di/container';
import { socialAuthController } from '../../infrastructure/di/container';
import { driverAuthController } from '../../infrastructure/di/container';
import multer from 'multer';

const router = Router();
const upload = multer({ dest: 'uploads/' });

// User Auth Routes
router.post('/register', userAuthController.register.bind(userAuthController));
router.post('/login', userAuthController.login.bind(userAuthController));
router.post('/verify-password', userAuthController.verifyPassword.bind(userAuthController));
router.put('/update-password', userAuthController.updatePassword.bind(userAuthController));
router.delete('/users/:userId', userAuthController.delete.bind(userAuthController));

// Token Routes
router.post('/verify-token', tokenController.verifyToken.bind(tokenController));
router.post('/refresh-token', tokenController.refreshToken.bind(tokenController));
router.post('/logout', tokenController.logout.bind(tokenController));
router.post('/temp-token', tokenController.createTempToken.bind(tokenController));
router.post('/verify-partner-token', tokenController.verifyPartnerToken.bind(tokenController));

// OTP Routes
router.post('/send-otp', otpController.sendOtp.bind(otpController));
router.post('/verify-otp', otpController.verifyOtp.bind(otpController));
router.post('/forgot-password', otpController.forgotPassword.bind(otpController));
router.post('/request-login-otp', otpController.requestLoginOtp.bind(otpController));
router.post('/verify-login-otp', otpController.verifyLoginOtp.bind(otpController));

// Social Auth Routes
router.post('/google-login', socialAuthController.googleLogin.bind(socialAuthController));

// Driver Auth Routes
router.post('/register-driver', driverAuthController.registerDriver.bind(driverAuthController));
router.put('/drivers/:partnerId/email', driverAuthController.updateEmail.bind(driverAuthController));

export default router;