// import { Request, Response } from 'express';
// import { RegisterUser } from '../../domain/use-cases/registerUser';
// import { LoginUser } from '../../domain/use-cases/loginUser';
// import { SendOtp } from '../../domain/use-cases/sendOtp';
// import { VerifyOtp } from '../../domain/use-cases/verifyOtp';
// import { AuthRepositoryImpl } from '../../infrastructure/repositories/authRepositoryImpl';
// import { AuthService } from '../../application/services/authService';
// import { OtpService } from '../../application/services/otpService';
// import { EmailService } from '../../application/services/emailService';
// import multer from 'multer';
// import bcrypt from 'bcrypt';
// import axios from 'axios';
// import jwt from 'jsonwebtoken';
// import { OAuth2Client } from "google-auth-library";
// import { client } from '../../server';
// import { GoogleAuthUser } from '../../domain/use-cases/googleAuthUser';
// import { UserService } from '../../application/services/userService';

// const authRepository = new AuthRepositoryImpl();
// const authService = new AuthService();
// const otpService = new OtpService();
// const emailService = new EmailService();
// const userService = new UserService();
// const googleAuthUser = new GoogleAuthUser(authRepository, authService, userService);

// const registerUser = new RegisterUser(authRepository, authService, otpService, emailService);
// const loginUser = new LoginUser(authRepository, authService);
// const sendOtp = new SendOtp(authRepository, otpService, emailService);
// const verifyOtp = new VerifyOtp(otpService, authService, authRepository);

// const upload = multer({ dest: 'uploads/' }); // For handling multipart/form-data from Partner Service

// export const authController = {
//   // Existing user registration (password required)
//   async register(req: Request, res: Response) {
//     try {
//       const { email, password, role, fullName, phone } = req.body;
//       if (!email || !password || !role || !fullName || !phone) {
//         res.status(400).json({ success: false, error: 'All fields are required' });
//         return;
//       }

//       const result = await registerUser.execute(email, password, role, { fullName, phone });
//       if (!result.success) {
//         res.status(400).json(result);
//         return;
//       }

//       res.status(201).json({
//         success: true,
//         message: result.message,
//         token: authService.generateToken(result.userId || '', email, role),
//         user: { email, role, fullName, phone, userId: result.userId }
//       });
//       return;
//     } catch (error) {
//       console.error('Registration error:', error);
//       res.status(500).json({ success: false, error: 'Internal server error' });
//       return;
//     }
//   },

//   // New driver registration (no password, from Partner Service)
//   async registerDriver(req: Request, res: Response) {
//     try {
//       const { email, role, partnerId } = req.body;

//       if (!email || !role || role !== 'partner') {
//         res.status(400).json({ success: false, error: 'Email and role=driver are required' });
//         return;
//       }

//       // Check if email already exists
//       const existingUser = await authRepository.findByEmail(email);
//       if (existingUser) {
//         res.status(400).json({ success: false, error: 'Email already exists' });
//         return;
//       }

//       // Store email and role directly in the database (no OTP)
//       const authData: { userId: string; email: string; password: string; role: 'user' | 'partner' | 'admin' } = {
//         userId: partnerId || `DRV-${authService.generateUserId()}`,
//         email,
//         password: '', // or generate a random password if needed
//         role: 'partner',
//       };

//       await authRepository.create(authData);

//       res.status(201).json({
//         success: true,
//         message: 'Driver email registered successfully',
//         user: { email, role: 'partner', partnerId: authData.userId }
//       });
//       return;
//     } catch (error) {
//       console.error('Driver registration error:', error);
//       res.status(500).json({ success: false, error: 'Internal server error' });
//       return;
//     }
//   },

//   // Existing user login (password-based)
//   async login(req: Request, res: Response) {
//     try {
//       const { email, password } = req.body;
//       if (!email || !password) {
//         res.status(400).json({ 
//           success: false, 
//           error: 'Email and password are required',
//           passwordError: true
//         });
//         return;
//       }

//       const result = await loginUser.execute(email, password);
//       if (!result.success || !result.authUser || !result.token) {
//         res.status(401).json({ 
//           success: false, 
//           error: result.error || 'Invalid email or password',
//           passwordError: true
//         });
//         return;
//       }
      
//       // Generate refresh token
//       const refreshToken = authService.generateRefreshToken(
//         result.authUser.userId, 
//         result.authUser.email, 
//         result.authUser.role
//       );
      
//       // Calculate refresh token expiry
//       const refreshTokenExpiry = authService.getRefreshTokenExpiry();
      
//       // Save refresh token to the database
//       await authRepository.update(result.authUser.userId, {
//         refreshToken,
//         refreshTokenExpiry
//       });

//       // Get user details from user service
//       try {
//         const userResponse = await axios.get(
//           `${process.env.USER_SERVICE_URL}/users/${result.authUser.userId}`,
//           {
//             headers: { Authorization: `Bearer ${result.token}` }
//           }
//         );

        
//         if (userResponse.data.user && !userResponse.data.user.status) {
//           res.status(403).json({
//             success: false,
//             error: 'Your account has been blocked. Please contact admin for support.',
//             passwordError: false
//           });
//           return;
//         }
//         const userData = {
//           ...result.authUser,
//           ...userResponse.data.user // This will include the profileImage URL
//         };
        

//         res.status(200).json({
//           success: true,
//           message: 'Login successful',
//           user: userData,
//           token: result.token,
//           refreshToken: refreshToken
//         });
//       } catch (error) {
//         console.error('Error fetching user details:', error);
//         res.status(200).json({
//           success: true,
//           message: 'Login successful',
//           user: result.authUser,
//           token: result.token,
//           refreshToken: refreshToken
//         });
//       }
//     } catch (error) {
//       console.error('Login error:', error);
//       res.status(500).json({ 
//         success: false, 
//         error: 'Internal server error',
//         passwordError: false
//       });
//     }
//   },

//   // New driver login OTP request
//   async requestLoginOtp(req: Request, res: Response) {
//     try {
//       const { email } = req.body;
//       if (!email) {
//         res.status(400).json({ success: false, error: 'Email is required' });
//         return;
//       }

//       const authUser = await authRepository.findByEmail(email);
//       if (!authUser) {
//         res.status(404).json({ success: false, error: 'Email not registered' });
//         return;
//       }

//       try{
//         const driverResponse = await axios.get(
//           `${process.env.PARTNER_SERVICE_URL}/drivers/${authUser.userId}`,
          
//         )
        
//         if (driverResponse.data.partner && !driverResponse.data.partner.status) {
//           res.status(403).json({
//             success: false,
//             error: 'Your account has been blocked. Please contact admin for support.'
//           });
//           return;
//         }
//         if (authUser.role === 'user') {
//           res.status(400).json({ success: false, error: 'Use password-based login for users' });
//           return;
//         }
//       }
//       catch(error){
//         res.status(404).json({ success: false, error: (error as any).response?.data.error || 'Driver not found' });
//         // console.error('Error fetching driver details:', (error as any).response?.data.error);
//         return;
//       }

      

//       const otp = otpService.generateOtp();
//       await otpService.storeOtp(email, otp);
//       await emailService.sendOtpEmail(email, otp);

//       res.status(200).json({
//         success: true,
//         message: 'OTP sent to your email for login'
//       });
//       return;
//     } catch (error) {
//       console.error('Login OTP request error:', error);
//       res.status(500).json({ success: false, error: 'Internal server error' });
//       return;
//     }
//   },

//   // New driver login OTP verification
//   async verifyLoginOtp(req: Request, res: Response) {
//     try {
//       const { email, otp } = req.body;
//       if (!email || !otp) {
//         res.status(400).json({ success: false, message: 'Email and OTP are required' });
//         return;
//       }

//       // Verify OTP
//       const verificationResult = await otpService.verifyOtp(email, otp);
//       if (!verificationResult.isValid) {
//         res.status(401).json({ success: false, message: 'Invalid or expired OTP' });
//         return;
//       }

//       // Get partner record
//       const partner = await authRepository.findByEmail(email);
//       if (!partner) {
//         res.status(404).json({ success: false, message: "Partner not found" });
//         return;
//       }

//       // Verify partner role
//       if (partner.role !== 'partner') {
//         res.status(403).json({ success: false, message: "Not authorized as partner" });
//         return;
//       }

//       // Generate token
//       const token = authService.generateToken(partner.userId, email, 'partner');
      
//       // Generate refresh token
//       const refreshToken = authService.generateRefreshToken(partner.userId, email, 'partner');
      
//       // Calculate refresh token expiry
//       const refreshTokenExpiry = authService.getRefreshTokenExpiry();
      
//       // Save refresh token to the database
//       await authRepository.update(partner.userId, {
//         refreshToken,
//         refreshTokenExpiry
//       });
      
//       res.status(200).json({
//         success: true,
//         message: "OTP verified successfully",
//         token,
//         refreshToken,
//         partnerId: partner.userId,
//         email: partner.email,
//         role: 'partner'
//       });
//     } catch (error) {
//       console.error('OTP verification error:', error);
//       res.status(500).json({ success: false, message: "Internal server error" });
//     }
//   },

//   // Existing send OTP (unchanged)
//   async sendOtp(req: Request, res: Response) {
//     try {
//       const { email } = req.body;
      
//       if (!email) {
//         res.status(400).json({ success: false, error: 'Email is required' });
//         return;
//       }
      
//       const result = await sendOtp.execute(email);
//       res.status(result.success ? 200 : 400).json({
//         success: result.success,
//         message: result.success ? 'OTP sent successfully' : result.error
//       });
//       return;
//     } catch (error) {
//       console.error('Send OTP error:', error);
//       res.status(500).json({ success: false, error: 'Internal server error' });
//       return;
//     }
//   },

//   // Existing verify OTP (unchanged, handles registration verification)
//   async verifyOtp(req: Request, res: Response) {
//     try {
//       const { email, otp, newPassword } = req.body;
//       const hashedPassword = newPassword ? await bcrypt.hash(newPassword, 10) : '';
//       if (!email || !otp) {
//         res.status(400).json({ success: false, error: 'Email and OTP are required' });
//         return;
//       }

//       const result = await verifyOtp.execute(email, otp, hashedPassword);
//       if (!result.success) {
//         res.status(400).json(result);
//         return;
//       }

//       // If newPassword is provided, this was a password reset flow
//       if (newPassword) {
//         res.status(200).json({
//           success: true,
//           message: 'Password reset successful'
//         });
//         return;
//       }

//       // Get the user details for refresh token generation
//       const user = await authRepository.findByEmail(email);
//       if (!user) {
//         res.status(404).json({ success: false, error: 'User not found' });
//         return;
//       }

//       // Generate refresh token
//       const refreshToken = authService.generateRefreshToken(
//         user.userId,
//         email,
//         user.role
//       );
      
//       // Calculate refresh token expiry
//       const refreshTokenExpiry = authService.getRefreshTokenExpiry();
      
//       // Save refresh token to the database
//       await authRepository.update(user.userId, {
//         refreshToken,
//         refreshTokenExpiry
//       });

//       // Normal OTP verification flow
//       res.status(200).json({
//         success: true,
//         message: 'OTP verified successfully',
//         token: result.token,
//         refreshToken: refreshToken
//       });
      
//     } catch (error) {
//       console.error('Verify OTP error:', error);
//       res.status(500).json({ success: false, error: 'Internal server error' });
//     }
//   },

//   async forgotPassword(req: Request, res: Response) {
//     try {
//       const { email } = req.body;
      
//       if (!email) {
//         res.status(400).json({ 
//           success: false, 
//           message: 'Email is required' 
//         });
//         return;
//       }

//       // Verify user exists
//       const user = await authRepository.findByEmail(email);
//       if (!user) {
//         res.status(404).json({
//           success: false,
//           message: 'User not found'
//         });
//         return;
//       }

//       // Send OTP
//       const result = await sendOtp.execute(email);
//       if (!result.success) {
//         res.status(400).json(result);
//         return;
//       }

//       // Store the temporary token for password reset flow
//       const tempToken = authService.generateToken(user.userId, email, user.role);
      
//       res.status(200).json({
//         success: true,
//         message: 'OTP sent successfully',
//         token: tempToken // Frontend will use this for OTP verification
//       });
      
//     } catch (error) {
//       console.error('Forgot password error:', error);
//       res.status(500).json({ 
//         success: false, 
//         message: 'Internal server error' 
//       });
//     }
//   },

//   async delete(req: Request, res: Response) {
//     try {
//       const { userId } = req.params;
//       await authRepository.delete(userId);
//       res.status(200).json({ success: true, message: 'User deleted' });
//       return;
//     } catch (error) {
//       console.error('Delete error:', error);
//       res.status(500).json({ success: false, error: 'Internal server error' });
//       return;
//     }
//   },

//   async verifyToken(req: Request, res: Response) {
//     try {
//       const authHeader = req.headers.authorization;
//       if (!authHeader) {
//          res.status(401).json({ valid: false, message: 'No token provided' });
//          return
//       }

//       const token = authHeader.split(' ')[1]; // Remove 'Bearer ' prefix
//       if (!token) {
//          res.status(401).json({ valid: false, message: 'Invalid token format' });
//          return
//       }

//       try {
//         // Verify token using your JWT service or auth service
//         const decoded = await authService.verifyToken(token);
//          res.status(200).json({ valid: true, user: decoded });
//          return
//       } catch (error) {
//         console.error('Token verification failed:', error);
//          res.status(401).json({ valid: false, message: 'Invalid token' });
//          return
//       }
//     } catch (error) {
//       console.error('Token verification error:', error);
//        res.status(500).json({ valid: false, message: 'Internal server error' });
//        return
//     }
//   },

//   async verifyPassword(req: Request, res: Response) {
//     try {
//       const { userId, password } = req.body;
      
//       const user = await authRepository.findById(userId);
//       if (!user) {
//         res.status(404).json({ success: false, message: 'User not found' });
//         return;
//       }

//       const isValid = await bcrypt.compare(password, user.password);
      
//       res.status(200).json({ success: isValid });
//     } catch (error) {
//       console.error('Password verification error:', error);
//       res.status(500).json({ success: false, message: 'Internal server error' });
//     }
//   },

//   async updatePassword(req: Request, res: Response) {
//     try {
//       const { userId, currentPassword, newPassword } = req.body;
      

//       const user = await authRepository.findById(userId);
//       if (!user) {
//         res.status(404).json({ 
//           success: false, 
//           message: 'User not found',
//           passwordError: true
//         });
//         return;
//       }
//       const isValid = await bcrypt.compare(currentPassword, user.password);
      
//       if(isValid){
//         const hashedPassword = await bcrypt.hash(newPassword, 10);
//         await authRepository.updatePassword(userId, hashedPassword);
        
//         res.status(200).json({ 
//           success: true, 
//           message: 'Password updated successfully' 
//         });
//       } else {
//         res.status(400).json({ 
//           success: false, 
//           message: 'Current password is incorrect',
//           passwordError: true
//         });
//       }
//     } catch (error) {
//       console.error('Password update error:', error);
//       res.status(500).json({ 
//         success: false, 
//         message: 'Failed to update password',
//         passwordError: true
//       });
//     }
//   },

//   async verifyPartnerToken(req: Request, res: Response) {
//     const token = req.headers.authorization?.split(' ')[1];

//     try {
//       const { email } = req.body;

//       if (!token || !email) {
//          res.status(401).json({
//           success: false,
//           message: 'No token or email provided'
//         });
//         return
//       }

//       // Verify the token
//       try {
//         const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;
        
//         // Check if the token belongs to the partner
//         if (decoded.email !== email || decoded.role !== 'partner') {
//            res.status(401).json({
//             success: false,
//             message: 'Invalid token'
//           });
//           return
//         }

//          res.json({
//           success: true,
//           message: 'Token is valid'
//         });
//         return
//       } catch (jwtError) {
//         console.error('JWT verification error:', jwtError);
//          res.status(401).json({
//           success: false,
//           message: 'Invalid token'
//         });
//         return
//       }
//     } catch (error) {
//       console.error('Partner token verification error:', error);
//        res.status(500).json({
//         success: false,
//         message: 'Internal server error'
//       });
//       return
//     }
//   },

//   async googleLogin(req: Request, res: Response) {
//     try {
//       const { credential } = req.body;
      
//       if (!credential) {
//          res.status(400).json({ success: false, error: "Google token is required" });
//          return
//       }

//       // Verify the Google token
//       try {
//         const ticket = await client.verifyIdToken({
//           idToken: credential,
//           audience: process.env.GOOGLE_CLIENT_ID,
//         });

//         const payload = ticket.getPayload();
        
//         if (!payload || !payload.email) {
//            res.status(400).json({ success: false, error: "Invalid token" });
//            return
//         }

//         const result = await googleAuthUser.execute({
//           email: payload.email,
//           name: payload.name,
//           picture: payload.picture
//         });

//         if (!result.success) {
//            res.status(400).json(result);
//            return
//         }

//         // Generate refresh token
//         const refreshToken = authService.generateRefreshToken(
//           result.user.userId, 
//           result.user.email, 
//           result.user.role
//         );
        
//         // Calculate refresh token expiry
//         const refreshTokenExpiry = authService.getRefreshTokenExpiry();
        
//         // Save refresh token to the database
//         await authRepository.update(result.user.userId, {
//           refreshToken,
//           refreshTokenExpiry
//         });

//         // Return successful response with refresh token
//          res.status(200).json({
//           ...result,
//           refreshToken
//         });
//         return
//       } catch (verifyError: any) {
//         console.error('Token verification error:', {
//           error: verifyError.message,
//           clientId: process.env.GOOGLE_CLIENT_ID,
//           stack: verifyError.stack
//         });
//          res.status(401).json({ 
//           success: false, 
//           error: "Token verification failed",
//           details: verifyError.message
//         });
//         return
//       }
//     } catch (error: any) {
//       console.error('Google authentication error:', error);
//        res.status(400).json({ success: false, error: "Authentication failed" });
//        return
//     }
//   },

//   async updateEmail(req: Request, res: Response) {
//     try {
//       const { partnerId } = req.params;
//       const { email } = req.body;

//       if (!email) {
//         res.status(400).json({
//           success: false,
//           error: 'Email is required'
//         });
//         return;
//       }

//       // Check if email is already in use by another user
//       const existingUser = await authRepository.findByEmail(email);
//       if (existingUser && existingUser.userId !== partnerId) {
//         res.status(400).json({
//           success: false,
//           error: 'Email is already in use by another user'
//         });
//         return;
//       }

//       // Update the email
//       const updatedUser = await authRepository.updateEmail(partnerId, email);
      
//       if (!updatedUser) {
//         res.status(404).json({
//           success: false,
//           error: 'User not found'
//         });
//         return;
//       }

//       res.status(200).json({
//         success: true,
//         message: 'Email updated successfully',
//         user: {
//           userId: updatedUser.userId,
//           email: updatedUser.email,
//           role: updatedUser.role
//         }
//       });

//     } catch (error) {
//       console.error('Update email error:', error);
//       res.status(500).json({
//         success: false,
//         error: 'Internal server error'
//       });
//     }
//   },

//   // Create temporary token for document uploads
//   async createTempToken(req: Request, res: Response) {
//     try {
//       if(!req.body.purpose){
//         const {userId,email,role} = req.body;
//         if (!userId || !email || !role) {
//           res.status(400).json({
//             success: false,
//             error: 'User ID, email, and role are required'
//           });
//           return
//         }
//        const token = authService.generateToken(userId, email, role);
//         res.status(200).json({
//           success: true,
//           token
//         });
//         return 
//       }



//       if (!req.body || Object.keys(req.body).length === 0) {
//          res.status(400).json({
//           success: false,
//           error: 'Request body is required'
//         });
//         return
//       }

//       const { purpose, role } = req.body;

//       if (!purpose || !role) {
//          res.status(400).json({
//           success: false,
//           error: 'Purpose and role are required'
//         });
//         return
//       }

//       if (purpose !== 'document-upload' || role !== 'partner') {
//          res.status(400).json({
//           success: false,
//           error: 'Invalid purpose or role'
//         });
//         return
//       }

//       // Generate a short-lived token (5 minutes)
//       const token = jwt.sign(
//         { purpose, role },
//         process.env.JWT_SECRET || 'your-secret-key',
//         { expiresIn: '5m' }
//       );

//        res.status(200).json({
//         success: true,
//         token
//       });
//       return
//     } catch (error) {
//       console.error('Error in createTempToken:', error);
//        res.status(500).json({
//         success: false,
//         error: 'Internal server error'
//       });
//       return
//     }
//   },

//   // Refresh token endpoint
//   async refreshToken(req: Request, res: Response) {
//     try {
//       const { refreshToken } = req.body;
      
//       console.log('Refresh token request received');
      
//       if (!refreshToken) {
//         console.log('Refresh token missing in request');
//          res.status(400).json({ 
//           success: false, 
//           error: 'Refresh token is required',
//           errorCode: 'REFRESH_TOKEN_MISSING'
//         });
//         return
//       }
      
//       // Verify the refresh token
//       let decoded;
//       try {
//         decoded = await authService.verifyRefreshToken(refreshToken);
//         console.log('Refresh token verified for user:', decoded.userId);
//       } catch (error) {
//         console.error('Refresh token verification error:', error);
//          res.status(401).json({ 
//           success: false, 
//           error: 'Invalid refresh token',
//           errorCode: 'REFRESH_TOKEN_INVALID'
//         });
//         return
//       }
      
//       // Find the user in the database
//       const user = await authRepository.findById(decoded.userId);
      
//       if (!user) {
//         console.log('User not found for refresh token:', decoded.userId);
//          res.status(404).json({ 
//           success: false, 
//           error: 'User not found',
//           errorCode: 'USER_NOT_FOUND'
//         });
//         return
//       }
      
//       // Check if the refresh token matches what's stored in the database
//       if (!user.refreshToken || user.refreshToken !== refreshToken) {
//         console.log('Refresh token mismatch for user:', user.userId);
//         console.log('Stored token:', user.refreshToken ? user.refreshToken.substring(0, 15) + '...' : 'none');
//         console.log('Received token:', refreshToken.substring(0, 15) + '...');
        
//          res.status(401).json({ 
//           success: false, 
//           error: 'Invalid refresh token - token mismatch',
//           errorCode: 'REFRESH_TOKEN_MISMATCH',
//           tokenMismatch: true
//         });
//         return
//       }
      
//       // Check if the refresh token is expired in the database
//       if (user.refreshTokenExpiry && new Date(user.refreshTokenExpiry) < new Date()) {
//         console.log('Refresh token expired for user:', user.userId);
//         console.log('Expiry:', user.refreshTokenExpiry);
//         console.log('Current time:', new Date());
        
//          res.status(401).json({ 
//           success: false, 
//           error: 'Refresh token expired',
//           errorCode: 'REFRESH_TOKEN_EXPIRED',
//           tokenExpired: true
//         });
//         return
//       }
      
//       console.log('Generating new tokens for user:', user.userId);
      
//       // Generate new tokens
//       const newAccessToken = authService.generateToken(user.userId, user.email, user.role);
//       const newRefreshToken = authService.generateRefreshToken(user.userId, user.email, user.role);
//       const refreshTokenExpiry = authService.getRefreshTokenExpiry();
      
//       // Update the refresh token in the database
//       await authRepository.update(user.userId, { 
//         refreshToken: newRefreshToken,
//         refreshTokenExpiry
//       });
      
//       console.log('Tokens refreshed successfully for user:', user.userId);
      
//        res.status(200).json({
//         success: true,
//         token: newAccessToken,
//         refreshToken: newRefreshToken,
//         user: {
//           userId: user.userId,
//           email: user.email,
//           role: user.role
//         }
//       });
//       return
//     } catch (error) {
//       console.error('Refresh token error:', error);
//        res.status(500).json({ 
//         success: false, 
//         error: 'Internal server error',
//         errorCode: 'SERVER_ERROR'
//       });
//       return
//     }
//   },

//   // Logout endpoint
//   async logout(req: Request, res: Response) {
//     try {
//       const { userId } = req.body;
      
//       if (!userId) {
//          res.status(400).json({ success: false, error: 'User ID is required' });
//          return
//       }
      
//       // Update the user record to clear the refresh token
//       await authRepository.update(userId, {
//         refreshToken: undefined,
//         refreshTokenExpiry: undefined
//       });
      
//        res.status(200).json({
//         success: true,
//         message: 'Logged out successfully'
//       });
//       return
//     } catch (error) {
//       console.error('Logout error:', error);
//        res.status(500).json({ success: false, error: 'Internal server error' });
//        return
//     }
//   },

// };