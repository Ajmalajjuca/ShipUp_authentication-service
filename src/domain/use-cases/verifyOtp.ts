import { OtpServiceInterface } from '../../application/services/otpService';
import { AuthServiceType } from '../../application/services/authService';
import { AuthRepository } from '../../domain/repositories/authRepository';
import axios from 'axios';

export class VerifyOtp {
  constructor(
    private otpService: OtpServiceInterface,
    private authService: AuthServiceType,
    private authRepo: AuthRepository
  ) {}

  async execute(email: string, otp: string, newPassword?: string): Promise<{ success: boolean; error?: string; token?: string }> {
    try {
      const result = await this.otpService.verifyOtp(email, otp);
      
      if (!result.isValid) {
        return { success: false, error: 'Invalid or expired OTP' };
      }

      // If newPassword is provided, this is a password reset flow
      if (newPassword) {
        const user = await this.authRepo.findByEmail(email);
        if (!user) {
          return { success: false, error: 'User not found' };
        }

        await this.authRepo.updatePassword(user.userId, newPassword);
        
        // Clear OTP after successful password reset
        await this.otpService.clearOtp(email);
        
        return { success: true };
      }

      // Existing registration verification logic
      const pendingDataJson = await this.otpService.getRedisKey(`${email}:pending`);
      if (!pendingDataJson) {
        return { success: false, error: 'No pending registration found' };
      }
      
      const { authData, additionalData } = JSON.parse(pendingDataJson);
      const { userId, role } = authData;
      
      await this.authRepo.create(authData);
      
      const serviceUrl = role === 'user' ? process.env.USER_SERVICE_URL : process.env.PARTNER_SERVICE_URL;
      try {
        await axios.post(`${serviceUrl}/${role === 'user' ? 'users' : 'drivers'}`, {
          ...(role === 'user' ? { userId } : { partnerId: userId }),
          email,
          ...additionalData,
        });
      } catch (error) {
        console.error('Downstream service error:', error);
        // Rollback auth creation if downstream fails
        await this.authRepo.delete(userId);
        return { success: false, error: 'Failed to complete registration' };
      }

      await Promise.all([
        this.otpService.deleteRedisKey(`${email}:pending`),
        this.otpService.deleteRedisKey(`${email}:otp`)
      ]);

      const token = this.authService.generateToken(userId, email, role);
      return { success: true, token };
    } catch (error) {
      console.error('Verify OTP error:', error);
      return { success: false, error: 'OTP verification failed' };
    }
  }
}
