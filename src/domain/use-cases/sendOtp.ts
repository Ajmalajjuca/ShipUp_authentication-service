import { AuthRepository } from '../repositories/authRepository';
import { OtpServiceInterface } from '../../application/services/otpService';
import { EmailServiceInterface } from '../../application/services/emailService';

export class SendOtp {
  constructor(
    private authRepo: AuthRepository,
    private otpService: OtpServiceInterface,
    private emailService: EmailServiceInterface
  ) {}

  async execute(email: string): Promise<{ success: boolean; error?: string }> {
    try {
      const otp = this.otpService.generateOtp();
      await this.otpService.storeOtp(email, otp);
      await this.emailService.sendOtpEmail(email, otp);
      
      return { success: true };
    } catch (error) {
      console.error('Send OTP error:', error);
      return { success: false, error: 'Failed to send OTP' };
    }
  }
}