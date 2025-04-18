import { Request, Response } from 'express';
import { ResponseHandler } from '../utils/responseHandler';
import { StatusCode } from '../../types/enums/StatusCode';
import { ErrorMessage } from '../../types/enums/ErrorMessage';
import { ErrorCode } from '../../types/enums/ErrorCode';
import { OtpRequest, VerifyOtpRequest } from '../../types/interfaces/requests';
import { OtpResponse, TokenResponse } from '../../types/interfaces/responses';
import { SendOtp } from '../../domain/use-cases/sendOtp';
import { VerifyOtp } from '../../domain/use-cases/verifyOtp';
import { AuthServiceType } from '../../application/services/authService';
import { OtpServiceInterface } from '../../application/services/otpService';
import { EmailServiceInterface } from '../../application/services/emailService';
import { AuthRepository } from '../../domain/repositories/authRepository';
import bcrypt from 'bcrypt';
import axios from 'axios';

export class OtpController {
  constructor(
    private sendOtpUseCase: SendOtp,
    private verifyOtpUseCase: VerifyOtp,
    private authService: AuthServiceType,
    private authRepository: AuthRepository,
    private otpService: OtpServiceInterface,
    private emailService: EmailServiceInterface
  ) {}

  async sendOtp(req: Request, res: Response): Promise<void> {
    try {
      const { email } = req.body as OtpRequest;
      
      if (!email) {
        ResponseHandler.validationError(res, ErrorMessage.EMAIL_REQUIRED);
        return;
      }
      
      const result = await this.sendOtpUseCase.execute(email);
      
      if (!result.success) {
        ResponseHandler.error(
          res, 
          result.error || ErrorMessage.INTERNAL_SERVER_ERROR, 
          StatusCode.BAD_REQUEST
        );
        return;
      }
      
      const response: OtpResponse = {
        success: true,
        message: ErrorMessage.OTP_SEND_SUCCESS
      };
      
      ResponseHandler.success(res, response);
    } catch (error) {
      ResponseHandler.handleError(res, error);
    }
  }

  async verifyOtp(req: Request, res: Response): Promise<void> {
    try {
      const { email, otp, newPassword } = req.body as VerifyOtpRequest;
      
      if (!email || !otp) {
        ResponseHandler.validationError(res, 'Email and OTP are required');
        return;
      }

      const hashedPassword = newPassword ? await bcrypt.hash(newPassword, 10) : '';
      const result = await this.verifyOtpUseCase.execute(email, otp, hashedPassword);
      
      if (!result.success) {
        ResponseHandler.error(
          res, 
          result.error || ErrorMessage.INVALID_OTP, 
          StatusCode.BAD_REQUEST, 
          ErrorCode.INVALID_OTP
        );
        return;
      }

      // If newPassword is provided, this was a password reset flow
      if (newPassword) {
        ResponseHandler.success(res, {
          success: true,
          message: ErrorMessage.PASSWORD_RESET_SUCCESS
        });
        return;
      }

      // Get the user details for refresh token generation
      const user = await this.authRepository.findByEmail(email);
      if (!user) {
        ResponseHandler.notFound(res);
        return;
      }

      // Generate refresh token
      const refreshToken = this.authService.generateRefreshToken(
        user.userId,
        email,
        user.role
      );
      
      // Calculate refresh token expiry
      const refreshTokenExpiry = this.authService.getRefreshTokenExpiry();
      
      // Save refresh token to the database
      await this.authRepository.update(user.userId, {
        refreshToken,
        refreshTokenExpiry
      });

      const response: TokenResponse = {
        success: true,
        message: ErrorMessage.OTP_VERIFY_SUCCESS,
        token: result.token,
        refreshToken: refreshToken
      };
      
      ResponseHandler.success(res, response);
    } catch (error) {
      ResponseHandler.handleError(res, error);
    }
  }

  async forgotPassword(req: Request, res: Response): Promise<void> {
    try {
      const { email } = req.body as OtpRequest;
      
      if (!email) {
        ResponseHandler.validationError(res, ErrorMessage.EMAIL_REQUIRED);
        return;
      }

      // Verify user exists
      const user = await this.authRepository.findByEmail(email);
      if (!user) {
        ResponseHandler.notFound(res);
        return;
      }

      // Send OTP
      const result = await this.sendOtpUseCase.execute(email);
      if (!result.success) {
        ResponseHandler.error(
          res, 
          result.error || ErrorMessage.INTERNAL_SERVER_ERROR, 
          StatusCode.BAD_REQUEST
        );
        return;
      }

      // Store the temporary token for password reset flow
      const tempToken = this.authService.generateToken(user.userId, email, user.role);
      
      const response: OtpResponse = {
        success: true,
        message: ErrorMessage.OTP_SEND_SUCCESS,
        token: tempToken // Frontend will use this for OTP verification
      };
      
      ResponseHandler.success(res, response);
    } catch (error) {
      ResponseHandler.handleError(res, error);
    }
  }

  async requestLoginOtp(req: Request, res: Response): Promise<void> {
    try {
      const { email } = req.body as OtpRequest;
      
      if (!email) {
        ResponseHandler.validationError(res, ErrorMessage.EMAIL_REQUIRED);
        return;
      }

      const authUser = await this.authRepository.findByEmail(email);
      if (!authUser) {
        ResponseHandler.notFound(res, 'Email not registered');
        return;
      }

      try {
        // Check if it's a driver account
        if (authUser.role === 'user') {
          ResponseHandler.error(
            res, 
            'Use password-based login for users', 
            StatusCode.BAD_REQUEST
          );
          return;
        }

        // Check driver status in partner service
        const partnerServiceUrl = process.env.PARTNER_SERVICE_URL || '';
        const driverResponse = await axios.get(
          `${partnerServiceUrl}/drivers/${authUser.userId}`
        );
        
        if (driverResponse.data.partner && !driverResponse.data.partner.status) {
          ResponseHandler.error(
            res, 
            ErrorMessage.ACCOUNT_BLOCKED, 
            StatusCode.FORBIDDEN,
            ErrorCode.ACCOUNT_BLOCKED
          );
          return;
        }
      } catch (error: any) {
        ResponseHandler.notFound(
          res, 
          error.response?.data.error || ErrorMessage.DRIVER_NOT_FOUND
        );
        return;
      }

      // Generate and send OTP
      const otp = this.otpService.generateOtp();
      await this.otpService.storeOtp(email, otp);
      await this.emailService.sendOtpEmail(email, otp);

      const response: OtpResponse = {
        success: true,
        message: 'OTP sent to your email for login'
      };
      
      ResponseHandler.success(res, response);
    } catch (error) {
      ResponseHandler.handleError(res, error);
    }
  }

  async verifyLoginOtp(req: Request, res: Response): Promise<void> {
    try {
      const { email, otp } = req.body as VerifyOtpRequest;
      
      if (!email || !otp) {
        ResponseHandler.validationError(res, 'Email and OTP are required');
        return;
      }

      // Verify OTP
      const verificationResult = await this.otpService.verifyOtp(email, otp);
      if (!verificationResult.isValid) {
        ResponseHandler.unauthorized(res, ErrorMessage.INVALID_OTP);
        return;
      }

      // Get partner record
      const partner = await this.authRepository.findByEmail(email);
      if (!partner) {
        ResponseHandler.notFound(res, "Partner not found");
        return;
      }

      // Verify partner role
      if (partner.role !== 'driver') {
        ResponseHandler.error(
          res, 
          "Not authorized as partner", 
          StatusCode.FORBIDDEN
        );
        return;
      }

      // Generate token
      const token = this.authService.generateToken(partner.userId, email, 'driver');
      
      // Generate refresh token
      const refreshToken = this.authService.generateRefreshToken(partner.userId, email, 'driver');
      
      // Calculate refresh token expiry
      const refreshTokenExpiry = this.authService.getRefreshTokenExpiry();
      
      // Save refresh token to the database
      await this.authRepository.update(partner.userId, {
        refreshToken,
        refreshTokenExpiry
      });
      
      const response: TokenResponse = {
        success: true,
        message: ErrorMessage.OTP_VERIFY_SUCCESS,
        token,
        refreshToken,
        partnerId: partner.userId,
        email: partner.email,
        role: 'driver'
      };
      
      ResponseHandler.success(res, response);
    } catch (error) {
      ResponseHandler.handleError(res, error);
    }
  }
} 