import { Request, Response } from 'express';
import { ResponseHandler } from '../utils/responseHandler';
import { StatusCode } from '../../types/enums/StatusCode';
import { ErrorMessage } from '../../types/enums/ErrorMessage';
import { ErrorCode } from '../../types/enums/ErrorCode';
import { GoogleLoginRequest } from '../../types/interfaces/requests';
import { GoogleAuthResponse } from '../../types/interfaces/responses';
import { GoogleAuthUser } from '../../domain/use-cases/googleAuthUser';
import { AuthServiceType } from '../../application/services/authService';
import { AuthRepository } from '../../domain/repositories/authRepository';
import { OAuth2Client } from "google-auth-library";

export class SocialAuthController {
  constructor(
    private googleAuthUserUseCase: GoogleAuthUser,
    private authService: AuthServiceType,
    private authRepository: AuthRepository,
    private googleClient: OAuth2Client
  ) {}

  async googleLogin(req: Request, res: Response): Promise<void> {
    try {
      const { credential } = req.body as GoogleLoginRequest;
      
      if (!credential) {
        ResponseHandler.validationError(res, ErrorMessage.GOOGLE_TOKEN_REQUIRED);
        return;
      }

      // Verify the Google token
      try {
        const ticket = await this.googleClient.verifyIdToken({
          idToken: credential,
          audience: process.env.GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
        
        if (!payload || !payload.email) {
          ResponseHandler.validationError(res, ErrorMessage.INVALID_GOOGLE_TOKEN);
          return;
        }

        const result = await this.googleAuthUserUseCase.execute({
          email: payload.email,
          name: payload.name,
          picture: payload.picture
        });

        if (!result.success) {
          ResponseHandler.error(
            res, 
            result.error || ErrorMessage.INTERNAL_SERVER_ERROR, 
            StatusCode.BAD_REQUEST
          );
          return;
        }

        // Generate refresh token
        const refreshToken = this.authService.generateRefreshToken(
          result.user.userId, 
          result.user.email, 
          result.user.role
        );
        
        // Calculate refresh token expiry
        const refreshTokenExpiry = this.authService.getRefreshTokenExpiry();
        
        // Save refresh token to the database
        await this.authRepository.update(result.user.userId, {
          refreshToken,
          refreshTokenExpiry
        });

        const response: GoogleAuthResponse = {
          ...result,
          refreshToken
        };

        ResponseHandler.success(res, response);
      } catch (verifyError: any) {
        console.error('Token verification error:', {
          error: verifyError.message,
          clientId: process.env.GOOGLE_CLIENT_ID,
          stack: verifyError.stack
        });
        
        ResponseHandler.unauthorized(
          res, 
          "Token verification failed: " + verifyError.message, 
          ErrorCode.UNAUTHORIZED
        );
      }
    } catch (error: any) {
      console.error('Google authentication error:', error);
      ResponseHandler.error(
        res, 
        "Authentication failed", 
        StatusCode.BAD_REQUEST
      );
    }
  }
} 