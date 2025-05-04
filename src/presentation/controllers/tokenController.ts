import { Request, Response } from 'express';
import { ResponseHandler } from '../utils/responseHandler';
import { StatusCode } from '../../types/enums/StatusCode';
import { ErrorMessage } from '../../types/enums/ErrorMessage';
import { ErrorCode } from '../../types/enums/ErrorCode';
import { RefreshTokenRequest, LogoutRequest, TempTokenRequest } from '../../types/interfaces/requests';
import { TokenResponse, VerifyTokenResponse } from '../../types/interfaces/responses';
import { AuthServiceType } from '../../application/services/authService';
import { AuthRepository } from '../../domain/repositories/authRepository';
import jwt from 'jsonwebtoken';

export class TokenController {
  constructor(
    private authService: AuthServiceType,
    private authRepository: AuthRepository
  ) {}

  async verifyToken(req: Request, res: Response): Promise<void> {
    try {
      const authHeader = req.headers.authorization;
      
      
      if (!authHeader) {
        ResponseHandler.unauthorized(res, ErrorMessage.TOKEN_REQUIRED);
        return;
      }

      const token = authHeader.split(' ')[1]; // Remove 'Bearer ' prefix
      
      if (!token) {
        ResponseHandler.unauthorized(res, ErrorMessage.INVALID_TOKEN);
        return;
      }

      try {
        // Verify token using auth service
        const decoded = await this.authService.verifyToken(token);
        
        const response: VerifyTokenResponse = { 
          success: true,
          valid: true, 
          user: {
            userId: decoded.userId,
            email: decoded.email,
            role: decoded.role
          }
        };
        
        ResponseHandler.success(res, response);
      } catch (error) {
        ResponseHandler.unauthorized(res, ErrorMessage.INVALID_TOKEN);
      }
    } catch (error) {
      ResponseHandler.handleError(res, error);
    }
  }

  async refreshToken(req: Request, res: Response): Promise<void> {
    try {
      const { refreshToken } = req.body as RefreshTokenRequest;
      
      if (!refreshToken) {
        ResponseHandler.error(
          res, 
          ErrorMessage.REFRESH_TOKEN_REQUIRED,
          StatusCode.BAD_REQUEST,
          ErrorCode.REFRESH_TOKEN_MISSING
        );
        return;
      }
      
      // Verify the refresh token
      let decoded;
      try {
        decoded = await this.authService.verifyRefreshToken(refreshToken);
      } catch (error) {
        ResponseHandler.unauthorized(
          res, 
          ErrorMessage.INVALID_REFRESH_TOKEN,
          ErrorCode.REFRESH_TOKEN_INVALID
        );
        return;
      }
      
      // Find the user in the database
      const user = await this.authRepository.findById(decoded.userId);
      
      if (!user) {
        ResponseHandler.notFound(res, ErrorMessage.USER_NOT_FOUND, {
          errorCode: ErrorCode.USER_NOT_FOUND
        });
        return;
      }
      
      // Check if the refresh token matches what's stored in the database
      if (!user.refreshToken || user.refreshToken !== refreshToken) {
        ResponseHandler.unauthorized(
          res, 
          ErrorMessage.INVALID_REFRESH_TOKEN,
          ErrorCode.REFRESH_TOKEN_MISMATCH,
          { tokenMismatch: true }
        );
        return;
      }
      
      // Check if the refresh token is expired in the database
      if (user.refreshTokenExpiry && new Date(user.refreshTokenExpiry) < new Date()) {
        ResponseHandler.unauthorized(
          res, 
          ErrorMessage.REFRESH_TOKEN_EXPIRED,
          ErrorCode.REFRESH_TOKEN_EXPIRED,
          { tokenExpired: true }
        );
        return;
      }
      
      // Generate new tokens
      const newAccessToken = this.authService.generateToken(user.userId, user.email, user.role);
      const newRefreshToken = this.authService.generateRefreshToken(user.userId, user.email, user.role);
      const refreshTokenExpiry = this.authService.getRefreshTokenExpiry();
      
      // Update the refresh token in the database
      await this.authRepository.update(user.userId, { 
        refreshToken: newRefreshToken,
        refreshTokenExpiry
      });
      
      const response: TokenResponse = {
        success: true,
        token: newAccessToken,
        refreshToken: newRefreshToken,
        user: {
          userId: user.userId,
          email: user.email,
          role: user.role
        }
      };
      
      ResponseHandler.success(res, response);
    } catch (error) {
      ResponseHandler.error(
        res, 
        ErrorMessage.INTERNAL_SERVER_ERROR,
        StatusCode.INTERNAL_SERVER_ERROR,
        ErrorCode.SERVER_ERROR
      );
    }
  }

  async logout(req: Request, res: Response): Promise<void> {
    try {
      const { userId } = req.body as LogoutRequest;
      
      if (!userId) {
        ResponseHandler.validationError(res, ErrorMessage.USER_ID_REQUIRED);
        return;
      }
      
      // Update the user record to clear the refresh token
      await this.authRepository.update(userId, {
        refreshToken: undefined,
        refreshTokenExpiry: undefined
      });
      
      ResponseHandler.success(res, {
        success: true,
        message: ErrorMessage.LOGOUT_SUCCESS
      });
    } catch (error) {
      ResponseHandler.handleError(res, error);
    }
  }

  async createTempToken(req: Request, res: Response): Promise<void> {
    try {
      const { purpose, role, userId, email } = req.body as TempTokenRequest;
      
      // If userId and email are provided, generate a normal token
      if (userId && email && role) {
        const token = this.authService.generateToken(userId, email, role);
        
        ResponseHandler.success(res, {
          success: true,
          token
        });
        return;
      }
      
      // For temporary token for specific purpose
      if (!purpose || !role) {
        ResponseHandler.validationError(res, 'Purpose and role are required');
        return;
      }

      if (purpose !== 'document-upload' || role !== 'partner') {
        ResponseHandler.validationError(res, 'Invalid purpose or role');
        return;
      }

      // Generate a short-lived token (5 minutes)
      const token = jwt.sign(
        { purpose, role },
        process.env.JWT_SECRET || 'your-secret-key',
        { expiresIn: '5m' }
      );

      ResponseHandler.success(res, {
        success: true,
        token
      });
    } catch (error) {
      ResponseHandler.handleError(res, error);
    }
  }

  async verifyPartnerToken(req: Request, res: Response): Promise<void> {
    const token = req.headers.authorization?.split(' ')[1];
    const { email } = req.body;
    console.log('Token:', token);
    console.log('Email:', email);
    
    try {
      

      if (!token || !email) {
        ResponseHandler.unauthorized(res, 'No token or email provided');
        return;
      }

      // Verify the token
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;
        console.log('Decoded:', decoded);
        
        // Check if the token belongs to the partner
        if (decoded.email !== email || decoded.role !== 'partner') {
          ResponseHandler.unauthorized(res, ErrorMessage.INVALID_TOKEN);
          return;
        }

        ResponseHandler.success(res, {
          success: true,
          message: 'Token is valid'
        });
      } catch (jwtError) {
        ResponseHandler.unauthorized(res, ErrorMessage.INVALID_TOKEN);
      }
    } catch (error) {
      ResponseHandler.handleError(res, error);
    }
  }
} 