import { Request, Response } from 'express';
import { RegisterUser } from '../../domain/use-cases/registerUser';
import { LoginUser } from '../../domain/use-cases/loginUser';
import { AuthServiceType } from '../../application/services/authService';
import { UserServiceInterface } from '../../application/services/userServiceInterface';
import { ResponseHandler } from '../utils/responseHandler';
import { StatusCode } from '../../types/enums/StatusCode';
import { ErrorMessage } from '../../types/enums/ErrorMessage';
import { ErrorCode } from '../../types/enums/ErrorCode';
import { AuthRepository } from '../../domain/repositories/authRepository';
import { 
  RegisterRequest, 
  LoginRequest, 
  PasswordUpdateRequest, 
  VerifyPasswordRequest 
} from '../../types/interfaces/requests';
import { UserResponse, VerifyPasswordResponse } from '../../types/interfaces/responses';
import bcrypt from 'bcrypt';

export class UserAuthController {
  constructor(
    private registerUserUseCase: RegisterUser,
    private loginUserUseCase: LoginUser,
    private authService: AuthServiceType,
    private authRepository: AuthRepository,
    private userServiceClient: UserServiceInterface
  ) {}

  async register(req: Request, res: Response): Promise<void> {
    try {
      const { email, password, role, fullName, phone } = req.body as RegisterRequest;
      
      if (!email || !password || !role || !fullName || !phone) {
        ResponseHandler.validationError(res, ErrorMessage.ALL_FIELDS_REQUIRED);
        return;
      }

      // Ensure role is valid by casting to expected type
      const validRole = role as 'user' | 'partner';
      
      const result = await this.registerUserUseCase.execute(email, password, validRole, { fullName, phone });
      
      if (!result.success) {
        ResponseHandler.error(
          res, 
          result.error || ErrorMessage.INTERNAL_SERVER_ERROR, 
          StatusCode.BAD_REQUEST
        );
        return;
      }

      const response: UserResponse = {
        success: true,
        message: result.message,
        token: this.authService.generateToken(result.userId || '', email, role),
        user: { 
          email, 
          role, 
          fullName, 
          phone, 
          userId: result.userId || '' 
        }
      };

      ResponseHandler.success(res, response, StatusCode.CREATED);
    } catch (error) {
      ResponseHandler.handleError(res, error);
    }
  }

  async login(req: Request, res: Response): Promise<void> {
    try {
      const { email, password } = req.body as LoginRequest;
      
      if (!email || !password) {
        ResponseHandler.validationError(res, ErrorMessage.ALL_FIELDS_REQUIRED, {
          passwordError: true
        });
        return;
      }

      const result = await this.loginUserUseCase.execute(email, password);
      
      if (!result.success || !result.authUser || !result.token) {
        ResponseHandler.unauthorized(
          res, 
          ErrorMessage.INVALID_CREDENTIALS, 
          ErrorCode.PASSWORD_ERROR, 
          { passwordError: true }
        );
        return;
      }
      
      // Generate refresh token
      const refreshToken = this.authService.generateRefreshToken(
        result.authUser.userId, 
        result.authUser.email, 
        result.authUser.role
      );
      
      // Calculate refresh token expiry
      const refreshTokenExpiry = this.authService.getRefreshTokenExpiry();
      
      // Save refresh token to the database
      await this.authRepository.update(result.authUser.userId, {
        refreshToken,
        refreshTokenExpiry
      });

      // Try to get user details from user service
      try {
        const userProfile = await this.userServiceClient.getUserProfile(
          result.authUser.userId, 
          result.token
        );

        console.log('User profile:', userProfile);
        

        if (userProfile && !userProfile.status) {
          ResponseHandler.error(
            res, 
            ErrorMessage.ACCOUNT_BLOCKED, 
            StatusCode.FORBIDDEN, 
            ErrorCode.ACCOUNT_BLOCKED
          );
          return;
        }

        const response: UserResponse = {
          success: true,
          message: ErrorMessage.LOGIN_SUCCESS,
          token: result.token,
          refreshToken,
          user: {
            ...result.authUser,
            ...userProfile
          }
        };
        
        ResponseHandler.success(res, response);
      } catch (error) {
        // If user service is unavailable, return minimal info
        const response: UserResponse = {
          success: true,
          message: ErrorMessage.LOGIN_SUCCESS,
          token: result.token,
          refreshToken,
          user: result.authUser
        };
        
        ResponseHandler.success(res, response);
      }
    } catch (error) {
      ResponseHandler.handleError(res, error);
    }
  }

  async verifyPassword(req: Request, res: Response): Promise<void> {
    try {
      const { userId, password } = req.body as VerifyPasswordRequest;
      
      const user = await this.authRepository.findById(userId);
      
      if (!user) {
        ResponseHandler.notFound(res);
        return;
      }

      const isValid = await bcrypt.compare(password, user.password);
      
      const response: VerifyPasswordResponse = { success: isValid };
      ResponseHandler.success(res, response);
    } catch (error) {
      ResponseHandler.handleError(res, error);
    }
  }

  async updatePassword(req: Request, res: Response): Promise<void> {
    try {
      const { userId, currentPassword, newPassword } = req.body as PasswordUpdateRequest;
      
      const user = await this.authRepository.findById(userId);
      
      if (!user) {
        ResponseHandler.notFound(res, ErrorMessage.USER_NOT_FOUND, { passwordError: true });
        return;
      }
      
      const isValid = await bcrypt.compare(currentPassword, user.password);
      
      if (isValid) {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await this.authRepository.updatePassword(userId, hashedPassword);
        
        ResponseHandler.success(res, { 
          success: true, 
          message: ErrorMessage.PASSWORD_UPDATE_SUCCESS 
        });
      } else {
        ResponseHandler.error(
          res,
          ErrorMessage.CURRENT_PASSWORD_INCORRECT,
          StatusCode.BAD_REQUEST,
          ErrorCode.PASSWORD_ERROR,
          { passwordError: true }
        );
      }
    } catch (error) {
      console.error('Password update error:', error);
      ResponseHandler.error(
        res,
        ErrorMessage.PASSWORD_UPDATE_FAILED,
        StatusCode.INTERNAL_SERVER_ERROR,
        ErrorCode.SERVER_ERROR,
        { passwordError: true }
      );
    }
  }

  async delete(req: Request, res: Response): Promise<void> {
    try {
      const { userId } = req.params;
      await this.authRepository.delete(userId);
      
      ResponseHandler.success(res, { 
        success: true, 
        message: 'User deleted' 
      });
    } catch (error) {
      ResponseHandler.handleError(res, error);
    }
  }
} 