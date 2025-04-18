import { Request, Response } from 'express';
import { ResponseHandler } from '../utils/responseHandler';
import { StatusCode } from '../../types/enums/StatusCode';
import { ErrorMessage } from '../../types/enums/ErrorMessage';
import { DriverRegistrationRequest, EmailUpdateRequest } from '../../types/interfaces/requests';
import { PartnerServiceClient } from '../../infrastructure/clients/partnerServiceClient';
import { AuthServiceType } from '../../application/services/authService';
import { AuthRepository } from '../../domain/repositories/authRepository';

export class DriverAuthController {
  constructor(
    private authRepository: AuthRepository,
    private authService: AuthServiceType,
    private partnerServiceClient: PartnerServiceClient
  ) {}

  async registerDriver(req: Request, res: Response): Promise<void> {
    try {
      const { email, role, partnerId } = req.body as DriverRegistrationRequest;

      if (!email || !role || role !== 'driver') {
        ResponseHandler.validationError(res, 'Email and role=driver are required');
        return;
      }

      // Check if email already exists
      const existingUser = await this.authRepository.findByEmail(email);
      if (existingUser) {
        ResponseHandler.error(
          res, 
          ErrorMessage.EMAIL_ALREADY_EXISTS, 
          StatusCode.BAD_REQUEST
        );
        return;
      }

      // Store email and role directly in the database (no OTP)
      const authData: { userId: string; email: string; password: string; role: 'user' | 'driver' | 'admin' } = {
        userId: partnerId || `DRV-${this.authService.generateUserId()}`,
        email,
        password: '', // or generate a random password if needed
        role: 'driver',
      };

      await this.authRepository.create(authData);

      ResponseHandler.success(
        res, 
        {
          success: true,
          message: ErrorMessage.DRIVER_REGISTRATION_SUCCESS,
          user: { 
            email, 
            role: 'driver', 
            partnerId: authData.userId 
          }
        }, 
        StatusCode.CREATED
      );
    } catch (error) {
      ResponseHandler.handleError(res, error);
    }
  }

  async updateEmail(req: Request, res: Response): Promise<void> {
    try {
      const { partnerId } = req.params;
      const { email } = req.body as EmailUpdateRequest;

      if (!email) {
        ResponseHandler.validationError(res, ErrorMessage.EMAIL_REQUIRED);
        return;
      }

      // Check if email is already in use by another user
      const existingUser = await this.authRepository.findByEmail(email);
      if (existingUser && existingUser.userId !== partnerId) {
        ResponseHandler.error(
          res,
          'Email is already in use by another user',
          StatusCode.BAD_REQUEST
        );
        return;
      }

      // Update the email
      const updatedUser = await this.authRepository.updateEmail(partnerId, email);
      
      if (!updatedUser) {
        ResponseHandler.notFound(res);
        return;
      }

      ResponseHandler.success(res, {
        success: true,
        message: ErrorMessage.EMAIL_UPDATE_SUCCESS,
        user: {
          userId: updatedUser.userId,
          email: updatedUser.email,
          role: updatedUser.role
        }
      });
    } catch (error) {
      ResponseHandler.handleError(res, error);
    }
  }
} 