import { Response } from 'express';
import { StatusCode } from '../../types/enums/StatusCode';
import { ErrorMessage } from '../../types/enums/ErrorMessage';
import { ErrorCode } from '../../types/enums/ErrorCode';
import { BaseResponse } from '../../types/interfaces/responses';

export class ResponseHandler {
  /**
   * Send a success response
   */
  static success<T extends BaseResponse>(
    res: Response,
    data: T,
    statusCode: StatusCode = StatusCode.OK
  ): void {
    // Create a copy of data without the success property to avoid duplication
    const { success, ...restData } = data;
    
    res.status(statusCode).json({
      success: true,
      ...restData
    });
  }

  /**
   * Send an error response
   */
  static error(
    res: Response,
    message: string = ErrorMessage.INTERNAL_SERVER_ERROR,
    statusCode: StatusCode = StatusCode.INTERNAL_SERVER_ERROR,
    errorCode?: string,
    additionalData: Record<string, any> = {}
  ): void {
    res.status(statusCode).json({
      success: false,
      error: message,
      ...(errorCode && { errorCode }),
      ...additionalData
    });
  }

  /**
   * Handle common controller errors
   */
  static handleError(res: Response, error: any): void {
    console.error('Controller error:', error);
    this.error(res, ErrorMessage.INTERNAL_SERVER_ERROR, StatusCode.INTERNAL_SERVER_ERROR);
  }

  /**
   * Send a validation error response
   */
  static validationError(
    res: Response,
    message: string,
    additionalData: Record<string, any> = {}
  ): void {
    this.error(
      res,
      message,
      StatusCode.BAD_REQUEST,
      ErrorCode.VALIDATION_ERROR,
      additionalData
    );
  }

  /**
   * Send a not found error response
   */
  static notFound(
    res: Response,
    message: string = ErrorMessage.USER_NOT_FOUND,
    additionalData: Record<string, any> = {}
  ): void {
    this.error(
      res,
      message,
      StatusCode.NOT_FOUND,
      ErrorCode.USER_NOT_FOUND,
      additionalData
    );
  }

  /**
   * Send an unauthorized error response
   */
  static unauthorized(
    res: Response,
    message: string = ErrorMessage.INVALID_CREDENTIALS,
    errorCode: string = ErrorCode.UNAUTHORIZED,
    additionalData: Record<string, any> = {}
  ): void {
    this.error(
      res,
      message,
      StatusCode.UNAUTHORIZED,
      errorCode,
      additionalData
    );
  }
} 