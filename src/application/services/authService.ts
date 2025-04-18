import jwt, { SignOptions } from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

export interface AuthServiceType {
  generateToken(userId: string, email: string, role: string): string;
  generateRefreshToken(userId: string, email: string, role: string): string;
  verifyToken(token: string): Promise<any>;
  verifyRefreshToken(token: string): Promise<any>;
  getRefreshTokenExpiry(): Date;
  generateUserId(): string;
}

export class AuthService implements AuthServiceType {
  private readonly jwtSecret: string;
  private readonly jwtExpiresIn: string;
  private readonly refreshSecret: string;
  private readonly refreshExpiresIn: string;

  constructor() {
    this.jwtSecret = process.env.JWT_SECRET || 'your-secret-key';
    this.jwtExpiresIn = process.env.JWT_EXPIRES_IN || '1h';
    this.refreshSecret = process.env.REFRESH_TOKEN_SECRET || 'your-refresh-secret-key';
    this.refreshExpiresIn = process.env.REFRESH_TOKEN_EXPIRES_IN || '7d';
  }

  generateToken(userId: string, email: string, role: string): string {
    const payload = { userId, email, role };
    const expiresIn: SignOptions['expiresIn'] = isNaN(Number(this.jwtExpiresIn)) ? this.jwtExpiresIn as SignOptions['expiresIn'] : Number(this.jwtExpiresIn);
    const options: SignOptions = { expiresIn };
    return jwt.sign(payload, this.jwtSecret, options);
  }

  generateRefreshToken(userId: string, email: string, role: string): string {
    const payload = { userId, email, role };
    const expiresIn: SignOptions['expiresIn'] = isNaN(Number(this.refreshExpiresIn)) ? this.refreshExpiresIn as SignOptions['expiresIn'] : Number(this.refreshExpiresIn);
    const options: SignOptions = { expiresIn };
    return jwt.sign(payload, this.refreshSecret, options);
  }

  getRefreshTokenExpiry(): Date {
    const expiresIn = isNaN(Number(this.refreshExpiresIn)) 
      ? this.refreshExpiresIn as string
      : `${Number(this.refreshExpiresIn)}ms`;
    
    // Parse the expiresIn value
    const match = expiresIn.match(/^(\d+)([smhdwy])$/);
    if (match) {
      const value = parseInt(match[1], 10);
      const unit = match[2];
      
      const now = new Date();
      switch (unit) {
        case 's': return new Date(now.getTime() + value * 1000);
        case 'm': return new Date(now.getTime() + value * 60 * 1000);
        case 'h': return new Date(now.getTime() + value * 60 * 60 * 1000);
        case 'd': return new Date(now.getTime() + value * 24 * 60 * 60 * 1000);
        case 'w': return new Date(now.getTime() + value * 7 * 24 * 60 * 60 * 1000);
        case 'y': return new Date(now.getTime() + value * 365 * 24 * 60 * 60 * 1000);
      }
    }
    
    // Default to 7 days if parsing fails
    return new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  }

  generateUserId(): string {
    return uuidv4();
  }

  async verifyToken(token: string): Promise<any> {
    try {
      const decoded = jwt.verify(token, this.jwtSecret);
      return decoded;
    } catch (error) {
      throw new Error('Invalid token');
    }
  }

  async verifyRefreshToken(token: string): Promise<any> {
    try {
      const decoded = jwt.verify(token, this.refreshSecret);
      return decoded;
    } catch (error) {
      throw new Error('Invalid refresh token');
    }
  }
}