import { AuthRepository } from '../repositories/authRepository';
import { AuthService, AuthServiceType } from '../../application/services/authService';
import bcrypt from 'bcrypt';
import axios from 'axios';

interface LoginResult {
  success: boolean;
  error?: string;
  authUser?: {
    userId: string;
    email: string;
    role: string;
  };
  token?: string;
}

export class LoginUser {
  constructor(
    private authRepo: AuthRepository,
    private authService: AuthServiceType
  ) {}

  async execute(email: string, password: string): Promise<LoginResult> {
    try {
      const user = await this.authRepo.findByEmail(email);
      if (!user) {
        return { success: false, error: 'Invalid credentials' };
      }

      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        return { success: false, error: 'Invalid credentials' };
      }

      const token = this.authService.generateToken(user.userId, user.email, user.role);

      return {
        success: true,
        authUser: {
          userId: user.userId,
          email: user.email,
          role: user.role
        },
        token
      };
    } catch (error) {
      console.error('Login error:', error);
      return { success: false, error: 'Login failed' };
    }
  }
}