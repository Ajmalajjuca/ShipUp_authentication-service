import { AuthRepository } from '../repositories/authRepository';
import { AuthServiceType } from '../../application/services/authService';
import { UserServiceInterface } from '../../application/services/userServiceInterface';

export class GoogleAuthUser {
  constructor(
    private authRepository: AuthRepository,
    private authService: AuthServiceType,
    private userService: UserServiceInterface
  ) {}

  async execute(googlePayload: {
    email: string;
    name?: string;
    picture?: string;
  }) {
    try {
      // Check if user exists
      let user = await this.authRepository.findByEmail(googlePayload.email);
      let isNewUser = false;

      if (!user) {
        isNewUser = true;
        // Register new user
        const userData = {
          userId: `USR-${this.authService.generateUserId()}`,
          email: googlePayload.email,
          password: '', // Google authenticated users don't need password
          role: 'user',
        };

        try {
          // Create auth user
          user = await this.authRepository.create(userData);
          
          // Create user profile
          await this.userService.createUserProfile({
            userId: userData.userId,
            email: googlePayload.email,
            fullName: googlePayload.name || '',
            picture: googlePayload.picture || '',
            role: 'user'
          });
        } catch (error) {
          console.error('Error creating user:', error);          
          if (user && user.userId) {
            await this.authRepository.delete(userData.userId);
          }
          throw error;
        }
      }

      // Generate JWT token
      const token = this.authService.generateToken(user.userId, user.email, user.role);

      // Get user profile
      const userProfile = await this.userService.getUserProfile(user.userId, token);

      return {
        success: true,
        message: isNewUser ? 'User registered successfully' : 'Login successful',
        user: {
          ...user,
          ...(userProfile || {}),
          picture: googlePayload.picture || userProfile?.picture
        },
        token
      };
    } catch (error: any) {
      console.error('Google auth error:', error);
      return {
        success: false,
        error: error.message || 'Authentication failed'
      };
    }
  }
} 