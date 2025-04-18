export interface UserServiceInterface {
  createUserProfile(userData: {
    userId: string;
    email: string;
    fullName?: string;
    phone?: string;
    picture?: string;
    role: string;
  }): Promise<boolean>;

  getUserProfile(userId: string, token: string): Promise<any>;
  
  checkUserStatus(userId: string, token: string): Promise<boolean>;
} 