// Dependency container for Clean Architecture
import { AuthRepositoryImpl } from '../repositories/authRepositoryImpl';
import { AuthRepository } from '../../domain/repositories/authRepository';
import { AuthService, AuthServiceType } from '../../application/services/authService';
import { EmailService, EmailServiceInterface } from '../../application/services/emailService';
import { OtpService, OtpServiceInterface } from '../../application/services/otpService';
import { UserServiceClient } from '../clients/userServiceClient';
import { UserServiceInterface } from '../../application/services/userServiceInterface';
import { PartnerServiceClient } from '../clients/partnerServiceClient';
import { RegisterUser } from '../../domain/use-cases/registerUser';
import { LoginUser } from '../../domain/use-cases/loginUser';
import { SendOtp } from '../../domain/use-cases/sendOtp';
import { VerifyOtp } from '../../domain/use-cases/verifyOtp';
import { GoogleAuthUser } from '../../domain/use-cases/googleAuthUser';
import { OAuth2Client } from 'google-auth-library';
import { UserAuthController } from '../../presentation/controllers/userAuthController';
import { TokenController } from '../../presentation/controllers/tokenController';
import { OtpController } from '../../presentation/controllers/otpController';
import { SocialAuthController } from '../../presentation/controllers/socialAuthController';
import { DriverAuthController } from '../../presentation/controllers/driverAuthController';

// Create the OAuth client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Infrastructure layer dependencies
const authRepository: AuthRepository = new AuthRepositoryImpl();
const userServiceClient: UserServiceInterface = new UserServiceClient();
const partnerServiceClient = new PartnerServiceClient();

// Application services
const authService: AuthServiceType = new AuthService();
const otpService: OtpServiceInterface = new OtpService();
const emailService: EmailServiceInterface = new EmailService();

// Domain use cases
const registerUser = new RegisterUser(authRepository, authService, otpService, emailService);
const loginUser = new LoginUser(authRepository, authService);
const sendOtp = new SendOtp(authRepository, otpService, emailService);
const verifyOtp = new VerifyOtp(otpService, authService, authRepository);
const googleAuthUser = new GoogleAuthUser(authRepository, authService, userServiceClient);

// Controllers
export const userAuthController = new UserAuthController(
  registerUser,
  loginUser,
  authService,
  authRepository,
  userServiceClient
);

export const tokenController = new TokenController(
  authService,
  authRepository
);

export const otpController = new OtpController(
  sendOtp,
  verifyOtp,
  authService,
  authRepository,
  otpService,
  emailService
);

export const socialAuthController = new SocialAuthController(
  googleAuthUser,
  authService,
  authRepository,
  googleClient
);

export const driverAuthController = new DriverAuthController(
  authRepository,
  authService,
  partnerServiceClient
); 