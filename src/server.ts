import express from 'express';
import cors from 'cors';
import authRoutes from './presentation/routes/authRoutes';
import { connectDB } from './infrastructure/database/mongoose';
import dotenv from 'dotenv';
import { OAuth2Client } from "google-auth-library";
import morgan from 'morgan';


dotenv.config();

const app = express();

// Ensure GOOGLE_CLIENT_ID is available
if (!process.env.GOOGLE_CLIENT_ID) {
  console.error('GOOGLE_CLIENT_ID is not defined in environment variables');
  process.exit(1);
}

// Initialize Google OAuth client
const client = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET // Optional
});

export { client };

// Middleware
app.use(express.json()); // Add JSON body parser
app.use(express.urlencoded({ extended: true })); // Add URL-encoded body parser
app.use(morgan('dev')); 

app.use(cors({
  origin: ['http://localhost:5173', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Database connection
connectDB();

// Routes
app.use('/auth', authRoutes);

// Error handling middleware
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Authentication Service running on port ${PORT}`);
});