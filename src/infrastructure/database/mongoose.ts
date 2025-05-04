import mongoose from 'mongoose';

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/authentication-service';

export const connectDB = async () => {
  try {
    await mongoose.connect(MONGO_URI); // No need for deprecated options
    console.log('✅ MongoDB connected successfully');
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    process.exit(1); // Exit process if connection fails
  }

  mongoose.connection.on('disconnected', () => {
    console.warn('⚠️ MongoDB disconnected. Attempting to reconnect...');
    connectDB(); // Auto-reconnect
  });
};
