import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

export interface EmailServiceInterface {
  sendOtpEmail(email: string, otp: string): Promise<void>;
}

export class EmailService implements EmailServiceInterface {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT),
      secure: false, // Use TLS (false for 587, true for 465)
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }

  async sendOtpEmail(to: string, otp: string): Promise<void> {
    const subject = 'Verify Your ShipUp Account';
    const text = `Hello,\n\nThank you for joining ShipUp! Your One-Time Password (OTP) to verify your email is: ${otp}\n\nThis OTP is valid for 5 minutes. Please enter it in the app to complete your registration.\n\nRegards,\nAjmal - ShipUp Team`;
    const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
          }
          .container {
            max-width: 600px;
            margin: 20px auto;
            background-color: #ffffff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            overflow: hidden;
          }
          .header {
            background-color: #1e3a8a; /* indigo-900 */
            color: #ffffff;
            padding: 20px;
            text-align: center;
          }
          .logo {
            font-size: 24px;
            font-weight: bold;
          }
          .logo span {
            color: #f87171; /* red-400 */
          }
          .content {
            padding: 20px;
            color: #374151; /* gray-800 */
          }
          .otp {
            font-size: 24px;
            font-weight: bold;
            color: #1e3a8a; /* indigo-900 */
            text-align: center;
            margin: 20px 0;
          }
          .footer {
            background-color: #f3f4f6; /* gray-100 */
            padding: 10px;
            text-align: center;
            font-size: 14px;
            color: #6b7280; /* gray-500 */
          }
          .button {
            display: inline-block;
            padding: 10px 20px;
            background-color: #1e3a8a; /* indigo-900 */
            color: #ffffff;
            text-decoration: none;
            border-radius: 4px;
            margin-top: 20px;
          }
          .button:hover {
            background-color: #1e40af; /* indigo-800 */
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">
              Ship<span>Up</span>
            </div>
          </div>
          <div class="content">
            <h1>Welcome to ShipUp!</h1>
            <p>Hello,</p>
            <p>Thank you for joining ShipUp! To complete your registration, please use the following One-Time Password (OTP) to verify your email address:</p>
            <div class="otp">${otp}</div>
            <p>This OTP is valid for 5 minutes. Enter it in the ShipUp app to activate your account.</p>
            <a href="http://localhost:3000/otp-verification" class="button">Verify Now</a>
          </div>
          <div class="footer">
            <p>Regards,<br>Ajmal - ShipUp Team</p>
            <p>&copy; ${new Date().getFullYear()} ShipUp. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    const mailOptions = {
      from: `"ShipUp Team" <${process.env.SMTP_USER}>`,
      to,
      subject,
      text,
      html,
    };

    try {
      const info = await this.transporter.sendMail(mailOptions);
      console.log(`Email sent to ${to}: ${info.messageId}`);
    } catch (error) {
      console.error(`Error sending email to ${to}:`, error);
      throw new Error('Failed to send OTP email');
    }
  }
}