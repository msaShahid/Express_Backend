import nodemailer from 'nodemailer';
import { logger } from './logger.js';

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

interface EmailOptions {
  to: string;
  subject: string;
  html: string;
  text?: string;
}

export class EmailService {
  static async sendEmail(options: EmailOptions): Promise<boolean> {
    try {
      await transporter.sendMail({
        from: `"${process.env.APP_NAME || 'MyApp'}" <${process.env.SMTP_FROM || process.env.SMTP_USER}>`,
        to: options.to,
        subject: options.subject,
        html: options.html,
        text: options.text,
      });

      logger.info('Email sent successfully', {
        to: options.to,
        subject: options.subject,
      });

      return true;
    } catch (error) {
      logger.error('Failed to send email', {
        error: error instanceof Error ? error.message : 'Unknown error',
        to: options.to,
        subject: options.subject,
      });
      return false;
    }
  }

  static async sendPasswordResetEmail(
    email: string,
    name: string,
    resetToken: string
  ): Promise<boolean> {
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
    const expiryMinutes = 15;

    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .button { 
            display: inline-block; 
            padding: 12px 24px; 
            background-color: #007bff; 
            color: #ffffff; 
            text-decoration: none; 
            border-radius: 4px; 
            margin: 20px 0;
          }
          .warning { color: #dc3545; font-size: 14px; margin-top: 20px; }
          .footer { margin-top: 30px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>Password Reset Request</h2>
          <p>Hi ${name},</p>
          <p>We received a request to reset your password. Click the button below to create a new password:</p>
          <a href="${resetUrl}" class="button">Reset Password</a>
          <p>Or copy and paste this link into your browser:</p>
          <p style="word-break: break-all;">${resetUrl}</p>
          <p class="warning">
            ⚠️ This link will expire in ${expiryMinutes} minutes.<br>
            If you didn't request this, please ignore this email.
          </p>
          <div class="footer">
            <p>For security reasons, never share this link with anyone.</p>
            <p>© ${new Date().getFullYear()} ${process.env.APP_NAME || 'MyApp'}. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    const text = `
      Password Reset Request
      
      Hi ${name},
      
      We received a request to reset your password. Click the link below to create a new password:
      
      ${resetUrl}
      
      This link will expire in ${expiryMinutes} minutes.
      
      If you didn't request this, please ignore this email.
      
      For security reasons, never share this link with anyone.
    `;

    return this.sendEmail({
      to: email,
      subject: 'Password Reset Request',
      html,
      text,
    });
  }

  static async sendPasswordChangedEmail(
    email: string,
    name: string
  ): Promise<boolean> {
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .success { color: #28a745; }
          .warning { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin: 20px 0; }
          .footer { margin-top: 30px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2 class="success">✓ Password Changed Successfully</h2>
          <p>Hi ${name},</p>
          <p>Your password has been changed successfully.</p>
          <div class="warning">
            <strong>⚠️ Security Alert</strong><br>
            If you didn't make this change, please contact our support team immediately.
          </div>
          <div class="footer">
            <p>© ${new Date().getFullYear()} ${process.env.APP_NAME || 'MyApp'}. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    const text = `
      Password Changed Successfully
      
      Hi ${name},
      
      Your password has been changed successfully.
      
      If you didn't make this change, please contact our support team immediately.
    `;

    return this.sendEmail({
      to: email,
      subject: 'Password Changed Successfully',
      html,
      text,
    });
  }
}