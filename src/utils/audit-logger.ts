import { prisma } from '../prisma/client.js';
import { logger } from './logger.js';

export enum AuditAction {
  USER_REGISTERED = 'USER_REGISTERED',
  USER_LOGIN = 'USER_LOGIN',
  USER_LOGOUT = 'USER_LOGOUT',
  TOKEN_REFRESHED = 'TOKEN_REFRESHED',
  PASSWORD_CHANGED = 'PASSWORD_CHANGED',
  LOGIN_FAILED = 'LOGIN_FAILED',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  PASSWORD_RESET_REQUESTED = 'PASSWORD_RESET_REQUESTED',
  PASSWORD_RESET_COMPLETED = 'PASSWORD_RESET_COMPLETED',
  PASSWORD_RESET_FAILED = 'PASSWORD_RESET_FAILED',
}

interface AuditLogData {
  action: AuditAction;
  userId?: string;
  email?: string;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: Record<string, any>;
  status: 'SUCCESS' | 'FAILURE';
}

export class AuditLogger {
  static async log(data: AuditLogData): Promise<void> {
    try {
      await prisma.auditLog.create({
        data: {
          action: data.action,
          userId: data.userId,
          email: data.email,
          ipAddress: data.ipAddress,
          userAgent: data.userAgent,
          metadata: data.metadata || {},
          status: data.status,
          timestamp: new Date(),
        },
      });

      logger.info('Audit log created', {
        action: data.action,
        userId: data.userId,
        email: data.email,
        status: data.status,
      });
    } catch (error) {
      logger.error('Failed to create audit log', {
        error: error instanceof Error ? error.message : 'Unknown error',
        auditData: data,
      });
    }
  }

  static async logSuccess(
    action: AuditAction,
    data: Omit<AuditLogData, 'action' | 'status'>
  ): Promise<void> {
    await this.log({ ...data, action, status: 'SUCCESS' });
  }

  static async logFailure(
    action: AuditAction,
    data: Omit<AuditLogData, 'action' | 'status'>
  ): Promise<void> {
    await this.log({ ...data, action, status: 'FAILURE' });
  }
}