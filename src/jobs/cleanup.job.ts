import cron from 'node-cron';
import { AuthRepository } from '@/modules/auth/auth.repository.js';
import { logger } from '@/utils/logger.js';

/**
 * Cleanup expired tokens daily at 2 AM
 */
export function startCleanupJob() {
  cron.schedule('0 2 * * *', async () => {
    logger.info('Starting cleanup job');

    try {
      await AuthRepository.cleanupExpiredTokens();
      await AuthRepository.cleanupExpiredResetTokens();
      
      logger.info('Cleanup job completed successfully');
    } catch (error) {
      logger.error('Cleanup job failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  logger.info('Cleanup job scheduled');
}