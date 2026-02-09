import app from './app.js';
import fs from 'fs';
import path from 'path';
import { logger } from './utils/logger.js';
import { prisma } from './prisma/client.js';
import { startCleanupJob } from './jobs/cleanup.job.js';

const PORT = process.env.PORT || 4000;

const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir);
}

const gracefulShutdown = async () => {
  logger.info('Shutting down gracefully...');
  await prisma.$disconnect();
  process.exit(0);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  
  // Start cleanup job
  startCleanupJob(); 

});