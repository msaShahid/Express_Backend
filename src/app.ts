import express, {Application, Request, Response, NextFunction } from 'express'
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import authRoutes from "@/modules/auth/auth.routes.js";
import { errorHandler } from '@/middlewares/error.middleware.js';

const app: Application = express();

app.set('trust proxy', 1);
app.use(cors({
  origin: 'http://localhost:3000', // frontend URL
  credentials: true,               // allow cookies
}))
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
      },
    },
  })
);
app.use(cookieParser());
app.use(express.json());

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.use(errorHandler);

app.use("/api/auth", authRoutes);

app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

export default app;
