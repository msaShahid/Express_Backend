import express, {Application, Request, Response, NextFunction } from 'express'
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import authRoutes from "@/modules/auth/auth.routes.js";

const app: Application = express();

app.set('trust proxy', 1);
app.use(
  cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
  })
);
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

app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error(err.message);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Somthing went wrong.'
  })
})

app.use("/api/auth", authRoutes);

app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

export default app;
