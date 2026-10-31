import express from 'express';
import cors from 'cors';
import auth from './routes/auth.js';
import preview from './routes/preview.js';
import files from './routes/files.js';
import webhooks from './routes/webhooks.js';
import settings from './routes/settings.js';
import coupons from './routes/coupons.js';
export function createApp() {
  const app = express();
  app.use(cors({ origin: true, credentials: true }));
  for (const router of [webhooks, auth, preview, files, settings, coupons]) app.use(router);
  return app;
}
