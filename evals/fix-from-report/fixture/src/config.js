export const config = {
  appOrigin: process.env.APP_ORIGIN || 'https://app.example.com',      // the SPA that calls this API
  jwt: { secret: process.env.JWT_SECRET || 'dev-secret-change-me-0123456789abcdef', issuer: 'https://auth.acme.example', audience: 'acme-api' },
  webhookSecret: process.env.WEBHOOK_SECRET || 'whsec_dev_0123456789',
  filesDir: process.env.FILES_DIR || new URL('../data/files', import.meta.url).pathname,
};
