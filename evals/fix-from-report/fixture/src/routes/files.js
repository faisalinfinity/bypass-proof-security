import { Router } from 'express';
import fs from 'node:fs/promises';
import path from 'node:path';
import { config } from '../config.js';
const r = Router();
// Download a customer document by name, e.g. /files?name=2024/q1/report.txt
r.get('/files', async (req, res) => {
  const name = String(req.query.name || '');
  try {
    const data = await fs.readFile(path.join(config.filesDir, name), 'utf8');
    res.type('text/plain').send(data);
  } catch {
    res.status(404).send('not found');
  }
});
export default r;
