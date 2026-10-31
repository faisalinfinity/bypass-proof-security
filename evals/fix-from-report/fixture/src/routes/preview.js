import { Router } from 'express';
const r = Router();
// Link previews for chat messages: fetch the page and return its <title>.
r.get('/api/preview', async (req, res) => {
  const url = String(req.query.url || '');
  try {
    const upstream = await fetch(url);
    const html = (await upstream.text()).slice(0, 200_000);
    const title = (html.match(/<title[^>]*>([^<]*)<\/title>/i) || [])[1] || null;
    res.json({ url, status: upstream.status, title, snippet: html.slice(0, 200) });
  } catch (e) {
    res.status(502).json({ error: 'fetch failed' });
  }
});
export default r;
