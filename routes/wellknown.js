import { Router } from 'express';
import { publishedJwks } from '../lib/keys.js';

const router = Router();

router.get('/.well-known/jwks.json', async (req, res, next) => {
  try {
    // Only rows' `public_jwk` is read; private material never leaves the DB.
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.json(await publishedJwks());
  } catch (err) {
    next(err);
  }
});

export default router;
