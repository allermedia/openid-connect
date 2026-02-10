import attemptSilentLogin from './src/middleware/attemptSilentLogin.js';
import auth from './src/middleware/auth.js';
import { requiresAuth, claimEquals, claimIncludes, claimCheck } from './src/middleware/requiresAuth.js';

export default {
  auth,
  requiresAuth,
  claimEquals,
  claimIncludes,
  claimCheck,
  attemptSilentLogin,
};

export { auth, attemptSilentLogin, requiresAuth, claimEquals, claimIncludes, claimCheck };
