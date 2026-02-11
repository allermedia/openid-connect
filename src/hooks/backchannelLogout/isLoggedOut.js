import { getClient } from '../../client.js';

/**
 * Default hook that checks if the user has been logged out via Back-Channel Logout
 * @param {import('express').Request} req
 * @param {import('types').ConfigParams} config
 */
export default async function isLoggedOut(req, config) {
  // @ts-ignore
  const store = config.backchannelLogout?.store || config.session.store;
  const {
    issuer: { issuer },
  } = await getClient(config);
  const { sid, sub } = req.oidc.idTokenClaims;

  // Normalize issuer URL to handle trailing slashes consistently
  const normalizedIssuer = issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;

  if (!sid && !sub) {
    throw new Error(`The session must have a 'sid' or a 'sub'`);
  }

  // Try both normalized and non-normalized issuer URLs to handle inconsistencies
  const [logoutSid, logoutSidAlt, logoutSub, logoutSubAlt] = await Promise.all([
    sid && store.get(`${normalizedIssuer}|${sid}`),
    sid && store.get(`${normalizedIssuer}/|${sid}`),
    sub && store.get(`${normalizedIssuer}|${sub}`),
    sub && store.get(`${normalizedIssuer}/|${sub}`),
  ]);

  return !!(logoutSid || logoutSidAlt || logoutSub || logoutSubAlt);
}
