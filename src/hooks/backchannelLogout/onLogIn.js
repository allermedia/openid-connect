import { getClient } from '../../client.js';

/**
 * Remove any Back-Channel Logout tokens for this `sub` and `sid`
 * @param {import('express').Request} req
 * @param {import('types').ConfigParams} config
 */
export default async function onLogIn(req, config) {
  const {
    issuer: { issuer },
  } = await getClient(config);
  const { session, backchannelLogout } = config;
  const store = backchannelLogout && typeof backchannelLogout === 'object' ? backchannelLogout.store : session.store;

  // Get the sub and sid from the ID token claims
  const { sub, sid } = req.oidc.idTokenClaims;

  // Normalize issuer URL to handle trailing slashes consistently
  const normalizedIssuer = issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;

  // Remove both sub and sid based entries for both normalized and non-normalized issuer URLs
  const keys = [
    `${normalizedIssuer}|${sub}`,
    `${normalizedIssuer}/|${sub}`,
    sid && `${normalizedIssuer}|${sid}`,
    sid && `${normalizedIssuer}/|${sid}`,
  ].filter(Boolean);

  await Promise.all(keys.map((key) => store.destroy(key)));
}
