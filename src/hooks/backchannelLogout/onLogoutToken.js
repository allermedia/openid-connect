/**
 * Default hook stores an entry in the logout store for `sid` (if available) and `sub` (if available).
 * @param {any} token
 * @param {import('types').ConfigParams} config
 */
export default async function onLogoutToken(token, config) {
  const {
    session: { absoluteDuration, rolling: rollingEnabled, rollingDuration, store },
    backchannelLogout,
  } = config;
  const backchannelLogoutStore = backchannelLogout?.store || store;
  const maxAge = (rollingEnabled ? Math.min(Number(absoluteDuration), Number(rollingDuration)) : Number(absoluteDuration)) * 1000;
  const payload = {
    // The "cookie" prop makes the payload compatible with
    // `express-session` stores.
    cookie: {
      expires: Date.now() + maxAge,
      maxAge,
    },
  };
  const { iss, sid, sub } = token;

  if (!sid && !sub) {
    throw new Error(`The Logout Token must have a 'sid' or a 'sub'`);
  }
  await Promise.all([
    sid && backchannelLogoutStore.set(`${iss}|${sid}`, payload),
    sub && backchannelLogoutStore.set(`${iss}|${sub}`, payload),
  ]);
}
