export default function attemptSilentLogin() {
  /**
   * Silent login
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @param {import('express').NextFunction} next
   */
  return function silentLoginHandler(req, res, next) {
    if (!req.oidc) {
      return next(new Error('req.oidc is not found, did you include the auth middleware?'));
    }

    return res.oidc.silentLogin();
  };
}
