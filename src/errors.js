export class OpenIDConnectError extends Error {
  /**
   * @param {string} error
   * @param {string} [errorDescription]
   * @param {string} [errorUri]
   */
  constructor(error, errorDescription, errorUri) {
    super(errorDescription || error);
    this.error = error;
    this.error_description = errorDescription;
    this.error_uri = errorUri;
    this.statusCode = 400;
  }
}

export class OpenIDConnectBadRequest extends Error {
  /**
   * @param {string} message
   */
  constructor(message) {
    super(message);
    this.statusCode = 400;
  }
}

export class UnauthorizedError extends Error {
  /**
   * @param {string} msg
   * @param {Record<string, string>} [headers] response headers the error handler should apply, e.g. a `WWW-Authenticate` challenge
   */
  constructor(msg, headers) {
    super(msg);
    this.statusCode = 401;
    this.headers = headers || {};
  }
}

export class ForbiddenError extends Error {
  /**
   * Raised by the claim check middlewares (`claimEquals`, `claimIncludes`,
   * `claimCheck`) when the request is authenticated but the claim check fails.
   * @param {string} msg
   * @param {import('types').ForbiddenReason} [reason] what failed, e.g. `{ claim, expected, actual }`
   */
  constructor(msg, reason) {
    super(msg);
    this.statusCode = 403;
    this.reason = reason;
  }
}
