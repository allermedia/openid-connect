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
   */
  constructor(msg) {
    super(msg);
    this.statusCode = 401;
  }
}
