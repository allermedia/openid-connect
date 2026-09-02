import { ForbiddenError, OpenIDConnectError, UnauthorizedError } from '../../src/errors.js';

describe('errors', () => {
  it('OpenIDConnectError uses error description as message when provided', () => {
    const err = new OpenIDConnectError('access_denied', 'user said no', 'https://example.com/error');

    expect(err.message).to.equal('user said no');
    expect(err.error).to.equal('access_denied');
    expect(err.error_uri).to.equal('https://example.com/error');
    expect(err.statusCode).to.equal(400);
  });

  it('OpenIDConnectError falls back to error code as message', () => {
    const err = new OpenIDConnectError('access_denied');

    expect(err.message).to.equal('access_denied');
    expect(err.error_description).to.be.undefined;
  });

  it('ForbiddenError has status 403 and carries an optional reason', () => {
    const err = new ForbiddenError('Insufficient claims', { claim: 'roles', expected: ['Admin'], actual: ['User'] });

    expect(err.message).to.equal('Insufficient claims');
    expect(err.statusCode).to.equal(403);
    expect(err.reason).to.deep.equal({ claim: 'roles', expected: ['Admin'], actual: ['User'] });
    expect(new ForbiddenError('nope').reason).to.be.undefined;
  });

  it('UnauthorizedError has status 401 and defaults headers to an empty object', () => {
    const err = new UnauthorizedError('Authentication is required for this route.');

    expect(err.statusCode).to.equal(401);
    expect(err.headers).to.deep.equal({});
  });
});
