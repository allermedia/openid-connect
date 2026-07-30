import { OpenIDConnectError } from '../../src/errors.js';

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
});
