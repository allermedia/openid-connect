import { getConfig } from '../src/config.js';

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  issuerBaseURL: 'https://op.example.com',
  baseURL: 'https://example.org',
};

function validateAuthorizationParams(authorizationParams) {
  return getConfig({ ...defaultConfig, authorizationParams });
}

describe('get config', () => {
  it('should get config for default config', () => {
    const config = getConfig(defaultConfig);
    expect(config).to.deep.include({
      authorizationParams: {
        response_type: 'code',
        scope: 'openid profile email',
      },
      authRequired: true,
    });
  });

  it('should get config for response_type=code', () => {
    const config = getConfig({
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      authorizationParams: {
        response_type: 'code',
      },
    });
    expect(config).to.deep.include({
      authorizationParams: {
        response_type: 'code',
        scope: 'openid profile email',
      },
      authRequired: true,
    });
  });

  it('should require a fully qualified URL for issuer', () => {
    const config = {
      ...defaultConfig,
      issuerBaseURL: 'www.example.com',
    };
    expect(() => getConfig(config)).to.throw(TypeError, '"issuerBaseURL" must be a valid uri');
  });

  it('should set default route paths', () => {
    const config = getConfig(defaultConfig);
    expect(config.routes).to.deep.include({
      callback: '/callback',
      login: '/login',
      logout: '/logout',
    });
  });

  it('should set custom route paths', () => {
    const config = getConfig({
      ...defaultConfig,
      routes: {
        callback: '/custom-callback',
        login: '/custom-login',
        logout: '/custom-logout',
      },
    });
    expect(config.routes).to.deep.include({
      callback: '/custom-callback',
      login: '/custom-login',
      logout: '/custom-logout',
    });
  });

  it('should set default app session configuration for http', () => {
    const config = getConfig({
      ...defaultConfig,
      baseURL: 'http://example.com',
    });
    expect(config.session).to.deep.include({
      rollingDuration: 86400,
      name: 'appSession',
      cookie: {
        sameSite: 'Lax',
        httpOnly: true,
        transient: false,
        secure: false,
      },
    });
  });

  it('should set default app session configuration for https', () => {
    const config = getConfig({
      ...defaultConfig,
      baseURL: 'https://example.com',
    });
    expect(config.session).to.deep.include({
      rollingDuration: 86400,
      name: 'appSession',
      cookie: {
        sameSite: 'Lax',
        httpOnly: true,
        transient: false,
        secure: true,
      },
    });
  });

  it('should set custom cookie configuration', () => {
    const sessionIdGenerator = () => '1235';
    const config = getConfig({
      ...defaultConfig,
      secret: ['__test_session_secret_1__', '__test_session_secret_2__'],
      session: {
        name: '__test_custom_session_name__',
        rollingDuration: 1234567890,
        genid: sessionIdGenerator,
        cookie: {
          domain: '__test_custom_domain__',
          transient: true,
          httpOnly: false,
          secure: true,
          sameSite: 'strict',
        },
      },
    });

    expect(config).to.deep.include({
      secret: ['__test_session_secret_1__', '__test_session_secret_2__'],
      transactionCookie: {
        sameSite: 'strict',
        name: 'auth_verification',
      },
      session: {
        name: '__test_custom_session_name__',
        rollingDuration: 1234567890,
        absoluteDuration: 604800,
        rolling: true,
        genid: sessionIdGenerator,
        requireSignedSessionStoreCookie: false,
        signSessionStoreCookie: false,
        cookie: {
          domain: '__test_custom_domain__',
          transient: true,
          httpOnly: false,
          secure: true,
          sameSite: 'strict',
        },
      },
    });
  });

  it('should validate session name', () => {
    const validNames = ['mySession', 'my-session', 'my_session', '__Host-mysession', 'mySession123', 'my.session'];
    const invalidNames = [
      'my session',
      'my;session',
      'mysession?',
      'my{session}',
      '<my_session>',
      'my@session',
      'mySession:123',
      'my=session',
    ];

    for (const name of validNames) {
      expect(() => {
        getConfig({ ...defaultConfig, session: { name } });
      }, name).to.not.throw();
    }
    for (const name of invalidNames) {
      expect(() => {
        getConfig({ ...defaultConfig, session: { name } });
      }, name).to.throw();
    }
  });

  it('should set default transaction cookie sameSite configuration', () => {
    const config = getConfig({
      ...defaultConfig,
      secret: ['__test_session_secret_1__', '__test_session_secret_2__'],
    });

    expect(config).to.deep.include({
      secret: ['__test_session_secret_1__', '__test_session_secret_2__'],
      transactionCookie: {
        sameSite: 'Lax',
        name: 'auth_verification',
      },
    });
  });

  it('should set default transaction cookie sameSite configuration from session cookie configuration', () => {
    const config = getConfig({
      ...defaultConfig,
      secret: ['__test_session_secret_1__', '__test_session_secret_2__'],
      session: {
        cookie: {
          sameSite: 'Strict',
        },
      },
    });

    expect(config).to.deep.include({
      secret: ['__test_session_secret_1__', '__test_session_secret_2__'],
      transactionCookie: {
        sameSite: 'strict',
        name: 'auth_verification',
      },
    });
  });

  it('should set custom transaction cookie configuration', () => {
    const config = getConfig({
      ...defaultConfig,
      secret: ['__test_session_secret_1__', '__test_session_secret_2__'],
      transactionCookie: {
        sameSite: 'Strict',
        name: 'CustomTxnCookie',
      },
      session: {
        cookie: {
          sameSite: 'Lax',
        },
      },
    });

    expect(config).to.deep.include({
      secret: ['__test_session_secret_1__', '__test_session_secret_2__'],
      transactionCookie: {
        sameSite: 'Strict',
        name: 'CustomTxnCookie',
      },
    });
  });

  it('should fail when the baseURL is http and cookie is secure', () => {
    expect(() => {
      getConfig({
        ...defaultConfig,
        baseURL: 'http://example.com',
        session: { cookie: { secure: true } },
      });
    }).to.throw('Cookies set with the `Secure` property wont be attached to http requests');
  });

  it('should fail when the baseURL is invalid', () => {
    expect(() => {
      getConfig({
        ...defaultConfig,
        baseURL: '__invalid_url__',
      });
    }).to.throw('"baseURL" must be a valid uri');
  });

  it('should fail when the clientID is not provided', () => {
    expect(() => {
      getConfig({
        ...defaultConfig,
        clientID: undefined,
      });
    }).to.throw('"clientID" is required');
  });

  it('should fail when the baseURL is not provided', () => {
    expect(() => {
      getConfig({
        ...defaultConfig,
        baseURL: undefined,
      });
    }).to.throw('"baseURL" is required');
  });

  it('should fail when the secret is not provided', () => {
    expect(() => {
      getConfig({
        ...defaultConfig,
        secret: undefined,
      });
    }).to.throw('"secret" is required');
  });

  it('should fail when app session length is not an integer', () => {
    expect(() => {
      getConfig({
        ...defaultConfig,
        session: {
          rollingDuration: 3.14159,
        },
      });
    }).to.throw('"session.rollingDuration" must be an integer');
  });

  it('should fail when rollingDuration is defined and rolling is false', () => {
    expect(() => {
      getConfig({
        ...defaultConfig,
        session: {
          rolling: false,
          rollingDuration: 100,
        },
      });
    }).to.throw('"session.rollingDuration" must be false when "session.rolling" is disabled');
  });

  it('should fail when rollingDuration is not defined and rolling is true', () => {
    expect(() => {
      getConfig({
        ...defaultConfig,
        session: {
          rolling: true,
          rollingDuration: false,
        },
      });
    }).to.throw('"session.rollingDuration" must be provided an integer value when "session.rolling" is true');
  });

  it('should fail when absoluteDuration is not defined and rolling is false', () => {
    expect(() => {
      getConfig({
        ...defaultConfig,
        session: {
          rolling: false,
          absoluteDuration: false,
        },
      });
    }).to.throw('"session.absoluteDuration" must be provided an integer value when "session.rolling" is false');
  });

  it('should fail when app session secret is invalid', () => {
    expect(() => {
      getConfig({
        ...defaultConfig,
        secret: { key: '__test_session_secret__' },
      });
    }).to.throw('"secret" must be one of [string, binary, array]');
  });

  it('should fail when app session cookie httpOnly is not a boolean', () => {
    expect(() => {
      getConfig({
        ...defaultConfig,
        session: {
          cookie: {
            httpOnly: '__invalid_httponly__',
          },
        },
      });
    }).to.throw('"session.cookie.httpOnly" must be a boolean');
  });

  it('should fail when app session cookie secure is not a boolean', () => {
    expect(() => {
      getConfig({
        ...defaultConfig,
        secret: '__test_session_secret__',
        session: {
          cookie: {
            secure: '__invalid_secure__',
          },
        },
      });
    }).to.throw('"session.cookie.secure" must be a boolean');
  });

  it('should fail when app session cookie sameSite is invalid', () => {
    expect(() => {
      getConfig({
        ...defaultConfig,
        secret: '__test_session_secret__',
        session: {
          cookie: {
            sameSite: '__invalid_samesite__',
          },
        },
      });
    }).to.throw('"session.cookie.sameSite" must be one of [lax, strict, none]');
  });

  it('should fail when app session cookie domain is invalid', () => {
    expect(() => {
      getConfig({
        ...defaultConfig,
        secret: '__test_session_secret__',
        session: {
          cookie: {
            domain: false,
          },
        },
      });
    }).to.throw('"session.cookie.domain" must be a string');
  });

  it('should fail when http timeout is invalid', () => {
    expect(() => {
      getConfig({
        ...defaultConfig,
        httpTimeout: 'abcd',
      });
    }).to.throw('"httpTimeout" must be a number');

    expect(() => {
      getConfig({
        ...defaultConfig,
        httpTimeout: '-100',
      });
    }).to.throw('"httpTimeout" must be greater than or equal to 500');

    expect(() => {
      getConfig({
        ...defaultConfig,
        httpTimeout: '499',
      });
    }).to.throw('"httpTimeout" must be greater than or equal to 500');
  });

  it("shouldn't allow a secret of less than 8 chars", () => {
    expect(() => getConfig({ ...defaultConfig, secret: 'short' })).to.throw(TypeError, '"secret" does not match any of the allowed types');
    expect(() => getConfig({ ...defaultConfig, secret: ['short', 'too'] })).to.throw(
      TypeError,
      '"secret[0]" does not match any of the allowed types'
    );
    expect(() => getConfig({ ...defaultConfig, secret: Buffer.from('short') })).to.throw(TypeError, '"secret" must be at least 8 bytes');
  });

  it('should allow code flow without client secret (public client with PKCE)', () => {
    const config = {
      ...defaultConfig,
      authorizationParams: {
        response_type: 'code',
      },
    };
    const result = getConfig(config);
    expect(result.clientAuthMethod).to.equal('none');
  });

  it('should allow hybrid flow without client secret (public client with PKCE)', () => {
    const config = {
      ...defaultConfig,
      authorizationParams: {
        response_type: 'code id_token',
      },
    };
    const result = getConfig(config);
    expect(result.clientAuthMethod).to.equal('none');
  });

  it('should allow code flow with explicit clientAuthMethod "none" (public client with PKCE)', () => {
    const config = {
      ...defaultConfig,
      authorizationParams: {
        response_type: 'code',
      },
      clientAuthMethod: 'none',
    };
    const result = getConfig(config);
    expect(result.clientAuthMethod).to.equal('none');
  });

  it('should require "clientAssertionSigningKey" when clientAuthMethod is "private_key_jwt"', () => {
    const config = {
      ...defaultConfig,
      authorizationParams: {
        response_type: 'code',
      },
      clientAuthMethod: 'private_key_jwt',
    };
    expect(() => getConfig(config)).to.throw(
      TypeError,
      '"clientAssertionSigningKey" is required for a "clientAuthMethod" of "private_key_jwt"'
    );
  });

  it('should default to "private_key_jwt" when "clientAssertionSigningKey" is present', () => {
    const config = {
      ...defaultConfig,
      authorizationParams: {
        response_type: 'code',
      },
      clientAssertionSigningKey: 'foo',
    };
    expect(getConfig(config).clientAuthMethod).to.equal('private_key_jwt');
  });

  it('should not allow "none" for idTokenSigningAlg', () => {
    const config = (idTokenSigningAlg) =>
      getConfig({
        ...defaultConfig,
        idTokenSigningAlg,
      });
    const expected = '"idTokenSigningAlg" contains an invalid value';
    expect(() => config('none')).to.throw(TypeError, expected);
    expect(() => config('NONE')).to.throw(TypeError, expected);
    expect(() => config('noNE')).to.throw(TypeError, expected);
  });

  // Test HMAC requirement with code flow instead
  it('should require clientSecret for ID tokens with HMAC based algorithms', () => {
    const config = {
      ...defaultConfig,
      idTokenSigningAlg: 'HS256',
      authorizationParams: {
        response_type: 'code',
      },
    };
    expect(() => getConfig(config)).to.throw(TypeError, '"clientSecret" is required for ID tokens with HMAC based algorithms');
  });

  it('should require clientSecret for ID tokens in hybrid flow with HMAC based algorithms', () => {
    const config = {
      ...defaultConfig,
      idTokenSigningAlg: 'HS256',
      authorizationParams: {
        response_type: 'code id_token',
      },
    };
    expect(() => getConfig(config)).to.throw(TypeError, '"clientSecret" is required for ID tokens with HMAC based algorithms');
  });

  it('should require clientSecret for ID tokens in code flow with HMAC based algorithms', () => {
    const config = {
      ...defaultConfig,
      idTokenSigningAlg: 'HS256',
      authorizationParams: {
        response_type: 'code',
      },
    };
    expect(() => getConfig(config)).to.throw(TypeError, '"clientSecret" is required for ID tokens with HMAC based algorithms');
  });

  it('should allow empty auth params', () => {
    expect(validateAuthorizationParams).to.not.throw();
    expect(() => validateAuthorizationParams({})).to.not.throw();
  });

  it('should not allow empty scope', () => {
    expect(() => validateAuthorizationParams({ scope: null })).to.throw(TypeError, '"authorizationParams.scope" must be a string');
    expect(() => validateAuthorizationParams({ scope: '' })).to.throw(TypeError, '"authorizationParams.scope" is not allowed to be empty');
  });

  it('should not allow scope without openid', () => {
    expect(() => validateAuthorizationParams({ scope: 'profile email' })).to.throw(
      TypeError,
      '"authorizationParams.scope" with value "profile email" fails to match the contains openid pattern'
    );
  });

  it('should allow scope with openid', () => {
    expect(() => validateAuthorizationParams({ scope: 'openid read:users' })).to.not.throw();
    expect(() => validateAuthorizationParams({ scope: 'read:users openid' })).to.not.throw();
    expect(() => validateAuthorizationParams({ scope: 'read:users openid profile email' })).to.not.throw();
  });

  it('should not allow empty response_type', () => {
    expect(() => validateAuthorizationParams({ response_type: null })).to.throw(
      TypeError,
      '"authorizationParams.response_type" must be one of [code id_token, code]'
    );
    expect(() => validateAuthorizationParams({ response_type: '' })).to.throw(
      TypeError,
      '"authorizationParams.response_type" must be one of [code id_token, code]'
    );
  });

  it('should not allow invalid response_types', () => {
    expect(() => validateAuthorizationParams({ response_type: 'foo' })).to.throw(
      TypeError,
      '"authorizationParams.response_type" must be one of [code id_token, code]'
    );
    expect(() => validateAuthorizationParams({ response_type: 'foo id_token' })).to.throw(
      TypeError,
      '"authorizationParams.response_type" must be one of [code id_token, code]'
    );

    expect(() => validateAuthorizationParams({ response_type: 'id_token code' })).to.throw(
      TypeError,
      '"authorizationParams.response_type" must be one of [code id_token, code]'
    );

    expect(() => validateAuthorizationParams({ response_type: 'id_token' })).to.throw(
      TypeError,
      '"authorizationParams.response_type" must be one of [code id_token, code]'
    );
  });

  it('should allow valid response_types', () => {
    const config = (authorizationParams) => ({
      ...defaultConfig,
      clientSecret: 'foo',
      authorizationParams,
    });

    expect(() => config({ response_type: 'code id_token' })).to.not.throw();
    expect(() => config({ response_type: 'code' })).to.not.throw();
  });

  it('should not allow empty response_mode', () => {
    expect(() => validateAuthorizationParams({ response_mode: null })).to.throw(
      TypeError,
      '"authorizationParams.response_mode" must be one of [query, form_post]'
    );
    expect(() => validateAuthorizationParams({ response_mode: '' })).to.throw(
      TypeError,
      '"authorizationParams.response_mode" must be one of [query, form_post]'
    );
    expect(() =>
      validateAuthorizationParams({
        response_type: 'code',
        response_mode: '',
      })
    ).to.throw(TypeError, '"authorizationParams.response_mode" must be one of [query, form_post]');
  });

  it('should not allow response_type code id_token and response_mode query', () => {
    expect(() =>
      validateAuthorizationParams({
        response_type: 'code id_token',
        response_mode: 'query',
      })
    ).to.throw(TypeError, '"authorizationParams.response_mode" must be [form_post]');
  });

  it('should allow valid response_type response_mode combinations', () => {
    const config = (authorizationParams) => ({
      ...defaultConfig,
      clientSecret: 'foo',
      authorizationParams,
    });
    expect(() => config({ response_type: 'code', response_mode: 'query' })).to.not.throw();
    expect(() => config({ response_type: 'code', response_mode: 'form_post' })).to.not.throw();

    expect(() => config({ response_type: 'code id_token', response_mode: 'form_post' })).to.not.throw();
  });

  it('should allow valid httpTimeout configuration', () => {
    const config = (httpTimeout) => ({
      ...defaultConfig,
      httpTimeout,
    });

    expect(() => config(5000)).to.not.throw();
    expect(() => config(10000)).to.not.throw();
    expect(() => config('5000')).to.not.throw();
    expect(() => config('10000')).to.not.throw();
  });

  it('should default clientAuthMethod to none when no clientSecret is provided', () => {
    const config = getConfig(defaultConfig);
    expect(config).to.deep.include({
      clientAuthMethod: 'none',
    });
  });

  it('should default clientAuthMethod to client_secret_post when clientSecret is provided', () => {
    const config = getConfig({
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
    });
    expect(config).to.deep.include({
      clientAuthMethod: 'client_secret_post',
    });
  });

  it('should default httpTimeout to 5000', () => {
    const config = getConfig(defaultConfig);
    expect(config).to.deep.include({
      httpTimeout: 5000,
    });
  });

  it('should default clientAuthMethod to client_secret_post for other response types', () => {
    {
      const config = getConfig({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: { response_type: 'code' },
      });
      expect(config).to.deep.include({
        clientAuthMethod: 'client_secret_post',
      });
    }

    {
      const config = getConfig({
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: { response_type: 'code id_token' },
      });
      expect(config).to.deep.include({
        clientAuthMethod: 'client_secret_post',
      });
    }
  });

  it('should require a session store for back-channel logout', () => {
    expect(() => getConfig({ ...defaultConfig, backchannelLogout: true })).to.throw(
      TypeError,
      `Back-Channel Logout requires a "backchannelLogout.store" (you can also reuse "session.store" if you have stateful sessions) or custom hooks for "isLoggedOut" and "onLogoutToken".`
    );
  });

  it(`should configure back-channel logout with it's own store`, () => {
    expect(() =>
      getConfig({
        ...defaultConfig,
        backchannelLogout: { store: {} },
      })
    ).to.not.throw();
  });

  it(`should configure back-channel logout with a shared store`, () => {
    expect(() =>
      getConfig({
        ...defaultConfig,
        backchannelLogout: true,
        session: { store: {} },
      })
    ).to.not.throw();
  });

  it(`should configure back-channel logout with custom hooks`, () => {
    expect(() =>
      getConfig({
        ...defaultConfig,
        backchannelLogout: {
          isLoggedOut: () => {},
          onLogoutToken: () => {},
        },
      })
    ).to.not.throw();
  });
});
