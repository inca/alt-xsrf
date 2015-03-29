"use strict";

var csrf = require('csrf');

/**
 * This XSRF prevention middleware:
 *
 *   1. stores XSRF secret in Redis-backed session
 *   2. exposes a token on `res.locals` variable `xsrfToken`
 *   3. exposes a token via cookie
 *   4. validates incoming token if not ignored
 *
 * Note: this middleware requires [alt-session](https://github.com/inca/alt-session)
 * to be installed beforehand.
 *
 * You can provide custom ignore function via options:
 *
 * ```js
 * options.ignore = function(req, res) {
 *   return true; // Ignore all requests
 * }
 * ```
 *
 * You can provide custom token source getter
 * (by default it takes `X-XSRF-TOKEN` header value to ensure
 * compatibility with Angular):
 *
 * ```js
 * options.getToken = function(req, res) {
 *   return req.get('X-XSRF-TOKEN');
 * }
 * ```
 *
 * @param {object} options
 * @param {string[]} options.ignoredMethods - an array of ignored methods,
 *   lowercased, defaults to ['get', 'head', 'options'];
 * @param {string} options.cookieName - custom cookie name, defaults to `XSRF-TOKEN`
 * @param {string} options.headerName - custom header name, defaults to `X-XSRF-TOKEN`
 * @param {string} options.sessionKey - custom session variable name
 *   for storing CSRF secret, defaults to `XSRF-SECRET`
 *
 * @module alt-xsrf
 */
module.exports = function(options) {
  options = options || {};

  var csrfTokens = csrf();

  // Methods which bypass XSRF token by default
  var IGNORED_METHODS = options.ignoredMethods || ['get', 'head', 'options'];

  // Angular-compatible cookie name and header name by default
  var COOKIE_NAME = options.cookieName || 'XSRF-TOKEN'
    , HEADER_NAME = options.headerName || 'X-XSRF-TOKEN';

  // Session variable key to store CSRF secret.
  var SESSION_KEY = options.sessionKey || 'XSRF-SECRET';

  // Custom ignore function
  var ignore = typeof options.ignore == 'function' ? options.ignore : null;

  // Custom token getter function
  var getToken = typeof options.getToken == 'function' ?
    options.getToken : function(req) { return req.get(HEADER_NAME) };

  return function(req, res, next) {

    obtainSecret(req.session, function(err, xsrfSecret) {
      /* istanbul ignore if */
      if (err) return next(err);
      var xsrfToken = csrfTokens.create(xsrfSecret);
      // Store in locals
      res.locals.xsrfToken = xsrfToken;
      // Store in cookies
      res.cookie(COOKIE_NAME, xsrfToken);
      // Bypass validation if ignored
      if (IGNORED_METHODS.indexOf(req.method.toLowerCase()) > -1)
        return next();
      // Account for custom ignore function, if any
      if (ignore && ignore(req, res))
        return next();
      // Validate token
      if (csrfTokens.verify(xsrfSecret, getToken(req, res)))
        return next();
      // Exit with 412 Precondition failed
      res.sendStatus(412);
    });

  };

  /**
   * Lookup CSRF secret in session, or generate new one and store it.
   *
   * @param {object} session - alt-session
   * @param {function} cb - callback `function(err, secret)`
   */
  function obtainSecret(session, cb) {
    session.get(SESSION_KEY, function(err, secret) {
      /* istanbul ignore if */
      if (err) return cb(err);
      if (secret) return cb(null, secret);
      secret = csrfTokens.secretSync();
      session.set(SESSION_KEY, secret, function(err) {
        /* istanbul ignore if */
        if (err) return cb(err);
        cb(null, secret);
      });
    });
  }

};
