# Anti-XSRF middleware

This XSRF prevention middleware:

  1. stores XSRF secret in Redis-backed session
  2. exposes a token on `res.locals` variable `xsrfToken`
  3. exposes a token via cookie
  4. validates incoming token if not ignored

Note: this middleware requires [alt-session](https://github.com/inca/alt-session)
to be installed beforehand.

You can provide custom ignore function via options:

```js
options.ignore = function(req, res) {
  return true; // Ignore all requests
}
```

You can provide custom token source getter
(by default it takes `X-XSRF-TOKEN` header value to ensure
compatibility with Angular):

```js
options.getToken = function(req, res) {
  return req.get('X-XSRF-TOKEN');
}
```
