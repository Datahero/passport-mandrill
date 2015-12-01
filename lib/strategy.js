/**
 * Module dependencies.
 */
var passport = require('passport-strategy');
var querystring = require('querystring');
var request = require('request');
var url = require('url');
var util = require('util');
var utils = require('./utils');

/**
 * `Strategy` constructor.
 *
 * The authentication strategy authenticates requests based on the
 * credentials submitted through an HTML-based login form.
 *
 * Applications must supply a `verify` callback which accepts `username` and
 * `password` credentials, and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 *
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (!verify) { throw new TypeError('MandrillStrategy requires a verify callback'); }

  options = options || {};
  if (!options.callbackURL) { throw new TypeError('MandrillStrategy requires a callbackURL option'); }
  if (!options.clientID) { throw new TypeError('MandrillStrategy requires a clientID option'); }

  this._authorizationURL = options.authorizationURL || 'https://mandrillapp.com/api-auth/';
  this._userURL = (options.hostURL || 'https://mandrillapp.com/api/1.0/') + '/users/info.json';
  this._clientID = options.clientID;

  passport.Strategy.call(this);
  this.name = 'mandrill';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {

  // TODO - handle errors from Auth callback here. Error code should be in req (req.query.error?)

  options = options || {};
  var callbackURL =  options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
    }
  }

  var apiKey = req.body && req.body.key;

  if (apiKey) {
    var self = this;
    request.post({url: this._userURL, json: {key: apiKey}}, function(error, res, body) {
      if (error)
        return self.error(error);

      if (body && body.status && body.status === 'error')
        return self.error(new Error(body.name + ': ' + body.message));

      var arity = self._verify.length;
      var verified = function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }
        self.success(user, info);
      };

      // body is the object containing user information
      try {
        if (self._passReqToCallback) {
          self._verify(req, apiKey, body, verified);
        } else {
          self._verify(apiKey, body, verified);
        }
      } catch (err) {
        return self.error(err);
      }

    });
    return;
  } else {
    var authParams = {
      id: this._clientID,
      redirect_url: callbackURL
    };

    var location = this._authorizationURL + '?' + querystring.stringify(authParams);
    this.redirect(location);
  }
};



/**
 * Expose `Strategy`.
 */
module.exports = Strategy;