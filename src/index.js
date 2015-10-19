var jwt = require('express-jwt'),
	jwk2pem = require('pem-jwk').jwk2pem,
	jwksUtils = require('jwks-utils'),
	extend = require('util')._extend,
	Buffer = require('buffer').Buffer,
	async = require('async');

module.exports = function (options) {
	if(!options) {
		return new Error('Options not set');
	}

	if (jwksUtils.isJWK(options.secret)) {
		options.secret = {keys: [options.secret]};
	}

	if (jwksUtils.isJWKset(options.secret)) {
		var keys = options.secret.keys, pems = [];
		for (var i = 0, len = keys.length; i < len; i++) {
			pems.push(jwk2pem(keys[i]));
		}
		return function (req, res, next) {
			var errors = [];
			async.some(pems, function (pem, callback) {
				var copy = extend({}, options);
				copy.secret = new Buffer(pem);
				jwt(copy)(req, res, function (err) {
					if (err) {
						errors.push(err);
					}
					callback(err == undefined);
				});
			}, function (result) {
				next(result ? undefined : errors.pop());
			});
		}
	}

	return jwt(options);
};
