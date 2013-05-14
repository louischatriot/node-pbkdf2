var crypto = require('crypto');


/**
 * Constructor
 * @param {Number} options.iterations Number of iterations to be used when hashing new passwords
 * @param {Number} options.saltLength Length of the salt to use
 * @param {Number} options.derivedKeyLength Length of the stored encrypted password
 */
function NodePbkdf2 (options) {
  this.iterations = options.iterations || 10000;
  this.saltLength = options.saltLength || 12;
  this.derivedKeyLength = options.derivedKeyLength || 30;
}


/**
 * Generates a random alphanumerical string of length len
 */
NodePbkdf2.uid = function (len) {
  var randomString = crypto.randomBytes(Math.max(8, len * 2))
    .toString('base64')
    .replace(/[^a-zA-Z0-9]/g, '')
    .slice(0, len);

  // If randomString is not of length len, retry
  // After tests, it turns out the probability of a retry is less than 1/1,000,000 so no risk of a too long recursion
  if (randomString.length === len) {
    return randomString;
  } else {
    return NodePbkdf2.uid(len);
  }
};


/**
 * Encrypt a password using node.js' crypto's PBKDF2
 * Description here: http://en.wikipedia.org/wiki/PBKDF2
 * Number of iterations are saved in case we change the setting in the future
 * @param {String} password
 * @param {Funtion} callback Signature: err, encryptedPassword
 */
NodePbkdf2.prototype.encryptPassword = function (password, callback) {
  var self = this
    , randomSalt = NodePbkdf2.uid(self.saltLength);

  crypto.pbkdf2(password, randomSalt, self.iterations, self.derivedKeyLength, function (err, derivedKey) {
    if (err) { return callback(err); }

    return callback(null, JSON.stringify({ salt: randomSalt, iterations: self.iterations, derivedKeyLength: self.derivedKeyLength, derivedKey: new Buffer(derivedKey).toString('base64') }));
  });
};


/**
 * Compare a password to an encrypted password
 * @param {String} password
 * @param {String} encryptedPassword
 * @param {Function} callback Signature: err, true/false
 */
NodePbkdf2.prototype.checkPassword = function (password, encryptedPassword, callback) {
  var self = this
    , encryptedPassword;

  try {
    encryptedPassword = JSON.parse(encryptedPassword);
  } catch (e) {
   return callback('Unexpected encrypted password format');
  }

  if (!encryptedPassword.salt || !encryptedPassword.derivedKey || !encryptedPassword.iterations || !encryptedPassword.derivedKeyLength) { return callback("encryptedPassword doesn't have the right format"); }

  // Use the encrypted password's parameter to hash the candidate password
  crypto.pbkdf2(password, encryptedPassword.salt, encryptedPassword.iterations, encryptedPassword.derivedKeyLength, function (err, derivedKey) {
    if (err) { return callback(err); }

    if (new Buffer(derivedKey).toString('base64') === encryptedPassword.derivedKey) {
      return callback(null, true);
    } else {
      return callback(null, false);
    }
  });
};


// Interface
module.exports = NodePbkdf2;
