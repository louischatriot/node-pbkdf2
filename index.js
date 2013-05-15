var crypto = require('crypto');


/**
 * Constructor
 * @param {Number} options.iterations Number of iterations to be used when hashing new passwords
 * @param {Number} options.saltLength Length of the salt to use
 * @param {Number} options.derivedKeyLength Length of the stored encrypted password
 */
function NodePbkdf2 (options) {
  options = options || {};

  this.iterations = options.iterations || 10000;
  this.saltLength = options.saltLength || 12;
  this.derivedKeyLength = options.derivedKeyLength || 30;
}


/**
 * Generates a random string of length len
 */
NodePbkdf2.uid = function (len) {
  return crypto.randomBytes(len)
    .toString('base64')
    .slice(0, len);
};


/**
 * Serialize a password object containing all the information needed to check a password into a string
 * The info is salt, derivedKey, derivedKey length and number of iterations
 */
NodePbkdf2.serializeEncryptedPassword = function (encryptedPassword) {
  return encryptedPassword.salt + "::" +
         encryptedPassword.derivedKey + "::" +
         encryptedPassword.derivedKeyLength + "::" +
         encryptedPassword.iterations;
};


/**
 * Deserialize a string into a password object
 * The info is salt, derivedKey, derivedKey length and number of iterations
 */
NodePbkdf2.deserializeEncryptedPassword = function (encryptedPassword) {
  var res = {}
    , items = encryptedPassword.split('::')
    ;

  res.salt = items[0];
  res.derivedKey = items[1];
  res.derivedKeyLength = parseInt(items[2], 10);
  res.iterations = parseInt(items[3], 10);

  return res;
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

    return callback(null, NodePbkdf2.serializeEncryptedPassword({ salt: randomSalt
                                                                , iterations: self.iterations
                                                                , derivedKeyLength: self.derivedKeyLength
                                                                , derivedKey: new Buffer(derivedKey, 'binary').toString('base64') }));
  });
};


/**
 * Compare a password to an encrypted password
 * @param {String} password
 * @param {String} encryptedPassword
 * @param {Function} callback Signature: err, true/false
 */
NodePbkdf2.prototype.checkPassword = function (password, encryptedPassword, callback) {
  var self = this;

  encryptedPassword = NodePbkdf2.deserializeEncryptedPassword(encryptedPassword);

  if (!encryptedPassword.salt || !encryptedPassword.derivedKey || !encryptedPassword.iterations || !encryptedPassword.derivedKeyLength) { return callback("encryptedPassword doesn't have the right format"); }

  // Use the encrypted password's parameter to hash the candidate password
  crypto.pbkdf2(password, encryptedPassword.salt, encryptedPassword.iterations, encryptedPassword.derivedKeyLength, function (err, derivedKey) {
    if (err) { return callback(err); }

    if (new Buffer(derivedKey, 'binary').toString('base64') === encryptedPassword.derivedKey) {
      return callback(null, true);
    } else {
      return callback(null, false);
    }
  });
};



// Interface
module.exports = NodePbkdf2;
