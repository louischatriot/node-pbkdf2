var should = require('chai').should()
  , assert = require('chai').assert
  , NodePbkdf2 = require('../index')
  ;

describe('Custom utils', function () {

  describe('#uid', function () {

    it('Gives a string of length len', function () {
      NodePbkdf2.uid(8).length.should.equal(8);
      NodePbkdf2.uid(12).length.should.equal(12);
      NodePbkdf2.uid(15).length.should.equal(15);
    });

    it('Strings generated are random and unique (to a very high probability)', function () {
      NodePbkdf2.uid(8).should.not.equal(NodePbkdf2.uid(8));
    });

  });   // ==== End of '#uid' ==== //


  describe('Serialization, deserialization', function () {

    it('Can serialize an encrypted password and retrieve it after deserialization', function () {
      var obj = { salt: 'erwrw/+99', derivedKey: 'qzeqzr++p//r', derivedKeyLength: 12, iterations: 1000 };

      obj = NodePbkdf2.serializeEncryptedPassword(obj);
      (typeof obj).should.equal('string');

      obj = NodePbkdf2.deserializeEncryptedPassword(obj);
      Object.keys(obj).length.should.equal(4);
      obj.salt.should.equal('erwrw/+99');
      obj.derivedKey.should.equal('qzeqzr++p//r');
      obj.derivedKeyLength.should.equal(12);
      obj.iterations.should.equal(1000);
    });

  });   // ==== End of 'Serialization, deserialization' ==== //


  describe('Password encryption', function () {

    it('Encrypts a password with its uniquely generated salt, preventing rainbow tables attacks', function (done) {
      var password = 'supersecret'
        , options = { iterations: 10000, saltLength: 12, derivedKeyLength: 30 }
        , hasher = new NodePbkdf2(options)
        ;

      // Generate two encrypted passwords from the same password
      hasher.encryptPassword(password, function (err, e1) {
        if (err) { return done(err.toString()); }
        e1 = NodePbkdf2.deserializeEncryptedPassword(e1);
        hasher.encryptPassword(password, function (err, e2) {
          if (err) { return done(err.toString()); }
          e2 = NodePbkdf2.deserializeEncryptedPassword(e2);

          // Salt length as specified in the hasher options
          e1.salt.length.should.equal(hasher.saltLength);
          e2.salt.length.should.equal(hasher.saltLength);

          // Iterations are saved
          e1.iterations.should.equal(hasher.iterations);
          e2.iterations.should.equal(hasher.iterations);

          // The two salts should be different, as well as the derived keys
          e1.salt.should.not.equal(e2.salt);
          e1.derivedKey.should.not.equal(e2.derivedKey);

          // Of course, the derived keys should not be equal to the original password
          e1.derivedKey.should.not.equal(password);
          e2.derivedKey.should.not.equal(password);

          done();
        });
      });
    });

    it('Can check whether a given password matches its encrypted version', function (done) {
      var password = 'supersecret'
        , options = { iterations: 10000, saltLength: 12, derivedKeyLength: 30 }
        , hasher = new NodePbkdf2(options)
        ;

      hasher.encryptPassword(password, function (err, e1) {
        if (err) { return done(err.toString()); }

        hasher.checkPassword('supersecre', e1, function (err, ok) {
          if (err) { return done(err.toString()); }
          ok.should.equal(false);

          hasher.checkPassword('supersecrett', e1, function (err, ok) {
            if (err) { return done(err.toString()); }
            ok.should.equal(false);

            hasher.checkPassword('supersecret', e1, function (err, ok) {
              if (err) { return done(err.toString()); }
              ok.should.equal(true);

              done();
            });
          });
        });
      });
    });

    it('Can change the password encryption settings and still check passwords encrypted with former method', function (done) {
      var password = 'supersecret'
        , options = { iterations: 10000, saltLength: 12, derivedKeyLength: 30 }
        , hasher = new NodePbkdf2(options)
        , options2 = { iterations: 20000, saltLength: 24, derivedKeyLength: 40 }
        , hasher2 = new NodePbkdf2(options2)
        ;

      hasher.encryptPassword(password, function (err, _e1) {
        var e1 = NodePbkdf2.deserializeEncryptedPassword(_e1);
        e1.salt.length.should.equal(12);
        e1.iterations.should.equal(10000);

        // Use new and stronger password hasher
        hasher2.encryptPassword(password, function (err, _e2) {
          var e2 = NodePbkdf2.deserializeEncryptedPassword(_e2);
          e2.salt.length.should.equal(24);
          e2.iterations.should.equal(20000);

          // We can still check against the password encrypted with the former method as well as the new method
          hasher.checkPassword(password, _e1, function (err, ok) {
            if (err) { return done(err.toString()); }
            ok.should.equal(true);

            hasher.checkPassword(password, _e2, function (err, ok) {
              if (err) { return done(err.toString()); }
              ok.should.equal(true);

              done();
            });
          });
        });
      });
    });

  });   // ==== End of 'Password encryption' ==== //

});

