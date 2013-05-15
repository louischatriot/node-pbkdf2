#!/usr/bin/env node

var NodePbkdf2 = require('../../index')
  , hasher = new NodePbkdf2()
  , fs = require('fs')
  ;

console.log("Getting password from save file");
fs.readFile('workspace/encryptedPassword', 'utf8', function (err, data) {
  if (err) { process.exit(1); }

  hasher.checkPassword('supersecret', data, function (err, ok) {
    if (!ok) { console.log('Password checking failed'); process.exit(1); }

    hasher.checkPassword('supersecre', data, function (err, ok) {
      if (ok) { console.log('Password checking failed'); process.exit(1); }

      hasher.checkPassword('supersecrett', data, function (err, ok) {
        if (ok) { console.log('Password checking failed'); process.exit(1); }
      });
    });
  });
});
