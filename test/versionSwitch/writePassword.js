#!/usr/bin/env node

var NodePbkdf2 = require('../../index')
  , hasher = new NodePbkdf2()
  , fs = require('fs')
  ;

console.log("Encrypting password");
hasher.encryptPassword('supersecret', function (err, enc) {
  if (err) { process.exit(1); }

  console.log("Writing encrypted version to file");
  fs.writeFile('workspace/encryptedPassword', enc, function (err) {
    if (err) { process.exit(1); }
  });
});
