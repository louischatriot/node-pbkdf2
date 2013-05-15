node-pbkdf2
===========

Wrapper to hash and check password with crypto's built-in pbkdf2.

It abstracts the API change between Node v0.8 and v0.10, you can begin using this module with one of the versions and it will also work on the other.

It is future-proof, meaning that you can change the parameters to increase the strength of encryption and it will still be able to check against password encrypted with the old method.

```javascript
// Install it
npm install node-pbkdf2

// Run tests (dev dependencies need to be installed)
make test

// Create a new password hasher with standard strength parameters
var NodePbkdf2 = require('node-pbkdf2')
  , hasher = new NodePbkdf2({ iterations: 10000, saltLength: 12, derivedKeyLength: 30 });

// Hash a password
hasher('supersecret', function (err, encryptedPassword) {
  // encryptedPassword is a string
});

// Check a given password against an encrypted one
hasher('supersecret', encryptedPassword, function (err, passwordIsCorrect) {
  // passwordIsCorrect is true
});
```

