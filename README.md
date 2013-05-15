node-pbkdf2
===========

Wrapper to hash and check password with Node's crypto module's built-in pbkdf2.

It abstracts the API change between Node v0.8 and v0.10, you can begin
using this module with any version and it will also work on the others.

It is future-proof, meaning that you can change the parameters to arbitrarily increase the strength of new password encryption and it will still be able to check against passwords encrypted with the old method.

```javascript
// Install it
npm install node-pbkdf2

// Run tests (dev dependencies need to be installed)
make test

// You can also test it works across the API change between Node v0.8 and v0.10
// You need to have nvm, node v0.8 and node v0.10 for this test
make testVersionSwitch

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


## License
MIT, do whatever you want with the code, just leave this message here  
(c) 2013 Louis Chatriot (louis@tldr.io)
