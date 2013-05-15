set -e

mkdir -p workspace

# Source nvm. The second method is what the nvm's readme says but it's
# the first one that works on my machine so this script tries both
. ~/.nvm/nvm.sh || . ~/nvm/nvm.sh

echo "============================================"
echo "Encrypting with v0.8 and checking with v0.10"
echo "============================================"
nvm use 0.8
./test/versionSwitch/writePassword.js
nvm use 0.10
./test/versionSwitch/checkPassword.js

echo ""
echo ""

echo "============================================"
echo "Encrypting with v0.10 and checking with v0.8"
echo "============================================"
nvm use 0.10
./test/versionSwitch/writePassword.js
nvm use 0.8
./test/versionSwitch/checkPassword.js

echo ""
echo ""

echo "============================================"
echo "SUCCESS."
echo "============================================"
