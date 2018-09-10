#include <botan/init.h>
#include <botan/ed25519.h>
#include <botan/version.h>
int main()
{
        Botan::secure_vector<uint8_t> k(32);
        try {
                Botan::Ed25519_PrivateKey* key =
                    new Botan::Ed25519_PrivateKey(k);
        } catch(...) {
                return 1;
        }
        return 0;
}
