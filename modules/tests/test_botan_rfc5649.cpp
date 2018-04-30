#include <botan/botan.h>
#include <botan/rfc3394.h>
#include <botan/version.h>
int main()
{
        using namespace Botan;

#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
        secure_vector<byte> key(10);
        SymmetricKey kek("AABB");
        secure_vector<byte> x = rfc5649_keywrap(key, kek);
#else
        SecureVector<byte> key(10);
        SymmetricKey kek("AABB");
        Algorithm_Factory& af = global_state().algorithm_factory();
        SecureVector<byte> x = rfc5649_keywrap(key, kek, af);
#endif
        return 0;
}
