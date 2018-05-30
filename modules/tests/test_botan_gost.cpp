#include <botan/init.h>
#include <botan/gost_3410.h>
#include <botan/oids.h>
#include <botan/version.h>
int main()
{
        Botan::LibraryInitializer::initialize();
        const std::string name("gost_256A");
        const Botan::OID oid(Botan::OIDS::lookup(name));
        const Botan::EC_Group ecg(oid);
        try {
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
                const std::vector<Botan::byte> der =
                    ecg.DER_encode(Botan::EC_DOMPAR_ENC_OID);
#else
                const Botan::SecureVector<Botan::byte> der =
                    ecg.DER_encode(Botan::EC_DOMPAR_ENC_OID);
#endif
        } catch(...) {
                return 1;
        }

        return 0;
}
