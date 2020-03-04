#include <botan/ec_group.h>
#include <botan/oids.h>
int main()
{
        try {
                const std::string name("secp256r1");
                const Botan::OID oid(Botan::OIDS::lookup(name));
                const Botan::EC_Group ecg(oid);
                const std::vector<Botan::byte> der =
                    ecg.DER_encode(Botan::EC_DOMPAR_ENC_OID);
        } catch(...) {
                return 1;
        }
        return 0;
}
