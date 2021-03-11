#include "BotanGOST2012_512.h"
#include "ECParameters.h"

#include <botan/ber_dec.h>
#include <botan/oids.h>

bool BotanGOST2012_512::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng)
{
	ECParameters *p = reinterpret_cast<ECParameters*>(parameters);
	const ByteString &ec = p->getEC();
	if(ec.size())
	{
		Botan::BER_Decoder dec(ec.const_byte_str(), ec.size());
		Botan::OID oid;
		oid.decode_from(dec);
		if (oid != Botan::OID({1,2,643,7,1,2,1,2,1}) &&
				oid != Botan::OID({1,2,643,7,1,2,1,2,2}) &&
				oid != Botan::OID({1,2,643,7,1,2,1,2,3})
				)
		{
			ERROR_MSG("Public Key paramSet is not valid for GOST R34.10-2012 512");
			return false;
		}
	}
	else
	{
		const std::vector<u_char> &data = Botan::OID({1,2,643,7,1,2,1,2,1}).BER_encode();
		p->setEC(ByteString(data.data(), data.size()));
	}
	return BotanGOST::generateKeyPair(ppKeyPair, parameters, rng);
}
