#include <openssl/ecdsa.h>
#include <openssl/objects.h>
int main()
{
        EC_KEY *ec256, *ec384, *ec521;

        ec256 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        ec384 = EC_KEY_new_by_curve_name(NID_secp384r1);
        ec521 = EC_KEY_new_by_curve_name(NID_secp521r1);
        if (ec256 == NULL || ec384 == NULL || ec521 == NULL)
                return 1;
        return 0;
}
