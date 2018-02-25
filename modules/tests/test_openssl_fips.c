#include <openssl/crypto.h>
int main()
{
        return !FIPS_mode_set(1);
}
