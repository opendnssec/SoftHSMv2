#include <botan/version.h>

#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(2,11,0)
#error Botan 2.11.0 or newer is required
#endif

int main()
{
        return 0;
}
