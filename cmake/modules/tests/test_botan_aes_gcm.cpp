#include <botan/version.h>
int main()
{
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(2,0,0)
        return 0;
#endif
        return 1;
}
