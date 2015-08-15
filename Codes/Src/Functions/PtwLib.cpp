#include "SystemInclude.h"
#include "Common.h"
#include "Rc4.h"

#include "Types.h"
#include "MacHeader.h"
#include "SecurityHeader.h"
#include "PtwLib.h"
using namespace std;
CxxBeginNameSpace(Router)

Mac& GetMyMac()
{
    static Mac mac((uchar_t*)"\x00\x00\x00\x00\x00\x01");
    return mac;
}

CxxEndNameSpace /*Router*/