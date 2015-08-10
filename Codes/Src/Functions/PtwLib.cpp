#include "SystemInclude.h"
#include "Common.h"
#include "Rc4.h"

#include "Types.h"
#include "MacHeader.h"
#include "SecurityHeader.h"
#include "PtwLib.h"
using namespace std;
CxxBeginNameSpace(Router)

size_t CalcLayer3DataSize(const MacHeader& macHeader)
{
    assert(macHeader.GetTypeBits() == DataFrameType);
    size_t size = macHeader.GetFrameBodySize();
    if (macHeader.GetWepBit() == 1)
    {
        shared_ptr<SecurityHeader> mpdu(CreateSecurityHeader(macHeader)); 
        size = size - mpdu->GetHeaderSize() - mpdu->GetTailerSize();
    }
    return size;
}

Mac& GetMyRouterId()
{
    static Mac mac((uchar_t*)"\x00\x00\x00\x00\x00\x01");
    return mac;
}

CxxEndNameSpace /*Router*/