#include "SystemInclude.h"
#include "Common.h"
#include "Rc4.h"

#include "H802dot11.h"
#include "PtwLib.h"
using namespace std;
CxxBeginNameSpace(Router)

/*
7.1.3.1.8 Protected Frame field
The Protected Frame field is 1 bit in length. The Protected Frame field is set to 1 if the Frame Body field
contains information that has been processed by a cryptographic encapsulation algorithm. The Protected
Frame field is set to 1 only within data frames and within management frames of subtype Authentication.
The Protected Frame field is set to 0 in all other frames. When the Protected Frame field is set to 1, the
Frame Body field is protected utilizing the cryptographic encapsulation algorithm and expanded as defined
in Clause 8. The Protected Frame field is set to 0 in Data frames of subtype Null Function, CF-ACK (no
data), CF-Poll (no data), and CF-ACK+CF-Poll (no data) (see 8.3.2.2 and 8.3.3.1, which show that the frame
body must be 1 octet or longer to apply the encapsulation).
*/
ProtectedMpduBase* CreateProtectedMpdu(const H802dot11& h802dot11)
{
    assert(h802dot11.GetWepBit() == 1);

    uchar_t* ptr = h802dot11.GetFrameBodyPtr();
    if ((ptr[KeyIndexOffset] >> 5) == 0)
    {
        return new WepMpdu;
    }
    else
    {
        return new TkipMpdu;
    }
}

size_t CalcLayer3DataSize(const H802dot11& h802dot11)
{
    assert(h802dot11.GetTypeBits() == DataFrameType);
    size_t size = h802dot11.GetFrameBodySize();
    if (h802dot11.GetWepBit() == 1)
    {
        shared_ptr<ProtectedMpduBase> mpdu(CreateProtectedMpdu(h802dot11)); 
        size = size - mpdu->GetHeaderSize() - mpdu->GetTailerSize();
    }
    return size;
}

CxxEndNameSpace /*Router*/