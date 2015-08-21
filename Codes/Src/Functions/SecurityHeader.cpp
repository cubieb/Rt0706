#include "SystemInclude.h"
#include "Common.h"
#include "Rc4.h"

#include "Types.h"
#include "MacHeader.h"
#include "SecurityHeader.h"
using namespace std;
CxxBeginNameSpace(Router)

/**********************class MacPdu**********************/
size_t MacPdu::GetLayer3DataSize(const MacHeader& macHeader) const
{
    assert(macHeader.GetTypeBits() == DataFrameType);
    size_t size = macHeader.GetFrameBodySize();
    if (macHeader.GetWepBit() == 1)
    {
        size = size - GetHeaderSize() - GetTailerSize();
    }

    return size;
}

/**********************class WepMacPdu**********************/
size_t WepMacPdu::GetIvSize() const
{
    return WepIvSize;
}

size_t WepMacPdu::GetHeaderSize() const
{
    return WepIvSize + WepKeyIndexSize;
}

size_t WepMacPdu::GetTailerSize() const
{
    return TkipTailerSize;
}

CryptMode WepMacPdu::GetCryptMode() const
{
    return CryptMode::Wep;
}

/**********************class TkipMacPdu**********************/
size_t TkipMacPdu::GetIvSize() const
{
    return TkipIvSize;
}

size_t TkipMacPdu::GetHeaderSize() const
{
    return TkipHeaderSize;
}

size_t TkipMacPdu::GetTailerSize() const
{
    return TkipTailerSize;
}

CryptMode TkipMacPdu::GetCryptMode() const
{
    return CryptMode::Tkip;
}

/**********************SecurityHeader Factory**********************/
/*
7.2.2 Data frames
The frame body consists of the MSDU, or a fragment thereof, and a security header and trailer (if and only if
the Protected Frame subfield in the Frame Control field is set to 1). 
*/
MacPdu* CreateMacPduHeader(const MacHeader& macHeader)
{
    assert(macHeader.GetWepBit() == 1);
#define KeyIndexOffset 3

    uchar_t* ptr = macHeader.GetFrameBodyPtr();
    if (((ptr[KeyIndexOffset] >> 5) & 0x1) == 0)
    {
        return new WepMacPdu;
    }
    else
    {
        return new TkipMacPdu;
    }
}

size_t CalcLayer3DataSize(const MacHeader& macHeader)
{
    assert(macHeader.GetTypeBits() == DataFrameType);
    size_t size = macHeader.GetFrameBodySize();
    if (macHeader.GetWepBit() == 1)
    {
        shared_ptr<MacPdu> mpdu(CreateMacPduHeader(macHeader)); 
        size = size - mpdu->GetHeaderSize() - mpdu->GetTailerSize();
    }
    return size;
}


CxxEndNameSpace /*Router*/