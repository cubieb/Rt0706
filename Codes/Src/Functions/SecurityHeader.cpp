#include "SystemInclude.h"
#include "Common.h"
#include "Rc4.h"

#include "Types.h"
#include "MacHeader.h"
#include "SecurityHeader.h"
using namespace std;
CxxBeginNameSpace(Router)

/**********************class WepHeader**********************/
size_t WepHeader::GetIvSize() const
{
    return WepIvSize;
}

size_t WepHeader::GetHeaderSize() const
{
    return WepIvSize + WepKeyIndexSize;
}

size_t WepHeader::GetTailerSize() const
{
    return TkipTailerSize;
}

CryptMode WepHeader::GetCryptMode() const
{
    return CryptMode::Wep;
}

/**********************class TkipHeader**********************/
size_t TkipHeader::GetIvSize() const
{
    return TkipIvSize;
}

size_t TkipHeader::GetHeaderSize() const
{
    return TkipHeaderSize;
}

size_t TkipHeader::GetTailerSize() const
{
    return TkipTailerSize;
}

CryptMode TkipHeader::GetCryptMode() const
{
    return CryptMode::Tkip;
}

/**********************SecurityHeader Factory**********************/
/*
7.2.2 Data frames
The frame body consists of the MSDU, or a fragment thereof, and a security header and trailer (if and only if
the Protected Frame subfield in the Frame Control field is set to 1). 
*/
SecurityHeader* CreateSecurityHeader(const MacHeader& macHeader)
{
    assert(macHeader.GetWepBit() == 1);

    uchar_t* ptr = macHeader.GetFrameBodyPtr();
    if ((ptr[KeyIndexOffset] >> 5) == 0)
    {
        return new WepHeader;
    }
    else
    {
        return new TkipHeader;
    }
}



CxxEndNameSpace /*Router*/