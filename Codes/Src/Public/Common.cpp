#include "SystemInclude.h"

#include "Common.h"

using namespace std;

Mac::Mac(const uchar_t* mac): mac(new uchar_t[6])
{
    memcpy(this->mac.get(), mac, 6);
}

Mac::Mac(Mac const& right): mac(right.mac)
{}

Mac const& Mac::operator =(Mac const& right)
{
    mac = right.mac;
    return *this;
}

bool Mac::IsBroadcast() const
{
    return (memcmp(MacBroadcast, mac.get(), 6) == 0);
}

bool Mac::IsZero() const
{
    return (memcmp(MacZero, mac.get(), 6) == 0);    
}

uchar_t* Mac::GetPtr() const
{
    return mac.get();
}

int Mac::Compare(Mac const& right) const
{
    return memcmp(mac.get(), right.mac.get(), 6);
}

int Mac::Compare(const uchar_t* right) const
{
    return memcmp(mac.get(), right, 6);
}

void Mac::Put(ostream& os) const
{
    os << MemStream<uchar_t>(mac.get(),  6);
}

ostream& operator << (ostream& os, Mac const& mac)
{
    mac.Put(os);
    return os;
}

/******************Read from / Write to packet buffer******************/
size_t Read16(uchar_t* buf, uint16_t& value)
{
    uchar_t* pt = reinterpret_cast<uchar_t*>(&value);
    size_t size = sizeof(uint16_t);
    if(__BYTE_ORDER == __BIG_ENDIAN)
    {
        for (size_t i = 0; i < size; ++i)
        {
            pt[i] = buf[i];
        }
    }
    else
    {        
        for (size_t i = 0; i < size; ++i)
        {
            pt[i] = buf[size - i - 1];
        }
    }

    return size;
}

size_t Read32(uchar_t* buf, uint32_t& value)
{
    uchar_t* pt = reinterpret_cast<uchar_t*>(&value);
    size_t size = sizeof(uint32_t);
    if(__BYTE_ORDER == __BIG_ENDIAN)
    {
        for (size_t i = 0; i < size; ++i)
        {
            pt[i] = buf[i];
        }
    }
    else
    {        
        for (size_t i = 0; i < size; ++i)
        {
            pt[i] = buf[size - i - 1];
        }
    }

    return size;
}

size_t Write16(uchar_t* buf, uint16_t value)
{
    size_t size = sizeof(uint16_t);
    for (size_t i = 0; i < size; ++i)
    {
        buf[size - i - 1] = value & 0xff;
        value = value >> 8;
    }
    return size;
}

size_t Write32(uchar_t* buf, uint32_t value)
{
    size_t size = sizeof(uint32_t);
    for (size_t i = 0; i < size; ++i)
    {
        buf[size - i - 1] = value & 0xff;
        value = value >> 8;
    }
    return size;
}
