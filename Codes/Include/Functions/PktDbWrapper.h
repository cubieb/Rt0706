#ifndef _PktDbWrapper_h_
#define _PktDbWrapper_h_

CxxBeginNameSpace(Router)
#define TcpDumpMagic            0xA1B2C3D4

enum LinkType: uint32_t
{
    Ethernet       = 1,
    ieee802dot11   = 105,
    PrismHeader    = 119,
    RadiotapHeader = 127,
    PpiHeader      = 192
};

/**********************class PcapFile**********************/
struct PcapFileHeader
{
    uint32_t magic;
    uint16_t versionMajor;
    uint16_t versionMinor;
    int32_t  reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
    uint32_t linkType;
};

/**********************class PcapPacketHeader**********************/
struct PcapPacketHeader
{
    struct timeval ts;
    uint32_t       caplen;/* length of portion present */
    uint32_t       len;   /* length this packet (off wire) */
};

/**********************class PcapFileReader**********************/
class PcapFileReader
{
public:
    PcapFileReader(const char *fileName);
    size_t Read(std::shared_ptr<uchar_t>& out);

private:
    PcapFileReader();
    std::fstream fs;
};

/**********************class PcapPktDbWrapper**********************/
class PcapPktDbWrapper
{
public:
    typedef std::list<std::pair<std::shared_ptr<uchar_t>, size_t>>   MyContainer;

    typedef MyContainer::iterator       iterator;
    typedef MyContainer::const_iterator const_iterator;

    PcapPktDbWrapper(const char *fileName);    
    ~PcapPktDbWrapper();
    
    iterator begin()
    {
        return packets.begin();
    }

    iterator end()
    {
        return packets.end();
    }

private:
    std::list<std::pair<std::shared_ptr<uchar_t>, size_t>> packets;
};

CxxEndNameSpace
#endif