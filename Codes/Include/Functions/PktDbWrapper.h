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

/**********************class PktDbWrapper**********************/
class PktDbWrapper
{
public:
    typedef std::function<void(std::shared_ptr<uchar_t>, size_t)> Trigger;
    
    PktDbWrapper(Trigger theTrigger)
        : trigger(theTrigger)
    {}

    virtual void Start() const = 0;

protected:
    
    Trigger trigger;
};

/**********************class PcapFile**********************/
class PcapFile
{
public:
    PcapFile(const char *fileName);
    size_t GetHeaderSize();
    size_t GetFileSize();

public:
    uint32_t magic;
    uint16_t versionMajor;
    uint16_t versionMinor;
    int32_t  reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
    uint32_t linkType;

private:
    PcapFile() {}
    size_t fileSize;
};

/**********************class PcapPacketHeader**********************/
class PcapPacketHeader
{
public:
    PcapPacketHeader(const char *fileName, size_t offset);
    size_t GetSize();

public:
    struct timeval ts;
    uint32_t       caplen;/* length of portion present */
    uint32_t       len;   /* length this packet (off wire) */
};

/**********************class PcapPktDbWrapper**********************/
class PcapPktDbWrapper: public PktDbWrapper
{
public:
    PcapPktDbWrapper(Trigger trigger);
    void Start() const;

private:
    PcapPktDbWrapper();
    std::string filename;
};

CxxEndNameSpace
#endif