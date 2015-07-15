
#ifndef _Pcap_h_
#define _Pcap_h_

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

class PcapFileHeader
{
public:
    PcapFileHeader(const char *fileName);
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
    PcapFileHeader();
    size_t fileSize;
};

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

enum H802dot11Type: uchar_t
{
    ManagementFrameType = 0x0,
    ControlFrameType    = 0x1,
    DataFrameType       = 0x2,
    ReservedFrameType   = 0x3
};

enum H802dot11Subtype: uchar_t
{
    /* type = ManagementFrame 0x0; */
    AssociationRequest    = 0x0,
    AssociationResponse   = 0x1,
    ReassociationRequest  = 0x2,
    ReassociationResponse = 0x3,
    ProbeRequest          = 0x4,
    ProbeResponse         = 0x5,
    Beacon                = 0x8,
    /* Announcement Traffic Indication Message */
    Atim                  = 0x9,
    Diassociation         = 0xa,
    Authentication        = 0xb,
    Deauthentication      = 0xc,

    /* type = ControlFrame 0x1; */
    PowerSave             = 0xa,
    Rts                   = 0xb,
    Cts                   = 0xc,
    Acknowledgement       = 0xd,
    ContentionFree        = 0xe,
    CfEndAndCfAck         = 0xf,

    /* type = DataFrame 0x2; */
    Data                  = 0x0,
    DataAndCfAck          = 0x1,
    DataAndCfPoll         = 0x2, 
    CfAck                 = 0x5,
    CfPoll                = 0x6,
    DataAndCfAckAndCfPoll = 0x7
};

enum MacHeaderSize: uint32_t
{
    AssociationRequestMacHeaderSize = 24,
    BeaconMacHeaderSize = 24,
    ProbeResponseMacHeaderSize = 24,
    ProbeRequestMacHeaderSize = 24,
};

enum ManagementFrameFixedFieldSize
{
    AssociationRequestFixedFieldSize = 4,
    BeaconFixedFieldSize = 12,
    ProbeResponseFixedFieldSize = 12,
    ProbeRequestFixedFieldSize = 0,
};

class ManagementFrame
{
public:
    ManagementFrame(std::shared_ptr<uchar_t> theBuff, size_t theOffset, size_t theFrameSize);
    ManagementFrame(const ManagementFrame&);

    virtual size_t GetFixFieldSize() const = 0;
    std::string GetEssid() const;

    /* the following function is provided just for debug */
    virtual void Put(std::ostream& os) const;

protected:    
    std::shared_ptr<uchar_t> buf;
    size_t offset;    /* this management frame started at the buf.get() + offset */    
    size_t frameSize; /* the whole packet length */

private:
    ManagementFrame();
};
std::ostream& operator << (std::ostream& os, ManagementFrame const& frame);

class AssociationRequestFrame: public ManagementFrame
{
public:
    enum BeaconFrameOffset: uint32_t
    {
        CapabilityInfo  = 0,
        ListenInterval  = 2
    };
    AssociationRequestFrame(std::shared_ptr<uchar_t> theBuff, size_t theOffset, size_t theFrameSize);
    AssociationRequestFrame(const AssociationRequestFrame&);

    static ManagementFrame* CreateInstance(std::shared_ptr<uchar_t> buff, 
        size_t offset, size_t frameSize);

    size_t GetFixFieldSize() const;
    uint16_t GetListenInterval() const;

    void Put(std::ostream& os) const;

private:
    uchar_t* ptr;  /* ptr = buf.get() + offset, initialized by contruct function */
};

class BeaconFrame: public ManagementFrame
{
public:
    enum BeaconFrameOffset: uint32_t
    {
        TimeStamp       = 0,
        BeaconInterval  = 8,
        CapabilityInfo  = 10,    
    };
    BeaconFrame(std::shared_ptr<uchar_t> theBuff, size_t theOffset, size_t theFrameSize);
    BeaconFrame(const BeaconFrame&);

    static ManagementFrame* CreateInstance(std::shared_ptr<uchar_t> buff, 
        size_t offset, size_t frameSize);

    size_t GetFixFieldSize() const;
    uchar_t* GetTimeStamp();
    uint16_t GetBeaconInterval() const;

    uchar_t GetEssCapabilityBit() const;
    uchar_t GetIbssStatusBit() const;
    uchar_t GetPrivacyBit() const;

    void Put(std::ostream& os) const;

private:
    uchar_t* ptr;  /* ptr = buf.get() + offset, initialized by contruct function */
};

class ProbeResponseFrame: public ManagementFrame
{
public:
    ProbeResponseFrame(std::shared_ptr<uchar_t> theBuff, size_t theOffset, size_t theFrameSize);
    ProbeResponseFrame(const ProbeResponseFrame&);

    static ManagementFrame* CreateInstance(std::shared_ptr<uchar_t> buff, 
        size_t offset, size_t frameSize);

    size_t GetFixFieldSize() const;
    uchar_t* GetTimeStamp();
    uint16_t GetBeaconInterval() const;

    uchar_t GetEssCapabilityBit() const;
    uchar_t GetIbssStatusBit() const;
    uchar_t GetPrivacyBit() const;

    void Put(std::ostream& os) const;

private:
    uchar_t* ptr;  /* ptr = buf.get() + offset, initialized by contruct function */
};

class ProbeRequestFrame: public ManagementFrame
{
public:
    ProbeRequestFrame(std::shared_ptr<uchar_t> theBuff, size_t theOffset, size_t theFrameSize);
    ProbeRequestFrame(const ProbeRequestFrame&);

    static ManagementFrame* CreateInstance(std::shared_ptr<uchar_t> buff, 
        size_t offset, size_t frameSize);

    size_t GetFixFieldSize() const;
};

enum H802dot11Offset: uint32_t
{
    FrameControl = 0,
    DurationId   = 2,
    Addr1        = 4,
    Addr2        = 10,
    Addr3        = 16,
    SeqControl   = 22,

    ManagementFrameMacHeaderSize = 24,
    RtsFrameMacHeaderSize        = 16,
    CtsFrameMacHeaderSize        = 10
};

class H802dot11
{
public:
    typedef std::function<ManagementFrame*(std::shared_ptr<uchar_t> buff, 
        size_t, size_t)> FrameFactor;
    H802dot11(const char *fileName, size_t offset, size_t theFrameSize);
    ~H802dot11();

    uchar_t GetVersion() const;
    uchar_t GetType() const;
    uchar_t GetSubtype() const;

    uchar_t GetToDs() const;
    uchar_t GetFromDs() const;

    Mac GetBssid() const;
    Mac GetDestMac() const;

    ManagementFrame& GetManagementFrame();

    /* the following function is provided just for debug */
    void Put(std::ostream& os) const;
private:
    std::shared_ptr<uchar_t> buf;
    size_t frameSize;   /* the whole packet length */
    ManagementFrame* managementFrame;
    std::map<uchar_t, std::pair<FrameFactor, size_t>> classFactor;
};

std::ostream& operator << (std::ostream& os, H802dot11 const& h802dot11);
CxxEndNameSpace

#endif
