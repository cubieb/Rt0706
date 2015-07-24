
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
    PcapFile();
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

/*
802.11 Mac Frame:
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Frame Control         |     Duration ID               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Address 1                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Address 1          |      Address 2                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Address 2                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Address 3                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Address 3          |         Seq-Ctl               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Address 4                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Address 4          |         Frame Body ...        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Frame Control:
    Protocol:  bit 0~1
    Type    :  bit 2~3
    Sub Type:  bit 4~7
    To Ds   :  bit 8
    From Ds :  bit 9
    More Tag:  bit 10
    Retry   :  bit 11 
    Pwr Mgmt:  bit 12
    More Data: bit 13
    Wep     :  bit 14
    Order   :  bit 15
*/

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

/* 
Refer to 80211.FrameFormat.pdf, page 38 for details about management frame.
802.11 Mac Header for Management Frame:
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Frame Control         |     Duration ID               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Address 1                           |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |      Address 2                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Address 3                          |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |         Seq-Ctl               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Information Elements and Fixed Fields ... ...(variable)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Management Frame:
  1) Beacon Frame
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Timestamp                             |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Beacon Interval        |   Capability Information      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      SSID  ... ...(variable)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

class H802dot11
{
public:
    H802dot11(const char *fileName, size_t offset, size_t theFrameSize);
    ~H802dot11();

    uchar_t GetVersion() const;
    uchar_t GetType() const;
    uchar_t GetSubtype() const;

    uchar_t GetToDs() const;
    uchar_t GetFromDs() const;

    Mac GetBssid() const;
    Mac GetDestMac() const;

    std::shared_ptr<uchar_t> GetBuf() const;
    size_t GetSize() const;

    /* the following function is provided just for debug */
    void Put(std::ostream& os) const;
private:
    std::shared_ptr<uchar_t> buf;
    size_t  frameSize;   /* the whole packet's size, the following mgmt/data... frame included */
};
std::ostream& operator << (std::ostream& os, const H802dot11& h802dot11);


class Frame
{
public:
    Frame(std::shared_ptr<uchar_t> theBuff, size_t theOffset, size_t theSize);
    
protected:
    std::shared_ptr<uchar_t> buf;
    size_t  offset; /* this mgmt/data/control frame started at the buf.get() + offset */
    size_t  frameSize;   /* current frame content: buf.get()[offset, offset + size) . */
};

class ManagementFrame: public Frame
{
public:
    ManagementFrame(std::shared_ptr<uchar_t> buff, size_t offset, size_t size);
    ManagementFrame(const ManagementFrame&);

    virtual size_t GetFixFieldSize() const = 0;
    std::string GetEssid() const;

    /* the following function is provided just for debug */
    virtual void Put(std::ostream& os) const;
};
std::ostream& operator << (std::ostream& os, ManagementFrame const& frame);


class AssociationRequestFrame: public ManagementFrame
{
public:
    enum AssociationRequestFrameOffset: uint32_t
    {
        CapabilityInfo  = 0,
        ListenInterval  = 2
    };
    AssociationRequestFrame(const H802dot11& h802dot11);
    AssociationRequestFrame(const AssociationRequestFrame&);

    size_t GetFixFieldSize() const;
    uint16_t GetListenInterval() const;

    void Put(std::ostream& os) const;

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
    BeaconFrame(const H802dot11& h802dot11);
    BeaconFrame(const BeaconFrame&);
    
    size_t GetFixFieldSize() const;
    uchar_t* GetTimeStamp();
    uint16_t GetBeaconInterval() const;

    uchar_t GetEssCapabilityBit() const;
    uchar_t GetIbssStatusBit() const;
    uchar_t GetPrivacyBit() const;

    void Put(std::ostream& os) const;
};

class ProbeResponseFrame: public ManagementFrame
{
public:
    enum ProbeResponseFrameOffset: uint32_t
    {
        TimeStamp       = 0,
        BetweenInterval  = 8,
        CapabilityInfo  = 10,    
    };

    ProbeResponseFrame(const H802dot11& h802dot11);
    ProbeResponseFrame(const ProbeResponseFrame&);

    static ManagementFrame* CreateInstance(std::shared_ptr<uchar_t> buff, 
        size_t offset, size_t frameSize);

    size_t GetFixFieldSize() const;
    uchar_t* GetTimeStamp();
    uint16_t GetBetweenInterval() const;

    uchar_t GetEssCapabilityBit() const;
    uchar_t GetIbssStatusBit() const;
    uchar_t GetPrivacyBit() const;

    void Put(std::ostream& os) const;
};

class ProbeRequestFrame: public ManagementFrame
{
public:
    ProbeRequestFrame(const H802dot11& h802dot11);
    ProbeRequestFrame(const ProbeRequestFrame&);

    static ManagementFrame* CreateInstance(std::shared_ptr<uchar_t> buff, 
        size_t offset, size_t frameSize);

    size_t GetFixFieldSize() const;
};

#if 0
/*
    Refer 80211.FrameFormat.pdf page 34 for detail about data frame.
*/
class DataFrame: public Frame
{
};
#endif


CxxEndNameSpace
#endif
