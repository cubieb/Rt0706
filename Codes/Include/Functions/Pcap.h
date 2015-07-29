
#ifndef _Pcap_h_
#define _Pcap_h_

CxxBeginNameSpace(Router)

enum LinkType: uint32_t
{
    Ethernet       = 1,
    ieee802dot11   = 105,
    PrismHeader    = 119,
    RadiotapHeader = 127,
    PpiHeader      = 192
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
|                           Address 1                           =
++-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=            Address 1          |      Address 2                =
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=                           Address 2                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Address 3                          =
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=            Address 3          |         Seq-Ctl               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Address 4                          =
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=            Address 4          |         Frame Body ...        |
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
    DataMacHeaderSizeXx = 24,
    DataMacHeaderSize11 = 30,
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
    Addr4        = 22,

    ManagementFrameMacHeaderSize = 24,
    RtsFrameMacHeaderSize        = 16,
    CtsFrameMacHeaderSize        = 10
};

class H802dot11
{
public:
    H802dot11(const std::shared_ptr<uchar_t>& theBuf, size_t theBufSize);
    virtual ~H802dot11();

    size_t GetBufSize() const;
    uchar_t GetProtocolBits() const;
    uchar_t GetTypeBits() const;
    uchar_t GetSubtypeBits() const;

    uchar_t GetToDsBit() const;
    uchar_t GetFromDsBit() const;
    uchar_t GetMoreTagBit() const;
    uchar_t GetRetryBit() const;
    uchar_t GetPowerMgmtBit() const;
    uchar_t GetMoreDataBit() const;
    uchar_t GetWepBit() const;
        
    uchar_t* GetFramePtr() const;
    uchar_t* GetFrameBody() const;

    virtual Mac GetDestMac() const = 0;
    virtual Mac GetBssid() const = 0;
    virtual size_t GetMacHeaderSize() const = 0;
    
    /* the following function is provided just for debug */
    virtual void Put(std::ostream& os) const;

protected:
    std::shared_ptr<uchar_t> buf;
    size_t  bufSize;
};

inline std::ostream& operator << (std::ostream& os, const H802dot11& h802dot11)
{
    h802dot11.Put(os);
    return os;
}

class ManagementFrame: public H802dot11
{
public:
    ManagementFrame(const std::shared_ptr<uchar_t>& buf, size_t bufSize);
    virtual ~ManagementFrame();

    Mac GetDestMac() const;
    Mac GetBssid() const;
    std::string GetEssid() const;
        
    size_t GetMacHeaderSize() const = 0;
    virtual size_t GetFixedParaSize() const = 0;

    virtual void Put(std::ostream& os) const;
};

class AssociationRequestFrame: public ManagementFrame
{
public:
    enum AssociationRequestFrameOffset: uint32_t
    {
        CapabilityInfo  = 0,
        ListenInterval  = 2
    };
    AssociationRequestFrame(const std::shared_ptr<uchar_t>& buf, size_t bufSize);
    ~AssociationRequestFrame();

    size_t GetMacHeaderSize() const;
    size_t GetFixedParaSize() const;
    uint16_t GetListenInterval() const;

    /* the following function is provided just for debug */
    void Put(std::ostream& os) const;
};

/* 
Refer to 80211.FrameFormat.pdf, page 38 for details about management frame.
802.11 Mac Header for Management Frame:
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Frame Control         |     Duration ID               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Address 1                           =
++-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=            Address 1          |      Address 2                =
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=                           Address 2                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Address 3                          =
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=            Address 3          |         Seq-Ctl               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Frame Body ... ...(variable)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

1) Beacon Frame, Frame Body of 802.11 Frame (flowing the Mac Header)
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Timestamp                             =
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=                         Timestamp                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Beacon Interval        |   Capability Information      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      SSID  ... ...(variable)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         FH Parameter Set (Opt)                  | DS Parameter=
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=  Set (Opt)    |          CF Parameter Set (Opt)               =
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=                                                               =
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=               |             IBSS Parameter Set (Opt)          =
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=               |           TIM (Opt) ... ... (variable)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
class BeaconFrame: public ManagementFrame
{
public:
    enum BeaconFrameOffset: uint32_t
    {
        TimeStamp       = 0,
        BeaconInterval  = 8,
        CapabilityInfo  = 10,    
    };
    BeaconFrame(const std::shared_ptr<uchar_t>& buf, size_t bufSize);
    ~BeaconFrame();
    
    size_t GetMacHeaderSize() const;

    /* Frame Body Data */
    size_t GetFixedParaSize() const;
    uchar_t* GetTimeStamp();
    uint16_t GetBeaconInterval() const;

    /* Capability Information */
    uchar_t GetEssOfCapabilityBit() const;
    uchar_t GetIbssStatusOfCapabilityBit() const;
    uchar_t GetPrivacyOfCapabilityBit() const;

    /* the following function is provided just for debug */
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

    ProbeResponseFrame(const std::shared_ptr<uchar_t>& buf, size_t bufSize);
    ~ProbeResponseFrame();

    size_t GetMacHeaderSize() const;
    size_t GetFixedParaSize() const;
    uchar_t* GetTimeStamp();
    uint16_t GetBetweenInterval() const;

    uchar_t GetEssCapabilityBit() const;
    uchar_t GetIbssStatusBit() const;
    uchar_t GetPrivacyBit() const;

    /* the following function is provided just for debug */
    void Put(std::ostream& os) const;
};

class ProbeRequestFrame: public ManagementFrame
{
public:
    ProbeRequestFrame(const std::shared_ptr<uchar_t>& buf, size_t bufSize);
    ~ProbeRequestFrame();

    size_t GetMacHeaderSize() const;
    size_t GetFixedParaSize() const;
};

/*
Refer 80211.FrameFormat.pdf page 34 for detail about data frame.

802.11 Mac Header for Data Frame:
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Frame Control         |     Duration ID               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Address 1                           =
++-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=            Address 1          |      Address 2                =
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=                           Address 2                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Address 3                          =
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=            Address 3          |         Seq-Ctl               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Address 4 (only when ToDs == 1 && FromDs ==1)         =
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=                               |QosControl(only subtype bit4=1)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Frame Body  ... ...(variable)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Addressing and DS Bits (BSSID is MAC address of AP WLAN interface):
Function          To Ds   From Ds   Address 1   Address 2   Address 3   Address 4
                                   (recevier)  (Transmiter)
----------------  ------  -------  ----------  -----------  ----------  ----------
IBSS              0       0        DA          SA           BSSID       not used
To Ap (infra.)    1       0        BSSID       SA           DA          not used
From Ap(infra.)   0       1        DA          BSSID        SA          not used
WDS (bridge)      1       1        RA          TA           DA          SA

1) WEP Data Frame, Frame Body of 802.11 Frame (flowing the Mac Header)
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     WEP Initialization Vector                 | WEP Key Index |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    *************
|   LLC DSAP    |    LLC DSAP   |  LLC Control  | SNAP Org Code =                *
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                *
=                     SNAP Org Code             |  SNAP Type    |    ciphertext  *
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                *
|                      Data  ... ...(variable)                  |                *
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    *************
|                            WEP ICV                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
class DataFrame: public H802dot11
{
public: 
    DataFrame(const std::shared_ptr<uchar_t>& buf, size_t bufSize);
    ~DataFrame();

    Mac GetDestMac() const;
    Mac GetSrcMac() const;
    Mac GetBssid() const;
    std::string GetEssid() const;
    size_t GetMacHeaderSize() const;

    /* Frame Body Data */
    size_t GetWepParaTotalSize() const;
    uchar_t* GetWepIvPtr() const;
    uchar_t* GetWepKeyIndexPtr() const;
    uchar_t* GetWepIcvPtr() const;

    /* the following function is provided just for debug */
    void Put(std::ostream& os) const;
};

H802dot11* CreateFrame(const std::shared_ptr<uchar_t>& buf, size_t bufSize);

class WepParameter
{
public:
    static size_t GetSize() 
    {
        return 8;
    }

private:
    uchar_t initializationVector[3];
    uchar_t keyIndex;
    uchar_t integrityCheckValue[4];
};

class LlcSnap
{
public:
    static size_t GetSize() {return 8;}
    static const uchar_t* GetLlcSnapArp() 
    {
        static const uchar_t* llcSnapArp = (uchar_t*)"\xAA\xAA\x03\x00\x00\x00\x08\x06";
        return llcSnapArp;
    }
    static const uchar_t* GetLlcSnapIp()
    {
        static const uchar_t* llcSnapIp = (uchar_t*)"\xAA\xAA\x03\x00\x00\x00\x08\x00";
        return llcSnapIp;
    }
};

CxxEndNameSpace
#endif
