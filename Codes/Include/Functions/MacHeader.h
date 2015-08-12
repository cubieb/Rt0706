
#ifndef _H802dot11_h_
#define _H802dot11_h_

#include "Types.h"
CxxBeginNameSpace(Router)

/* OSI network model
               . +-+-+-+-+-+-+-+-+-+
              .  |      Session    |  
             .   +-+-+-+-+-+-+-+-+-+
            .    +-+-+-+-+-+-+-+-+-+
TCP/IP(etc) .    |     Transport   |  
            .    +-+-+-+-+-+-+-+-+-+
             .   +-+-+-+-+-+-+-+-+-+
              .  |     Network     |  
               . +-+-+-+-+-+-+-+-+-+

                 +-+-+-+-+-+-+-+-+-+
                 |    Data Link    |  802.2 Logical Link Control(LLC)
IEEE 802.11a,b,g +-----------------+
                 |     Layer       |  802.11 MAC Header (a,b,g identical)(If wired networks, this is Data Link Header)
                 +-+-+-+-+-+-+-+-+-+

                 +-+-+-+-+-+-+-+-+-+
                 |  Physical Layer |  802.11 PLCP header distinct
                 +-+-+-+-+-+-+-+-+-+
*/

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
    DataAndCfAckAndCfPoll = 0x3,
    Null                  = 0x4,
    CfAck                 = 0x5,
    CfPoll                = 0x6,
    CfAckAndCfPoll        = 0x7,
    QosData                  = 0x8,
    QosDataAndCfAck          = 0x9,
    QosDataAndCfPoll         = 0xa, 
    QosDataAndCfAckAndCfPoll = 0xb,
    QosNull                  = 0xc,
    DataReserved             = 0xd,
    QosCfPoll                = 0xe,
    QosCfAckAndCfPoll        = 0xf
};

enum MacHeaderSize: uint32_t
{
    ManagementHeaderSize = 24,
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
};

/*
802.11n Mac Frame:
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Frame Control         |     Duration ID               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Address 1                           =
++-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=            Address 1          |       Address 2 (opt)         =
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=                           Address 2 (opt)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Address 3 (opt)                     =
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=       Address 3 (opt)         |         Seq-Ctl (opt)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Address 4 (opt)                    =
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=       Address 4 (opt)         |      Qos Control (opt)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Frame Body (opt) ...                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              FCS                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

7.1.3.1 Frame Control field
  B0   B1 B2 B3 B4   B7 B8 B9   B10  B11   B12 B13  B14
+--------+-----+-------+--+----+----+-----+---+----+---------+
|Protocol|Type |Subtype|To|From|More|Retry|Pwr|More|Protected|
|Version |     |       |Ds|Ds  |Frag|     |Mgt|Data|Frame    |
+--------+-----+-------+--+----+----+-----+---+----+---------+
*/
/**********************class MacHeader**********************/
class MacHeader
{
public:
    MacHeader(const std::shared_ptr<uchar_t>& theBuf, size_t theBufSize);
    virtual ~MacHeader();
        
    /* begin, frame control field. */
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
    /* end, frame control field. */
            
    uchar_t* GetBufPtr() const;
    size_t GetBufSize() const;

    virtual uchar_t* GetFrameBodyPtr() const = 0;
    virtual size_t GetFrameBodySize() const = 0;

    virtual Mac GetDstMac() const = 0;
    virtual Mac GetSrcMac() const = 0;
    virtual Mac GetBssid() const = 0;
    
    /* the following function is provided just for debug */
    virtual void Put(std::ostream& os) const;

protected:
    std::shared_ptr<uchar_t> buf;
    size_t  bufSize;
};

inline std::ostream& operator << (std::ostream& os, const MacHeader& h802dot11)
{
    h802dot11.Put(os);
    return os;
}

class ManagementFrame: public MacHeader
{
public:
    ManagementFrame(const std::shared_ptr<uchar_t>& buf, size_t bufSize);
    virtual ~ManagementFrame();

    Mac GetDstMac() const;
    Mac GetSrcMac() const;
    Mac GetBssid() const;
    std::string GetEssid() const;

    virtual uchar_t* GetFrameBodyPtr() const;
    virtual size_t GetFrameBodySize() const;

    virtual void Put(std::ostream& os) const;

protected:
    /* Management Frame's option start from FrameBodyPtr + FixedParaSize, 
       MacHeaderSize and FixedParaSize is different for distinct Management Frame.
     */
    virtual size_t GetFixedParaSize() const = 0;

};

/**********************class AssociationRequestFrame**********************/
class AssociationRequestFrame: public ManagementFrame
{
public:
    AssociationRequestFrame(const std::shared_ptr<uchar_t>& buf, size_t bufSize);
    ~AssociationRequestFrame();

    static MacHeader* CreateInstance(const std::shared_ptr<uchar_t>& buf, size_t bufSize)
    {
        return new AssociationRequestFrame(buf, bufSize);
    }
    /* the following function is provided just for debug */
    void Put(std::ostream& os) const;

protected:
    size_t GetFixedParaSize() const;
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
/**********************class BeaconFrame**********************/
class BeaconFrame: public ManagementFrame
{
public:
    BeaconFrame(const std::shared_ptr<uchar_t>& buf, size_t bufSize);
    ~BeaconFrame();

    static MacHeader* CreateInstance(const std::shared_ptr<uchar_t>& buf, size_t bufSize)
    {
        return new BeaconFrame(buf, bufSize);
    }
    /* the following function is provided just for debug */
    void Put(std::ostream& os) const;

protected:
    size_t GetFixedParaSize() const;
};

/**********************class ProbeRequestFrame**********************/
class ProbeRequestFrame: public ManagementFrame
{
public:
    ProbeRequestFrame(const std::shared_ptr<uchar_t>& buf, size_t bufSize);
    ~ProbeRequestFrame();

    static MacHeader* CreateInstance(const std::shared_ptr<uchar_t>& buf, size_t bufSize)
    {
        return new ProbeRequestFrame(buf, bufSize);
    }
    /* the following function is provided just for debug */
    void Put(std::ostream& os) const;

protected:
    size_t GetFixedParaSize() const;
};

/**********************class ProbeResponseFrame**********************/
class ProbeResponseFrame: public ManagementFrame
{
public:
    ProbeResponseFrame(const std::shared_ptr<uchar_t>& buf, size_t bufSize);
    ~ProbeResponseFrame();

    static MacHeader* CreateInstance(const std::shared_ptr<uchar_t>& buf, size_t bufSize)
    {
        return new ProbeResponseFrame(buf, bufSize);
    }
    /* the following function is provided just for debug */
    void Put(std::ostream& os) const;

protected:
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
IBSS              0       0        RA=DA       TA=SA        BSSID       not used
From Ap(infra.)   0       1        RA=DA       TA=BSSID     SA          not used
To Ap (infra.)    1       0        RA=BSSID    TA=SA        DA          not used
WDS (bridge)      1       1        RA          TA=TA        DA          SA

"Note that Address 1 always holds the receiver address of the intended receiver 
(or, in the case of multicast frames, receivers), and that Address 2 always holds 
the address of the STA that is transmitting the frame."
*/
/**********************class DataFrame**********************/
class DataFrame: public MacHeader
{
public:
    DataFrame(const std::shared_ptr<uchar_t>& buf, size_t bufSize);
    ~DataFrame();

    uchar_t* GetFrameBodyPtr() const;
    size_t GetFrameBodySize() const;

    Mac GetDstMac() const;  
    Mac GetSrcMac() const;  
    Mac GetBssid() const;
    std::string GetEssid() const;

    static MacHeader* CreateInstance(const std::shared_ptr<uchar_t>& buf, size_t bufSize)
    {
        return new DataFrame(buf, bufSize);
    }
    /* the following function is provided just for debug */
    void Put(std::ostream& os) const;

private:
    size_t GetMacHeaderSize() const;
};

/**********************class CreateMacHeader**********************/
typedef std::function<MacHeader*(const std::shared_ptr<uchar_t>& buf, size_t bufSize)> MacHeaderCreator;

class MacHeaderFactor
{
public:
    void Register(uchar_t type, uchar_t subtype, MacHeaderCreator creator);
    MacHeader* Create(uchar_t type, uchar_t subtype, const std::shared_ptr<uchar_t>& buf, size_t bufSize);

    static MacHeaderFactor& GetInstance()
    {
        static MacHeaderFactor instance;
        return instance;
    }

private:
    MacHeaderFactor() { /* do nothing */ }
    std::map<uchar_t, MacHeaderCreator> creatorMap;
};

class AutoRegisterSuite
{
public:
    AutoRegisterSuite(uchar_t type, uchar_t subtype, MacHeaderCreator creator)
        : factor(MacHeaderFactor::GetInstance())
    {
        factor.Register(type, subtype, creator);
    }

private:
    MacHeaderFactor& factor;
};


#define MacHeaderCreatorRgistration(type, subtype, creator)      \
    static AutoRegisterSuite  JoinName(macHeaderCreator, __LINE__)(type, subtype, creator)

MacHeader* CreateMacHeader(const std::shared_ptr<uchar_t>& buf, size_t bufSize);

CxxEndNameSpace
#endif
