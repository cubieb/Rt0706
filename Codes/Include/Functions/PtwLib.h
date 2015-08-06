#ifndef _PtwLib_h_
#define _PtwLib_h_

CxxBeginNameSpace(Router)

/*
1) WEP parameter format, flowing the Mac Header
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

2) TKIP parameter format, flowing the Mac Header
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      TSC 1    |   WepSeed[1]  |      TSC 0    | Rsvd    |E| 1 |    1: Key Index
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Extended IV                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    *************
|   LLC DSAP    |    LLC DSAP   |  LLC Control  | SNAP Org Code =                *
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                *
=                     SNAP Org Code             |  SNAP Type    |    ciphertext  *
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                *
|                      Data  ... ...(variable)                  |                *
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    *************
|                            WEP ICV                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

E bit:

*/

enum class Crypt
{
    Wep  = 1,
    Tkip = 2
};

#define WepIvSize       3
#define WepKeyIndexSize 1
#define WepIcvSize      4

#define TkipIvSize      6
#define TkipHeaderSize  8
#define TkipTailerSize  4

#define WepMaxKeySize   24
/* 1 byte char can express 256 unsigned chars */
#define N               256

/**********************class ProcectMpduBase**********************/
class ProtectedMpduBase
{
public:
    ProtectedMpduBase() {}
    virtual ~ProtectedMpduBase() {}

    virtual size_t GetIvSize() const = 0;
    virtual size_t GetHeaderSize() const = 0;
    virtual size_t GetTailerSize() const = 0;
    virtual Crypt GetAlgorithm() = 0;
};

/**********************class WepMpdu**********************/
class WepMpdu: public ProtectedMpduBase
{
public:
    WepMpdu() {}
    ~WepMpdu() {}

    size_t GetIvSize() const
    {
        return WepIvSize;
    }

    size_t GetHeaderSize() const
    {
        return WepIvSize + WepKeyIndexSize;
    }

    size_t GetTailerSize() const
    {
        return TkipTailerSize;
    }

    Crypt GetAlgorithm()
    {
        return Crypt::Wep;
    }
};

/**********************class TkipMpdu**********************/
class TkipMpdu: public ProtectedMpduBase
{
public:
    TkipMpdu()  {}
    ~TkipMpdu() {}

    size_t GetIvSize() const
    {
        return TkipIvSize;
    }

    size_t GetHeaderSize() const
    {
        return TkipHeaderSize;
    }

    size_t GetTailerSize() const
    {
        return TkipTailerSize;
    }

    Crypt GetAlgorithm()
    {
        return Crypt::Tkip;
    }
};

/**********************Helper Function**********************/
#define KeyIndexOffset  3
class H802dot11;
ProtectedMpduBase* CreateProtectedMpdu(const H802dot11& h802dot11);

/* The frame body consists of the MSDU, or a fragment thereof, and a security header and trailer (if and only if
   the Protected Frame subfield in the Frame Control field is set to 1). The frame body is null (0 octets in
   length) in data frames of subtype Null (no data), CF-Ack (no data), CF-Poll (no data), and CF-Ack+CF-Poll
   (no data), regardless of the encoding of the QoS subfield in the Frame Control field.
 */
size_t CalcLayer3DataSize(const H802dot11& h802dot11);

/**********************class LlcSnap**********************/
class LlcSnap
{
public:
    static size_t GetSize() {return 8;}
    static const uchar_t* GetLlcSnapArp() 
    {
        static const uchar_t* llcSnapArp = (uchar_t*)"\xaa\xaa\x03\x00\x00\x00\x08\x06";
        return llcSnapArp;
    }
    static const uchar_t* GetLlcSnapIp()
    {
        static const uchar_t* llcSnapIp = (uchar_t*)"\xaa\xaa\x03\x00\x00\x00\x08\x00";
        return llcSnapIp;
    }
};

#define WepIvTableSize 0xFFFFFF /*  */
struct PswState
{
    /* Bitset to check for duplicate IVs. Every time we process a new IV, we set a bit. 
       We do not process the same IV for more than 1 time. 
     */
    std::bitset<WepIvTableSize> IvBits;

    /* How many packets(which's IV is unique) have been collected */
    uint_t pktNumber;

    // The table with votes for the keybytesums
    uint_t table[WepMaxKeySize][N];
};

CxxEndNameSpace
#endif