#ifndef _SecurityHeader_h_
#define _SecurityHeader_h_

#include "Types.h"
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
class SecurityHeader
{
public:
    SecurityHeader() {}
    virtual ~SecurityHeader() {}

    virtual size_t GetIvSize() const = 0;
    virtual size_t GetHeaderSize() const = 0;
    virtual size_t GetTailerSize() const = 0;
    virtual CryptMode GetCryptMode() const = 0;
};

/**********************class WepHeader**********************/
class WepHeader: public SecurityHeader
{
public:
    WepHeader() {}
    ~WepHeader() {}

    size_t GetIvSize() const;
    size_t GetHeaderSize() const;
    size_t GetTailerSize() const;
    CryptMode GetCryptMode() const;
};

/**********************class TkipHeader**********************/
class TkipHeader: public SecurityHeader
{
public:
    TkipHeader()  {}
    ~TkipHeader() {}

    size_t GetIvSize() const;
    size_t GetHeaderSize() const;
    size_t GetTailerSize() const;
    CryptMode GetCryptMode() const;
};

/**********************Helper Function**********************/
#define KeyIndexOffset  3
class MacHeader;
SecurityHeader* CreateSecurityHeader(const MacHeader& macHeader);

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

CxxEndNameSpace
#endif