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
|      TSC 1    |   WepSeed[1]  |      TSC 0    | Rsvd  |E|KeyID|
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

// How long the IV is, 3 is the default value for WEP
#define WepIvSize       3
#define WepKeyIndexSize 1
#define WepMaxKeySize   24
/* 1 byte char can express 256 chars */
#define N               256

class WepPara
{
public:
    static size_t GetIvSize()
    {
        return WepIvSize;
    }

    static size_t GetIvKeyIndexSize()
    {
        return WepIvSize + WepKeyIndexSize;
    }

    static size_t GetTotalSize()
    {
        return 8;
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