#ifndef _PtwLib_h_
#define _PtwLib_h_

CxxBeginNameSpace(Router)

    
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