#ifndef _PtwLib_h_
#define _PtwLib_h_

CxxBeginNameSpace(Router)

size_t CalcLayer3DataSize(const MacHeader& h802dot11);

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

Mac& GetMyMac();

CxxEndNameSpace
#endif