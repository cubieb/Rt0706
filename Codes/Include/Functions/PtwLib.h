#ifndef _PtwLib_h_
#define _PtwLib_h_

CxxBeginNameSpace(Router)

/* 1 byte char can express 256 unsigned chars */
#define N               256
#define WepMaxKeySize   24

/* wep iv fields is 3 bytes, so the table size is 2**24 */
#define WepIvTableSize 0xFFFFFF 

// The table with votes for the keybytesums
class PtwTable
{
public:
    typedef uint_t Entry[N];
    PtwTable(size_t keySize)
        : keySize(keySize), entry(new Entry[keySize], [](Entry* ptr){delete[] ptr;})
    {}

    Entry& operator[](size_t keyIndex)
    {
        return *(entry.get() + keyIndex);
    }

    size_t GetKeySize()
    {
        return keySize;
    }

private:
    size_t keySize;
    std::shared_ptr<Entry> entry;
};

/**********************class PtwState**********************/
class PtwState
{
public:
    PtwState(size_t keySize): ptwTable(keySize)
    {}
    /* Bitset to check for duplicate IVs. Every time we process a new IV, we set a bit. 
       We do not process the same IV for more than 1 time. 
     */
    std::bitset<WepIvTableSize> IvBits;

    /* How many packets(which's IV is unique) have been collected */
    uint_t pktNumber;

    // The table with votes for the keybytesums
    PtwTable ptwTable;
};

Mac& GetMyMac();

CxxEndNameSpace
#endif