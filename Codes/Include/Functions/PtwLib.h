#ifndef _PtwLib_h_
#define _PtwLib_h_

CxxBeginNameSpace(Router)

/* 1 byte char can express 256 unsigned chars */
#define N               256

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

/**********************class PtwValidateChar**********************/
class PtwValidateChar
{
public:
    static PtwValidateChar& GetInstance()
    {
        static PtwValidateChar instance;
        return instance;
    }

    bool operator[](uchar_t ch)
    {
        return validateChar[ch];
    }

private:
    PtwValidateChar()
    {
        for (size_t i = 0; i < N; ++i)
        {
            validateChar[i] = true;
        }
    }
    bool validateChar[N];
};

Mac& GetMyMac();

CxxEndNameSpace
#endif