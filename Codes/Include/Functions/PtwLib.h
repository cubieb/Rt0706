#ifndef _PtwLib_h_
#define _PtwLib_h_

CxxBeginNameSpace(Router)
// Number of bytes we use for our table of seen IVs, this is (2^24)/8
#define PtwIvTableSize 2097152

// How many sessions do we use to check if a guessed key is correct
// 10 seems to be a reasonable choice
// Its now the number of sessions for selecting 10 at a random position
#define PtwControlSessions 10000

// The maximum possible length of the main key, 13 is the maximum for a 104 bit key
#define PtwMaxKeysBytes 29

// How long the IV is, 3 is the default value for WEP
#define PtwIvByte 3

// How many bytes of a keystream we collect, 16 are needed for a 104 bit key
#define PtwKeysOfKeyStream 32

// The MAGIC VALUE!!
#define PtwMagicValue 256

// We use this to keep track of the outputs of A_i
struct PtwTableEntry
{
	// How often the value b appeard as an output of A_i
	uint_t votes;
	uchar_t b;
} ;

// A recovered session
struct PtwSession
{
    // The IV used in this session
    uchar_t iv[PtwIvByte];
    // The keystream used in this session
    uchar_t keyStream[PtwKeysOfKeyStream];
    // Weight for this session
    uint_t weight;
} ;

typedef int (*rc4test_func)(uchar_t *key, int keylen, uchar_t *iv, uchar_t *keyStream);

// The state of an attack
// You should usually never modify these values manually
class PtwAttackState
{
public:
    PtwAttackState(): allSessions(4096)
    {
        packetsNumber = 0;
        //std::for_each(iv, iv + PtwIvTableSize, [](uchar_t& v) {v=0;});
        sessionsNumber = 0;

        size_t i, j;
        for (i = 0; i < PtwMaxKeysBytes; ++i)
        {
            for (j = 0; j < PtwMagicValue; ++j)
            {
                table[i][j].b = j;
            }
        }
    }

private:
    // How many unique packets or IVs have been collected
    uint_t packetsNumber;
    // Table to check for duplicate IVs
    //uchar_t iv[PtwIvTableSize];
    // How many sessions for checking a guessed key have been collected
    uint_t sessionsNumber;
    // The actual recovered sessions
    PtwSession sessions[PtwControlSessions];
    // The table with votes for the key byte sums
    PtwTableEntry table[PtwMaxKeysBytes][PtwMagicValue];
    // Sessions for the original klein attack
    std::vector<PtwSession> allSessions;

    // rc4test function, optimized if available
    rc4test_func rc4test;
} ;

CxxEndNameSpace
#endif