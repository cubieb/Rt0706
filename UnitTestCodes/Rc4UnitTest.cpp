#include "SystemInclude.h"
#include "Common.h"
#include "Rc4.h"

#include "Rc4UnitTest.h"

using namespace std;
using namespace Router;

CxxBeginNameSpace(UnitTest)

#ifdef __linux
ostream& operator << (ostream& os, RC4_KEY const& rc4)
{
    cout << "x and y : x = " << rc4.x << ", y = " << rc4.y << endl;
    cout << "Key list:" << endl;
    cout << MemStream<uint_t>(rc4.data, 256);
    return os;
}
#endif

CPPUNIT_TEST_SUITE_REGISTRATION( Rc4TestCase );
void Rc4TestCase::setUp()
{}

/*
to verify the correction, use the following CLI command:
echo "this is a test" | openssl enc -rc4 -nopad -nosalt -K 31313131323232323333333334343434 | xxd
*/
void Rc4TestCase::TestRc4Encryption()
{
    uchar_t password[16] =
    {
        0x31,0x31,0x31,0x31,
        0x32,0x32,0x32,0x32,
        0x33,0x33,0x33,0x33,
        0x34,0x34,0x34,0x34,
    };
    char plaintext[64]={"this is a test"};
    size_t textLen = strlen(plaintext);
    cout << endl;
    cout << "plaintext  : " << MemStream<uchar_t>(reinterpret_cast<uchar_t*>(plaintext), textLen) << endl;
    cout << "key        : " << MemStream<uchar_t>(password, textLen) << endl;

#ifdef __linux
    uchar_t ciphertext1[64];
    RC4_KEY rc4Key = {0, 0, {0}};
    RC4_set_key(&rc4Key, sizeof(password), password);
    RC4(&rc4Key, textLen, (const uchar_t*)plaintext, ciphertext1);
    cout << "ciphertext1: " << MemStream<uchar_t>(ciphertext1, textLen) << endl;
    cout << rc4Key << endl;
#endif

    uchar_t ciphertext2[64];
    Rc4 rc4(password, sizeof(password));
    rc4.Encrypt((const uchar_t*)plaintext, textLen, ciphertext2);
    cout << "ciphertext2: " << MemStream<uchar_t>(ciphertext2, textLen) << endl;
    cout << rc4 << endl;

#ifdef __linux
    assert(rc4Key.x == rc4.GetX() && rc4Key.y == rc4.GetY());
    assert(memcmp(ciphertext1, ciphertext2, textLen) == 0);
#endif

    CPPUNIT_ASSERT( 1 == 1 );
} 

CxxEndNameSpace
