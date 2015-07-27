#include "SystemInclude.h"
#include "Common.h"
#include "Rc4.h"

using namespace std;
CxxBeginNameSpace(Router)

/* algorithm:
for i = 0 to 255 do
    S[ i ] = i
end
j = 0
for i = 0 to 255 do
    j = (j+S[i]+K[i mod len(K)]) mod 256
    swap(S[i], s[j])
end
i = 0
j = 0

* reference: RC4_set_key()
*/
Rc4::Rc4(const uchar_t* key, size_t len)
{
    size_t id1, id2, idk;

    rc4Key.x = 0;
    rc4Key.y = 0;
    for (uint_t i = 0; i < 256; i++)
    {
        rc4Key.data[i]=i;
    }
    for (id1=0, id2=0, idk=0; id1 < 256; id1++, idk++)
    {
        if (idk == len)
            idk = 0;
        id2 = (id2 + rc4Key.data[id1] + key[idk]) & 0xff; /* Algorithm 1, line 4 */
        swap(rc4Key.data[id1], rc4Key.data[id2]);         /* 5 */
    }
}

/* algorithm:
i = (i + 1) mod 256
j = (j + S[i]) mod 256
swap(S[i], s[j])
return S[ (S[ i ] + S[j]) mod 256 ]

 * reference: void RC4(RC4_KEY*, size_t, const unsigned char, unsigned char);
 */
void Rc4::Encrypt(const uchar_t* plantext, size_t len, uchar_t* ciphertext)
{
    size_t i;
    uint_t* data = rc4Key.data;
    uint_t& x = rc4Key.x;
    uint_t& y = rc4Key.y;
    for (i = 0; i < len; ++i)
    {
        x = (x + 1) & 0xff;        /* Algorithm 2, line 2 */
        y=(data[x]+y)&0xff;        /* 2 */
        swap(data[x], data[y]);    /* 3 */

        ciphertext[i] = data[(data[x] + data[y]) & 0xff] ^ plantext[i]; /* 4 */
    }
}

void Rc4::Put(ostream& os) const
{
    os << "x and y : x = " << rc4Key.x << ", y = " << rc4Key.y << endl;
    os << "Key list:" << endl;
    os << MemStream<uint_t>(rc4Key.data, 256);
}

ostream& operator << (ostream& os, Rc4 const& rc4)
{
    rc4.Put(os);
    return os;
}

ostream& operator << (ostream& os, RC4_KEY const& rc4)
{
    cout << "x and y : x = " << rc4.x << ", y = " << rc4.y << endl;
    cout << "Key list:" << endl;
    cout << MemStream<uint_t>(rc4.data, 256);
    return os;
}

CxxEndNameSpace /*Router*/

using namespace Router;

// to verify the correction, use the following CLI command:
//system("echo \"this is a test file\" "
//    "| openssl enc -rc4 -nopad -nosalt -K 31313131323232323333333334343434 "
//    "| xxd");
void VerifyRc4Encrypt()
{
    uchar_t password[16] =
    {
        0x31,0x31,0x31,0x31,
        0x32,0x32,0x32,0x32,
        0x33,0x33,0x33,0x33,
        0x34,0x34,0x34,0x34,
    };
    char plaintext[64]={"0123456789."};
    size_t textLen = strlen(plaintext);

#ifdef __linux
    uchar_t ciphertext1[64];
    RC4_KEY rc4Key = {0, 0, {0}};
    RC4_set_key(&rc4Key, sizeof(password), password);
    RC4(&rc4Key, textLen, (const uchar_t*)plaintext, ciphertext1);
#endif

    uchar_t ciphertext2[64];
    Rc4 rc4(password, sizeof(password));
    rc4.Encrypt((const uchar_t*)plaintext, textLen, ciphertext2);
    cout << "plaintext  : " << MemStream<uchar_t>(reinterpret_cast<uchar_t*>(plaintext), textLen) << endl;
    cout << "key        : " << MemStream<uchar_t>(password, textLen) << endl;
    cout << "ciphertext2: " << MemStream<uchar_t>(ciphertext2, textLen) << endl;
    cout << rc4 << endl;

#ifdef __linux
    assert(rc4Key.x == rc4.GetX() && rc4Key.y == rc4.GetY());
    assert(memcmp(ciphertext1, ciphertext2, textLen) == 0);
#endif
    cout << "Succeed!" << endl;
}
