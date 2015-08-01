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
Rc4::Rc4(const uchar_t* key, size_t keySize, uint_t round)
{
    for (uint_t i = 0; i < 256; i++)
    {
        data[i]=i;
    }

    for (x=0, y=0; x < round; x++)
    {
        y = (y + data[x] + key[x & keySize]) & 0xff; /* Algorithm 1, line 4 */
        swap(data[x], data[y]);                   /* 5 */
    }
    if (round == 256)
    {
        x = 0;
        y = 0;
    }
}

/* algorithm:
i = (i + 1) mod 256
j = (j + S[i]) mod 256
swap(S[i], S[j])
return S[ (S[ i ] + S[j]) mod 256 ]

* reference: void RC4(RC4_KEY*, size_t, const unsigned char, unsigned char);
*/
void Rc4::Encrypt(const uchar_t* plantext, size_t len, uchar_t* ciphertext)
{
    size_t i;
    for (i = 0; i < len; ++i)
    {
        x = (x + 1) & 0xff;        /* Algorithm 2, line 2 */
        y = (data[x] + y) & 0xff;  /* 2 */
        swap(data[x], data[y]);    /* 3 */

        ciphertext[i] = data[(data[x] + data[y]) & 0xff] ^ plantext[i]; /* 4 */
    }
}

void Rc4::Put(ostream& os) const
{
    os << "x and y : x = " << x << ", y = " << y << endl;
    os << "Key list:" << endl;
    os << MemStream<uint_t>(data, 256);
}

ostream& operator << (ostream& os, Rc4 const& rc4)
{
    rc4.Put(os);
    return os;
}

CxxEndNameSpace /*Router*/