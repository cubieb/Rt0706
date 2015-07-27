
#ifndef _Rc4_h_
#define _Rc4_h_

#ifdef _WIN32
    typedef struct rc4_key_st
    {
        uint_t x,y;
        uint_t data[256];
    } RC4_KEY;
#else
    #include <openssl/rc4.h>
#endif

CxxBeginNameSpace(Router)

class Rc4
{
public:
    Rc4(const uchar_t* key, size_t len);
    void Encrypt(const uchar_t* plantext, size_t len, uchar_t* ciphertext);

    /* the following function is provided just for debug */
    void Put(std::ostream& os) const;
    uint_t GetX() {return rc4Key.x;}
    uint_t GetY() {return rc4Key.y;}
private:
    RC4_KEY rc4Key;
};

std::ostream& operator << (std::ostream& os, Rc4 const& rc4);
std::ostream& operator << (std::ostream& os, RC4_KEY const& rc4);

void VerifyRc4Encrypt();

CxxEndNameSpace /*Router*/

#endif /* _Rc4_h_ */

