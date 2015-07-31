
#ifndef _Rc4_h_
#define _Rc4_h_

CxxBeginNameSpace(Router)

class Rc4
{
public:
    Rc4(const uchar_t* key, size_t len, uint_t round = 256);
    void Encrypt(const uchar_t* plantext, size_t len, uchar_t* ciphertext);

    /* the following function is provided just for debug */
    void Put(std::ostream& os) const;
    uint_t GetX() {return x;}
    uint_t GetY() {return y;}
    uint_t* GetData() {return data;}
private:
    uint_t x, y;
    uint_t data[256];
};

std::ostream& operator << (std::ostream& os, Rc4 const& rc4);


CxxEndNameSpace /*Router*/



#endif /* _Rc4_h_ */

