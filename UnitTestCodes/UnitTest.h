#ifndef _UnitTest_h_
#define _UnitTest_h_

#ifdef __linux
    #include <openssl/rc4.h>
#endif

CxxBeginNameSpace(UnitTest)

bool VerifyRc4Encrypt();

#ifdef __linux
    std::ostream& operator << (std::ostream& os, RC4_KEY const& rc4);
#endif

CxxEndNameSpace
#endif