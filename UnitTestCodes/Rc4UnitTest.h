#ifndef _UnitTest_h_
#define _UnitTest_h_

#include <cppunit/extensions/HelperMacros.h>

#ifdef __linux
    #include <openssl/rc4.h>
#endif

CxxBeginNameSpace(UnitTest)

#ifdef __linux
    std::ostream& operator << (std::ostream& os, RC4_KEY const& rc4);
#endif

/* 
 * A test case that is designed to produce
 * example errors and failures
 *
 */

class Rc4TestCase : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( Rc4TestCase );
    CPPUNIT_TEST( TestRc4Encryption );
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();

protected:
    void TestRc4Encryption();
};

CxxEndNameSpace
#endif