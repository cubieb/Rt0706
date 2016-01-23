#ifndef _UnitTest_h_
#define _UnitTest_h_

#include <cppunit/extensions/HelperMacros.h>

CxxBeginNameSpace(UnitTest)

class CrcTestCase : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(CrcTestCase);
    CPPUNIT_TEST(TestCrc32);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();

protected:
    void TestCrc32();
};

CxxEndNameSpace
#endif