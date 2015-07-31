#include "SystemInclude.h"
#include "Common.h"
#include "Crc.h"

#include "CrcUnitTest.h"

using namespace std;
using namespace Router;

CxxBeginNameSpace(UnitTest)

CPPUNIT_TEST_SUITE_REGISTRATION(CrcTestCase);
void CrcTestCase::setUp()
{}

void CrcTestCase::TestCrc32()
{
    char buf[128];
    fstream txtFile("D:/Temp/tmp.txt", ios_base::in  | ios::binary);

    streampos start = txtFile.tellg();
    txtFile.seekg(0, ios::end);      
    streampos end = txtFile.tellg();
    size_t fileSize = static_cast<size_t>(end - start); 
    txtFile.seekp(0);
    txtFile.read(buf, fileSize);

    uint32_t crc32 = CalculateCrc32((uchar_t*)buf, fileSize);

    CPPUNIT_ASSERT(crc32 == 1);
} 

CxxEndNameSpace
