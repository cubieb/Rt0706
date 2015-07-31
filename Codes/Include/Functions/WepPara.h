#ifndef _WepPara_h_
#define _WepPara_h_

CxxBeginNameSpace(Router)

class WepPara
{
public:
    static size_t GetIvSize()
    {
        return 3;
    }

    static size_t GetIvKeyIndexSize()
    {
        return 4;
    }

    static size_t GetTotalSize()
    {
        return 8;
    }
};

CxxEndNameSpace
#endif