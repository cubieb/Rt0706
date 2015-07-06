#ifndef _Option_h_
#define _Option_h_

CxxBeginNameSpace(Router)

class Option
{
public:
    Option();
    bool DoForceBssid();
    Mac Option::GetBssid();
    bool DoPtw() const;

    static Option& GetInstance();

private:
    bool doPtw;
};

CxxEndNameSpace
#endif