#ifndef _AccessPoint_h_
#define _AccessPoint_h_

#include "Types.h"
#include "Station.h"
CxxBeginNameSpace(Router)

class Ap
{
public:
    typedef MapIterator<std::map<Mac, St>::iterator> Iterator;
    typedef MapIterator<std::map<Mac, St>::const_iterator> ConstIterator;

    Ap(Mac const&, CryptMode);
    Ap(Ap const&);
    std::string GetEssid() const;
    void SetEssid(const std::string&);
    Mac const& GetBssid() const;
    CryptMode GetCrypt() const;
    void SetCrypt(CryptMode crypt);

    std::pair<Iterator, bool> Insert(St const&);
    Iterator Begin();
    Iterator End();
    ConstIterator CBegin() const;
    ConstIterator CEnd() const;

    Iterator Find(Mac const&);
    ConstIterator Find(Mac const&) const;

    /* the following function is provided just for debug */
    void Put(std::ostream& os) const;

private:   
    Ap();

private:
    Mac bssid;
    std::string essid;
    CryptMode crypt;
    std::map<Mac, St> stList;
};
std::ostream& operator << (std::ostream& os, Ap const& ap);

class Aps
{
public:
    typedef MapIterator<std::map<Mac, Ap>::iterator> Iterator;
    typedef MapIterator<std::map<Mac, Ap>::const_iterator> ConstIterator;

    std::pair<Iterator, bool> Insert(Ap const&);
    Iterator Begin();
    Iterator End();
    ConstIterator CBegin() const;
    ConstIterator CEnd() const;

    Iterator Find(Mac const&);
    ConstIterator Find(Mac const&) const;

    static Aps& GetInstance();

    /* the following function is provided just for debug */
    void Put(std::ostream& os) const;

private:
    Aps() {}
    std::map<Mac, Ap> apList;
};
std::ostream& operator << (std::ostream& os, Aps const& aps);

CxxEndNameSpace
#endif