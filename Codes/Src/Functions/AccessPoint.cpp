#include "SystemInclude.h"
#include "Common.h"
#include "Station.h"

#include "AccessPoint.h"

using namespace std;
CxxBeginNameSpace(Router)

Ap::Ap(Mac const& theBssid, CryptMode theCrypt) : bssid(theBssid), crypt(theCrypt)
{
}

Ap::Ap(Ap const& ap): bssid(ap.bssid), crypt(ap.crypt)
{
}

string Ap::GetEssid() const
{
    return essid;
}

void Ap::SetEssid(const string& essid)
{
    this->essid = essid;
}

Mac const&Ap:: GetBssid() const
{
    return bssid;
}

CryptMode Ap::GetCrypt() const
{
    return crypt;
}

void Ap::SetCrypt(CryptMode crypt)
{
    this->crypt = crypt;
}

pair<Ap::Iterator, bool> Ap::Insert(const St& st)
{
    pair<map<Mac, St>::iterator, bool> ret = stList.insert(make_pair(st.GetMac(), st));

    return make_pair(Iterator(ret.first), ret.second);
}

Ap::Iterator Ap::Begin()
{
    return Iterator(stList.begin());
}

Ap::Iterator Ap::End()
{
    return Iterator(stList.end());
}

Ap::ConstIterator Ap::CBegin() const
{
    return ConstIterator(stList.cbegin());
}

Ap::ConstIterator Ap::CEnd() const
{
    return ConstIterator(stList.cend());
}

Ap::Iterator Ap::Find(const Mac& mac)
{
    return Iterator(stList.find(mac));
}

Ap::ConstIterator Ap::Find(const Mac& mac) const
{
    return ConstIterator(stList.find(mac));
}

void Ap::Put(ostream& os) const
{
    os << bssid;
}

ostream& operator << (ostream& os, Ap const& ap)
{
    ap.Put(os);
    return os;
}

/**************** Aps ****************/
pair<Aps::Iterator, bool> Aps::Insert(Ap const& ap)
{
    pair<map<Mac, Ap>::iterator, bool> ret = apList.insert(make_pair(ap.GetBssid(), ap));

    return make_pair(Iterator(ret.first), ret.second);
}

Aps::Iterator Aps::Begin()
{
    return Iterator(apList.begin());
}

Aps::Iterator Aps::End()
{
    return Iterator(apList.end());
}

Aps::ConstIterator Aps::CBegin() const
{
    //here,  cbegin() and begin() has the same effect.  there are two definition
    // for map::begin(),  
    //1 iterator begin() _NOEXCEPT
    //2 const_iterator begin() const _NOEXCEPT
    return ConstIterator(apList.cbegin());
}

Aps::ConstIterator Aps::CEnd() const
{
    return ConstIterator(apList.cend());
}

Aps::Iterator Aps::Find(Mac const& bssid)
{
    return Iterator(apList.find(bssid));
}

Aps::ConstIterator Aps::Find(Mac const& bssid) const
{
    return ConstIterator(apList.find(bssid));
}

Aps& Aps::GetInstance()
{
    static Aps instance;
    return instance;
}

void Aps::Put(ostream& os) const
{
    map<Mac, Ap>::const_iterator iter;
    for (iter = apList.begin(); iter != apList.end(); ++iter)
    {
        os << iter->second << endl;
    }
}

ostream& operator << (ostream& os, Aps const& aps)
{
    aps.Put(os);
    return os;
}

CxxEndNameSpace