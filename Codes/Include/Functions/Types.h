#ifndef _Types_h_
#define _Types_h_

CxxBeginNameSpace(Router)

enum class CryptMode
{
    Wep  = 1,
    Tkip = 2
};

/*
 * From boost documentation:
 * The following piece of macro magic joins the two 
 * arguments together, even when one of the arguments is
 * itself a macro (see 16.3.1 in C++ standard).  The key
 * is that macro expansion of macro arguments does not
 * occur in JoinName2 but does in JoinName.
 */
#define JoinName(symbol1, symbol2)  JoinName1(symbol1, symbol2)
#define JoinName1(symbol1, symbol2) JoinName2(symbol1, symbol2)
#define JoinName2(symbol1, symbol2) symbol1##symbol2

/* class SecondType,  get element's type by iterator. 
   refer to <C++ Templates - The Complete Guide>, chapter 15.2.1 
   "Determining Element Types" for more detail.
 */
template <typename T>
class SecondType // primary template
{
public:
    typedef typename std::iterator_traits<T>::value_type::second_type Type;
};

template<class BaseIterator>
struct MapIterator: public BaseIterator
{
    typedef typename SecondType<BaseIterator>::Type SecondType;
    MapIterator() {}
    MapIterator(BaseIterator& iter): BaseIterator(iter) {}
    SecondType& operator*() const {return BaseIterator::operator ->()->second;}
    SecondType* operator->() const{return &(BaseIterator::operator ->()->second);}
};

CxxEndNameSpace
#endif