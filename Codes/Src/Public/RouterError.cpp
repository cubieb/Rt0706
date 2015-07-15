#include "SystemInclude.h"
#include "RouterError.h" 

using namespace std;
const char* router_category_impl::name() const
{
    return "Router error.";
}

string router_category_impl::message(int ev) const
{
    string ret;
    switch(ev)
    {
    case router_error_t::file_not_exists:
        ret = "file not exists";
        break;
    case router_error_t::bad_file_type:
        ret = "bad file type (supposed to be pcap format, 802.11 packet)";
        break;
    default:
        ret = "unknown error";
    }
    return ret;
}

error_condition router_category_impl::default_error_condition(int ev) const
{
    return error_condition(ev, *this);
}

const error_category& router_category()
{
    static router_category_impl instance;
    return instance;
}

error_code make_error_code(router_error_t e)
{
    return error_code(static_cast<int>(e), router_category());
}

error_condition make_error_condition(router_error_t e)
{
    return error_condition(static_cast<int>(e), router_category());
}

