#include "fs.h"

#include <boost/filesystem.hpp>

namespace fsbridge {

FILE *fopen(const fs::path& p, const char *mode)
{
#ifndef WIN32
    return ::fopen(p.string().c_str(), mode);
#else
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>,wchar_t> utf8_cvt;
    return ::_wfopen(p.wstring().c_str(), utf8_cvt.from_bytes(mode).c_str());
#endif
}

FILE *freopen(const fs::path& p, const char *mode, FILE *stream)
{
    return ::freopen(p.string().c_str(), mode, stream);
}

} // fsbridge