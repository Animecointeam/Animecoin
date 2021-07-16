// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Server/client environment: argument handling, config file parsing,
 * logging, thread wrappers
 */
#ifndef BITCOIN_UTIL_H
#define BITCOIN_UTIL_H

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "compat.h"
#include "fs.h"
#include "tinyformat.h"
#include "utiltime.h"

#include <atomic>
#include <exception>
#include <map>
#include <stdint.h>
#include <string>
#include <vector>

#include <boost/signals2/signal.hpp>
#include <boost/thread/condition_variable.hpp> // for boost::thread_interrupted
#include <boost/thread/exceptions.hpp>

static const bool DEFAULT_LOGIPS        = false;
static const bool DEFAULT_LOGTIMEMICROS = false;
static const bool DEFAULT_LOGTIMESTAMPS = true;
extern const char * const DEFAULT_DEBUGLOGFILE;

/** Signals for translation. */
class CTranslationInterface
{
public:
    /** Translate a message to the native language of the user. */
    boost::signals2::signal<std::string (const char* psz)> Translate;
};

extern std::map<std::string, std::string> mapArgs;
extern std::map<std::string, std::vector<std::string> > mapMultiArgs;
extern bool fDebug;
extern bool fPrintToConsole;
extern bool fPrintToDebugLog;
extern bool fLogTimestamps;
extern bool fLogTimeMicros;
extern bool fLogIPs;
extern std::atomic<bool> fReopenDebugLog;

extern CTranslationInterface translationInterface;

extern const char * const BITCOIN_CONF_FILENAME;
extern const char * const BITCOIN_PID_FILENAME;

/**
 * Translation function: Call Translate signal on UI interface, which returns a boost::optional result.
 * If no translation slot is registered, nothing is returned, and simply return the input.
 */
inline std::string _(const char* psz)
{
    boost::optional<std::string> rv = translationInterface.Translate(psz);
    return rv ? (*rv) : psz;
}

void SetupEnvironment();
bool SetupNetworking();

/** Return true if log accepts specified category */
bool LogAcceptCategory(const char* category);
/** Send a string to the log output */
int LogPrintStr(const std::string &str);

/** Get format string from VA_ARGS for error reporting */
template<typename... Args> std::string FormatStringFromLogArgs(const char *fmt, const Args&... args) { return fmt; }

#define LogPrintf(...) do { \
    std::string _log_msg_; /* Unlikely name to avoid shadowing variables */ \
    try { \
        _log_msg_ = tfm::format(__VA_ARGS__); \
    } catch (tinyformat::format_error &fmterr) { \
        /* Original format string will have newline so don't add one here */ \
        _log_msg_ = "Error \"" + std::string(fmterr.what()) + "\" while formatting log message: " + FormatStringFromLogArgs(__VA_ARGS__); \
    } \
    LogPrintStr(_log_msg_); \
} while(0)

#define LogPrint(category, ...) do { \
    if (LogAcceptCategory((category))) { \
        LogPrintf(__VA_ARGS__); \
    } \
} while(0)

template<typename... Args>
bool error(const char* fmt, const Args&... args)
{
    LogPrintStr("ERROR: " + tfm::format(fmt, args...) + "\n");
    return false;
}

void PrintExceptionContinue(const std::exception* pex, const char* pszThread);
void ParseParameters(int argc, const char*const argv[]);
void FileCommit(FILE *file);
bool TruncateFile(FILE *file, unsigned int length);
int RaiseFileDescriptorLimit(int nMinFD);
void AllocateFileRange(FILE *file, unsigned int offset, unsigned int length);
bool RenameOver(fs::path src, fs::path dest);
bool LockDirectory(const fs::path& directory, const std::string lockfile_name, bool probe_only=false);

/** Release all directory locks. This is used for unit testing only, at runtime
 * the global destructor will take care of the locks.
 */
void ReleaseDirectoryLocks();

bool TryCreateDirectory(const fs::path& p);
fs::path GetDefaultDataDir();
const fs::path &GetDataDir(bool fNetSpecific = true);
void ClearDatadirCache();
fs::path GetConfigFile(const std::string& confPath);
#ifndef WIN32
fs::path GetPidFile();
void CreatePidFile(const fs::path &path, pid_t pid);
#endif
void ReadConfigFile(const std::string& confPath, std::map<std::string, std::string>& mapSettingsRet, std::map<std::string, std::vector<std::string> >& mapMultiSettingsRet);
#ifdef WIN32
fs::path GetSpecialFolderPath(int nFolder, bool fCreate = true);
#endif
fs::path GetDebugLogPath();
bool OpenDebugLog();
void ShrinkDebugFile();
void runCommand(const std::string& strCommand);

/**
 * Most paths passed as configuration arguments are treated as relative to
 * the datadir if they are not absolute.
 *
 * @param path The path to be conditionally prefixed with datadir.
 * @param net_specific Forwarded to GetDataDir().
 * @return The normalized path.
 */
fs::path AbsPathForConfigVal(const fs::path& path, bool net_specific = true);

inline bool IsSwitchChar(char c)
{
#ifdef WIN32
    return c == '-' || c == '/';
#else
    return c == '-';
#endif
}

/**
 * Return string argument or default value
 *
 * @param strArg Argument to get (e.g. "-foo")
 * @param default (e.g. "1")
 * @return command-line argument or default value
 */
std::string GetArg(const std::string& strArg, const std::string& strDefault);

/**
 * Return integer argument or default value
 *
 * @param strArg Argument to get (e.g. "-foo")
 * @param default (e.g. 1)
 * @return command-line argument (0 if invalid number) or default value
 */
int64_t GetArg(const std::string& strArg, int64_t nDefault);

/**
 * Return boolean argument or default value
 *
 * @param strArg Argument to get (e.g. "-foo")
 * @param default (true or false)
 * @return command-line argument or default value
 */
bool GetBoolArg(const std::string& strArg, bool fDefault);

/**
 * Set an argument if it doesn't already have a value
 *
 * @param strArg Argument to set (e.g. "-foo")
 * @param strValue Value (e.g. "1")
 * @return true if argument gets set, false if it already had a value
 */
bool SoftSetArg(const std::string& strArg, const std::string& strValue);

/**
 * Set a boolean argument if it doesn't already have a value
 *
 * @param strArg Argument to set (e.g. "-foo")
 * @param fValue Value (e.g. false)
 * @return true if argument gets set, false if it already had a value
 */
bool SoftSetBoolArg(const std::string& strArg, bool fValue);

// Forces an arg setting. TODO: refactor args system.
void ForceSetArg(const std::string& strArg, const std::string& strValue);

/**
 * Format a string to be used as group of options in help messages
 *
 * @param message Group name (e.g. "RPC server options:")
 * @return the formatted string
 */
std::string HelpMessageGroup(const std::string& message);

/**
 * Format a string to be used as option description in help messages
 *
 * @param option Option message (e.g. "-rpcuser=<user>")
 * @param message Option description (e.g. "Username for JSON-RPC connections")
 * @return the formatted string
 */
std::string HelpMessageOpt(const std::string& option, const std::string& message);

void SetThreadPriority(int nPriority);
void RenameThread(const char* name);

/**
 * .. and a wrapper that just calls func once
 */
template <typename Callable> void TraceThread(const char* name,  Callable func)
{
    std::string s = strprintf("animecoin-%s", name);
    RenameThread(s.c_str());
    try
    {
        LogPrintf("%s thread start\n", name);
        func();
        LogPrintf("%s thread exit\n", name);
    }
    catch (const boost::thread_interrupted&)
    {
        LogPrintf("%s thread interrupt\n", name);
        throw;
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, name);
        throw;
    }
    catch (...) {
        PrintExceptionContinue(nullptr, name);
        throw;
    }
}

//! Substitute for C++14 std::make_unique.
template <typename T, typename... Args>
std::unique_ptr<T> MakeUnique(Args&&... args)
{
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

#endif // BITCOIN_UTIL_H
