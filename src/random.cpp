// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "random.h"

#include "crypto/common.h"
#include "crypto/sha512.h"
#include "support/cleanse.h"
#ifdef WIN32
#include "compat.h" // for Windows API
#include <wincrypt.h>
#endif
#include "serialize.h"        // for begin_ptr(vec)
#include "util.h"             // for LogPrint()
#include "utilstrencodings.h" // for GetTime()

#include <stdlib.h>
#include <limits>

#ifndef WIN32
#include <sys/time.h>
#endif

#include <mutex>

#include <openssl/err.h>
#include <openssl/rand.h>

static void RandFailure()
{
    LogPrintf("Failed to read randomness, aborting\n");
    abort();
}

static inline int64_t GetPerformanceCounter()
{
    int64_t nCounter = 0;
#ifdef WIN32
    QueryPerformanceCounter((LARGE_INTEGER*)&nCounter);
#else
    timeval t;
    gettimeofday(&t, nullptr);
    nCounter = (int64_t)(t.tv_sec * 1000000 + t.tv_usec);
#endif
    return nCounter;
}

#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
static std::atomic<bool> hwrand_initialized{false};
static bool rdrand_supported = false;
static constexpr uint32_t CPUID_F1_ECX_RDRAND = 0x40000000;
static void RDRandInit()
{
    //! When calling cpuid function #1, ecx register will have this set if RDRAND is available.
    // Avoid clobbering ebx, as that is used for PIC on x86.
    uint32_t eax, tmp, ecx, edx;
    __asm__ ("mov %%ebx, %1; cpuid; mov %1, %%ebx": "=a"(eax), "=g"(tmp), "=c"(ecx), "=d"(edx) : "a"(1));
    if (ecx & CPUID_F1_ECX_RDRAND) {
        LogPrintf("Using RdRand as entropy source\n");
        rdrand_supported = true;
    }
    hwrand_initialized.store(true);
}
#else
static void RDRandInit() {}
#endif

static bool GetHWRand(unsigned char* ent32) {
#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
    assert(hwrand_initialized.load(std::memory_order_relaxed));
    if (rdrand_supported) {
        uint8_t ok;
        // Not all assemblers support the rdrand instruction, write it in hex.
#ifdef __i386__
        for (int iter = 0; iter < 4; ++iter) {
            uint32_t r1, r2;
            __asm__ volatile (".byte 0x0f, 0xc7, 0xf0;" // rdrand %eax
                              ".byte 0x0f, 0xc7, 0xf2;" // rdrand %edx
                              "setc %2" :
                              "=a"(r1), "=d"(r2), "=q"(ok) :: "cc");
            if (!ok) return false;
            WriteLE32(ent32 + 8 * iter, r1);
            WriteLE32(ent32 + 8 * iter + 4, r2);
        }
#else
        uint64_t r1, r2, r3, r4;
        __asm__ volatile (".byte 0x48, 0x0f, 0xc7, 0xf0, " // rdrand %rax
                                "0x48, 0x0f, 0xc7, 0xf3, " // rdrand %rbx
                                "0x48, 0x0f, 0xc7, 0xf1, " // rdrand %rcx
                                "0x48, 0x0f, 0xc7, 0xf2; " // rdrand %rdx
                          "setc %4" :
                          "=a"(r1), "=b"(r2), "=c"(r3), "=d"(r4), "=q"(ok) :: "cc");
        if (!ok) return false;
        WriteLE64(ent32, r1);
        WriteLE64(ent32 + 8, r2);
        WriteLE64(ent32 + 16, r3);
        WriteLE64(ent32 + 24, r4);
#endif
        return true;
    }
#endif
    return false;
}

void RandAddSeed()
{
    // Seed with CPU performance counter
    int64_t nCounter = GetPerformanceCounter();
    RAND_add(&nCounter, sizeof(nCounter), 1.5);
    memory_cleanse((void*)&nCounter, sizeof(nCounter));
}

static void RandAddSeedPerfmon()
{
    RandAddSeed();

    // This can take up to 2 seconds, so only do it every 10 minutes
    static int64_t nLastPerfmon;
    if (GetTime() < nLastPerfmon + 10 * 60)
        return;
    nLastPerfmon = GetTime();

#ifdef WIN32
    // Don't need this on Linux, OpenSSL automatically uses /dev/urandom
    // Seed with the entire set of perfmon data
    std::vector<unsigned char> vData(250000, 0);
    long ret = 0;
    unsigned long nSize = 0;
    const size_t nMaxSize = 10000000; // Bail out at more than 10MB of performance data
    while (true) {
        nSize = vData.size();
        ret = RegQueryValueExA(HKEY_PERFORMANCE_DATA, "Global", nullptr, nullptr, begin_ptr(vData), &nSize);
        if (ret != ERROR_MORE_DATA || vData.size() >= nMaxSize)
            break;
        vData.resize(std::max((vData.size() * 3) / 2, nMaxSize)); // Grow size of buffer exponentially
    }
    RegCloseKey(HKEY_PERFORMANCE_DATA);
    if (ret == ERROR_SUCCESS) {
        RAND_add(begin_ptr(vData), nSize, nSize / 100.0);
        memory_cleanse(begin_ptr(vData), nSize);
        LogPrint("rand", "%s: %lu bytes\n", __func__, nSize);
    } else {
        static bool warned = false; // Warn only once
        if (!warned) {
            LogPrintf("%s: Warning: RegQueryValueExA(HKEY_PERFORMANCE_DATA) failed with code %i\n", __func__, ret);
            warned = true;
        }
    }
#endif
}

/** Get 32 bytes of system entropy. */
static void GetOSRand(unsigned char *ent32)
{
#ifdef WIN32
    HCRYPTPROV hProvider;
    int ret = CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    if (!ret) {
        RandFailure();
    }
    ret = CryptGenRandom(hProvider, 32, ent32);
    if (!ret) {
        RandFailure();
    }
    CryptReleaseContext(hProvider, 0);
#else
    int f = open("/dev/urandom", O_RDONLY);
    if (f == -1) {
        RandFailure();
    }
    int have = 0;
    do {
        ssize_t n = read(f, ent32 + have, 32 - have);
        if (n <= 0 || n + have > 32) {
            RandFailure();
        }
        have += n;
    } while (have < 32);
    close(f);
#endif
}

void GetRandBytes(unsigned char* buf, int num)
{
    if (RAND_bytes(buf, num) != 1) {
        RandFailure();
    }
}

static std::mutex cs_rng_state;
static unsigned char rng_state[32] = {0};
static uint64_t rng_counter = 0;

void GetStrongRandBytes(unsigned char* out, int num)
{
    assert(num <= 32);
    CSHA512 hasher;
    unsigned char buf[64];

    // First source: OpenSSL's RNG
    RandAddSeedPerfmon();
    GetRandBytes(buf, 32);
    hasher.Write(buf, 32);

    // Second source: OS RNG
    GetOSRand(buf);
    hasher.Write(buf, 32);

    // Third source: HW RNG, if available.
    if (GetHWRand(buf)) {
        hasher.Write(buf, 32);
    }

    // Combine with and update state
    {
        std::unique_lock<std::mutex> lock(cs_rng_state);
        hasher.Write(rng_state, sizeof(rng_state));
        hasher.Write((const unsigned char*)&rng_counter, sizeof(rng_counter));
        ++rng_counter;
        hasher.Finalize(buf);
        memcpy(rng_state, buf + 32, 32);
    }

    // Produce output
    memcpy(out, buf, num);
    memory_cleanse(buf, 64);
}

uint64_t GetRand(uint64_t nMax)
{
    if (nMax == 0)
        return 0;

    // The range of the random source must be a multiple of the modulus
    // to give every possible output value an equal possibility
    uint64_t nRange = (std::numeric_limits<uint64_t>::max() / nMax) * nMax;
    uint64_t nRand = 0;
    do {
        GetRandBytes((unsigned char*)&nRand, sizeof(nRand));
    } while (nRand >= nRange);
    return (nRand % nMax);
}

int GetRandInt(int nMax)
{
    return GetRand(nMax);
}

uint256 GetRandHash()
{
    uint256 hash;
    GetRandBytes((unsigned char*)&hash, sizeof(hash));
    return hash;
}

uint32_t insecure_rand_Rz = 11;
uint32_t insecure_rand_Rw = 11;
void seed_insecure_rand(bool fDeterministic)
{
    // The seed values have some unlikely fixed points which we avoid.
    if (fDeterministic) {
        insecure_rand_Rz = insecure_rand_Rw = 11;
    } else {
        uint32_t tmp;
        do {
            GetRandBytes((unsigned char*)&tmp, 4);
        } while (tmp == 0 || tmp == 0x9068ffffU);
        insecure_rand_Rz = tmp;
        do {
            GetRandBytes((unsigned char*)&tmp, 4);
        } while (tmp == 0 || tmp == 0x464fffffU);
        insecure_rand_Rw = tmp;
    }
}

void RandomInit()
{
    RDRandInit();
}