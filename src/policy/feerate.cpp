// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "feerate.h"
#include "tinyformat.h"

#include <cmath>

const std::string CURRENCY_UNIT = "ANI";

CFeeRate::CFeeRate(const CAmount& nFeePaid, size_t nSize)
{
    if (nSize > 0)
        nSatoshisPerK = nFeePaid*1000/nSize;
    else
        nSatoshisPerK = 0;
}

CAmount CFeeRate::GetFee(size_t nSize) const
{
    // Be explicit that we're converting from a double to int64_t (CAmount) here.
    // We've previously had issues with the silent double->int64_t conversion.
    CAmount nFee{static_cast<CAmount>(std::ceil(nSatoshisPerK * nSize / 1000.0))};

    if (nFee == 0 && nSize != 0 && nSatoshisPerK > 0)
        nFee = CAmount(1);

    return nFee;
}

std::string CFeeRate::ToString() const
{
    return strprintf("%d.%05d %s/kB", nSatoshisPerK / COIN, nSatoshisPerK % COIN, CURRENCY_UNIT);
}
