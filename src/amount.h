// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AMOUNT_H
#define BITCOIN_AMOUNT_H

#include <stdint.h>

typedef int64_t CAmount;

static const CAmount COIN = 100000;
static const CAmount CENT = 1000;

/** No amount larger than this (in satoshi) is valid */
static const CAmount MAX_MONEY = 2500000000 * COIN; // ~2.000 billion + ~8 million pa (inflation). Updated for Animecoin.
inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }

#endif //  BITCOIN_AMOUNT_H
