// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "hashblock.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"

uint256 CBlockHeader::GetHash() const
{
#if defined(WORDS_BIGENDIAN)
    uint8_t data[80];
    WriteLE32(&data[0], nVersion);
    memcpy(&data[4], hashPrevBlock.begin(), hashPrevBlock.size());
    memcpy(&data[36], hashMerkleRoot.begin(), hashMerkleRoot.size());
    WriteLE32(&data[68], nTime);
    WriteLE32(&data[72], nBits);
    WriteLE32(&data[76], nNonce);
    return Hash9(data, data + 80);
#else // Can take shortcut for little endian
    return Hash9(BEGIN(nVersion), END(nNonce));
#endif
    //return SerializeHash(*this);
}

std::string CBlock::ToString() const
{
	std::stringstream s;
	s << strprintf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
		GetHash().ToString(),
		nVersion,
		hashPrevBlock.ToString(),
		hashMerkleRoot.ToString(),
		nTime, nBits, nNonce,
		vtx.size());
	for (unsigned int i = 0; i < vtx.size(); i++)
	{
        s << "  " << vtx[i]->ToString() << "\n";
    }
	return s.str();
}

int64_t GetBlockWeight(const CBlock& block)
{
    // This implements the weight = (stripped_size * 4) + witness_size formula,
    // using only serialization with and without witness data. As witness_size
    // is equal to total_size - stripped_size, this formula is identical to:
    // weight = (stripped_size * 3) + total_size.
    return ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
}
