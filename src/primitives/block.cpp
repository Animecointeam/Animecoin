// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "hashblock.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

uint256 CBlockHeader::GetHash() const
{
	return Hash9(BEGIN(nVersion), END(nNonce));
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
		s << "  " << vtx[i].ToString() << "\n";
	}
	return s.str();
}