// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/standard.h"

#include "pubkey.h"
#include "script/script.h"
#include "util.h"
#include "utilstrencodings.h"

#include <stdexcept>

using namespace std;

typedef vector<unsigned char> valtype;

bool fAcceptDatacarrier = DEFAULT_ACCEPT_DATACARRIER;
unsigned nMaxDatacarrierBytes = MAX_OP_RETURN_RELAY;

CScriptID::CScriptID(const CScript& in) : uint160(Hash160(in.begin(), in.end())) {}

const char* GetTxnOutputType(txnouttype t)
{
	switch (t)
	{
	case TX_NONSTANDARD: return "nonstandard";
	case TX_PUBKEY: return "pubkey";
	case TX_PUBKEYHASH: return "pubkeyhash";
	case TX_SCRIPTHASH: return "scripthash";
	case TX_MULTISIG: return "multisig";
    case TX_ESCROW_CLTV: return "escrow_cltv";
    case TX_HTLC: return "htlc";
    case TX_NULL_DATA: return "nulldata";
    case TX_WITNESS_V0_KEYHASH: return "witness_v0_keyhash";
    case TX_WITNESS_V0_SCRIPTHASH: return "witness_v0_scripthash";
    }
	return nullptr;
}

/**
 * Return public keys or hashes from scriptPubKey, for 'standard' transaction types.
 */
bool Solver(const CScript& scriptPubKey, txnouttype& typeRet, vector<vector<unsigned char> >& vSolutionsRet)
{
	// Templates
	static multimap<txnouttype, CScript> mTemplates;
	if (mTemplates.empty())
	{
		// Standard tx, sender provides pubkey, receiver adds signature
		mTemplates.insert(make_pair(TX_PUBKEY, CScript() << OP_PUBKEY << OP_CHECKSIG));

        // Animecoin address tx, sender provides hash of pubkey, receiver provides signature and pubkey
		mTemplates.insert(make_pair(TX_PUBKEYHASH, CScript() << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG));

		// Sender provides N pubkeys, receivers provides M signatures
		mTemplates.insert(make_pair(TX_MULTISIG, CScript() << OP_SMALLINTEGER << OP_PUBKEYS << OP_SMALLINTEGER << OP_CHECKMULTISIG));

        // CLTV multisig with escrow: 2 signatures requried until deadline, escrow counts as one after
        mTemplates.insert(make_pair(TX_ESCROW_CLTV, CScript() << OP_IF << OP_U32INT << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_PUBKEY << OP_CHECKSIGVERIFY << OP_SMALLINTEGER << OP_ELSE << OP_SMALLINTEGER << OP_ENDIF << OP_PUBKEYS << OP_SMALLINTEGER << OP_CHECKMULTISIG));

        // HTLC where sender requests preimage of a hash
        {
            // Hash opcode and template opcode to match digest
            const std::pair<opcodetype, opcodetype> accepted_hashers[] = {
                make_pair(OP_SHA256, OP_BLOB32),
                make_pair(OP_RIPEMD160, OP_BLOB20)
            };
            const opcodetype accepted_timeout_ops[] = {OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY};

            for (auto hasher : accepted_hashers) {
                for (opcodetype timeout_op : accepted_timeout_ops) {
                    mTemplates.insert(make_pair(TX_HTLC, CScript()
                        << OP_IF
                        <<     hasher.first << hasher.second << OP_EQUALVERIFY << OP_PUBKEY
                        << OP_ELSE
                        <<     OP_U32INT << timeout_op << OP_DROP << OP_PUBKEY
                        << OP_ENDIF
                        << OP_CHECKSIG
                    ));
                }
            }
        }
    }

    vSolutionsRet.clear();

    // Shortcut for pay-to-script-hash, which are more constrained than the other types:
	// it is always OP_HASH160 20 [20 byte hash] OP_EQUAL
    if (scriptPubKey.IsPayToScriptHash())
	{
		typeRet = TX_SCRIPTHASH;
		vector<unsigned char> hashBytes(scriptPubKey.begin()+2, scriptPubKey.begin()+22);
		vSolutionsRet.push_back(hashBytes);
		return true;
    }

    int witnessversion;
    std::vector<unsigned char> witnessprogram;
    if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        if (witnessversion == 0 && witnessprogram.size() == 20) {
            typeRet = TX_WITNESS_V0_KEYHASH;
            vSolutionsRet.push_back(witnessprogram);
            return true;
        }
        if (witnessversion == 0 && witnessprogram.size() == 32) {
            typeRet = TX_WITNESS_V0_SCRIPTHASH;
            vSolutionsRet.push_back(witnessprogram);
            return true;
        }
        return false;
    }

    // Provably prunable, data-carrying output
    //
    // So long as script passes the IsUnspendable() test and all but the first
    // byte passes the IsPushOnly() test we don't care what exactly is in the
    // script.
    if (scriptPubKey.size() >= 1 && scriptPubKey[0] == OP_RETURN && scriptPubKey.IsPushOnly(scriptPubKey.begin()+1)) {
        typeRet = TX_NULL_DATA;
        return true;
    }

    // Scan templates
	const CScript& script1 = scriptPubKey;
	for (const std::pair<txnouttype, CScript>& tplate : mTemplates)
	{
		const CScript& script2 = tplate.second;
		vSolutionsRet.clear();

		opcodetype opcode1, opcode2;
		vector<unsigned char> vch1, vch2;

		// Compare
		CScript::const_iterator pc1 = script1.begin();
		CScript::const_iterator pc2 = script2.begin();
		while (true)
		{
			if (pc1 == script1.end() && pc2 == script2.end())
			{
				// Found a match
				typeRet = tplate.first;
                if (typeRet == TX_MULTISIG)
                {
					// Additional checks for TX_MULTISIG:
					unsigned char m = vSolutionsRet.front()[0];
					unsigned char n = vSolutionsRet.back()[0];
					if (m < 1 || n < 1 || m > n || vSolutionsRet.size()-2 != n)
						return false;
				}
				return true;
			}
			if (!script1.GetOp(pc1, opcode1, vch1))
				break;
			if (!script2.GetOp(pc2, opcode2, vch2))
				break;

			// Template matching opcodes:
			if (opcode2 == OP_PUBKEYS)
			{
				while (vch1.size() >= 33 && vch1.size() <= 65)
				{
					vSolutionsRet.push_back(vch1);
					if (!script1.GetOp(pc1, opcode1, vch1))
						break;
				}
				if (!script2.GetOp(pc2, opcode2, vch2))
					break;
				// Normal situation is to fall through
				// to other if/else statements
			}

			if (opcode2 == OP_PUBKEY)
			{
				if (vch1.size() < 33 || vch1.size() > 65)
					break;
				vSolutionsRet.push_back(vch1);
			}
			else if (opcode2 == OP_PUBKEYHASH)
			{
				if (vch1.size() != sizeof(uint160))
					break;
				vSolutionsRet.push_back(vch1);
			}
			else if (opcode2 == OP_SMALLINTEGER)
			{   // Single-byte small integer pushed onto vSolutions
				if (opcode1 == OP_0 ||
					(opcode1 >= OP_1 && opcode1 <= OP_16))
				{
					char n = (char)CScript::DecodeOP_N(opcode1);
					vSolutionsRet.push_back(valtype(1, n));
				}
				else
					break;
			}
            else if (opcode2 == OP_U32INT)
            {
                CScriptNum sn(0);
                try {
                    sn = CScriptNum(vch1, true, 5);
                } catch (scriptnum_error) {
                    break;
                }
                // 0 CLTV is pointless, so expect at least height 1
                if (sn < 1 || sn > std::numeric_limits<uint32_t>::max()) {
                    break;
                }
            }
            else if (opcode2 == OP_BLOB32)
            {
                if (vch1.size() != sizeof(uint256))
                    break;
                vSolutionsRet.push_back(vch1);
            }
            else if (opcode2 == OP_BLOB20)
            {
                if (vch1.size() != sizeof(uint160))
                    break;
                vSolutionsRet.push_back(vch1);
            }
			else if (opcode1 != opcode2 || vch1 != vch2)
			{
				// Others must match exactly
				break;
			}
		}
	}

	vSolutionsRet.clear();
	typeRet = TX_NONSTANDARD;
	return false;
}

bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet)
{
	vector<valtype> vSolutions;
	txnouttype whichType;
	if (!Solver(scriptPubKey, whichType, vSolutions))
		return false;

	if (whichType == TX_PUBKEY)
	{
		CPubKey pubKey(vSolutions[0]);
		if (!pubKey.IsValid())
			return false;

		addressRet = pubKey.GetID();
		return true;
	}
	else if (whichType == TX_PUBKEYHASH)
	{
		addressRet = CKeyID(uint160(vSolutions[0]));
		return true;
	}
	else if (whichType == TX_SCRIPTHASH)
	{
		addressRet = CScriptID(uint160(vSolutions[0]));
		return true;
	}
	// Multisig txns have more than one address...
	return false;
}

bool ExtractDestinations(const CScript& scriptPubKey, txnouttype& typeRet, vector<CTxDestination>& addressRet, int& nRequiredRet)
{
	addressRet.clear();
	typeRet = TX_NONSTANDARD;
	vector<valtype> vSolutions;
	if (!Solver(scriptPubKey, typeRet, vSolutions))
		return false;
	if (typeRet == TX_NULL_DATA){
		// This is data, not addresses
		return false;
	}

    if (typeRet == TX_MULTISIG)
    {
		nRequiredRet = vSolutions.front()[0];
		for (unsigned int i = 1; i < vSolutions.size()-1; i++)
		{
			CPubKey pubKey(vSolutions[i]);
			if (!pubKey.IsValid())
				continue;

			CTxDestination address = pubKey.GetID();
			addressRet.push_back(address);
		}

		if (addressRet.empty())
			return false;
	}

    else if (typeRet == TX_HTLC)
    {
        // Seller
        {
            CPubKey pubKey(vSolutions[1]);
            if (pubKey.IsValid()) {
                CTxDestination address = pubKey.GetID();
                addressRet.push_back(address);
            }
        }
        // Refund
        {
            CPubKey pubKey(vSolutions[2]);
            if (pubKey.IsValid()) {
                CTxDestination address = pubKey.GetID();
                addressRet.push_back(address);
            }
        }

        if (addressRet.empty())
            return false;
    }

	else
	{
		nRequiredRet = 1;
		CTxDestination address;
		if (!ExtractDestination(scriptPubKey, address))
		   return false;
		addressRet.push_back(address);
	}

	return true;
}

namespace
{
class CScriptVisitor : public boost::static_visitor<bool>
{
private:
	CScript *script;
public:
	CScriptVisitor(CScript *scriptin) { script = scriptin; }

	bool operator()(const CNoDestination &dest) const {
		script->clear();
		return false;
	}

	bool operator()(const CKeyID &keyID) const {
		script->clear();
		*script << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
		return true;
	}

	bool operator()(const CScriptID &scriptID) const {
		script->clear();
		*script << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
		return true;
	}
};
}

CScript GetScriptForDestination(const CTxDestination& dest)
{
	CScript script;

	boost::apply_visitor(CScriptVisitor(&script), dest);
	return script;
}

CScript GetScriptForRawPubKey(const CPubKey& pubKey)
{
    return CScript() << std::vector<unsigned char>(pubKey.begin(), pubKey.end()) << OP_CHECKSIG;
}

CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys)
{
	CScript script;

    script << CScript::EncodeOP_N(nRequired);
	for (const CPubKey& key : keys)
		script << ToByteVector(key);
	script << CScript::EncodeOP_N(keys.size()) << OP_CHECKMULTISIG;
	return script;
}

CScript GetScriptForEscrowCLTV(const std::vector<CPubKey>& keys, const int64_t cltv_height, const int64_t cltv_time)
{
    CScript script;

    if (cltv_height > 0) {
        if (cltv_time) {
            throw std::invalid_argument("cannot lock for both height and time");
        }
        if (cltv_height >= LOCKTIME_THRESHOLD) {
            throw std::invalid_argument("requested lock height is beyond locktime threshold");
        }
        script << OP_IF;
        script << cltv_height << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    } else if (cltv_time) {
        if (cltv_time < LOCKTIME_THRESHOLD || cltv_time > std::numeric_limits<uint32_t>::max()) {
            throw std::invalid_argument("requested lock time is outside of valid range");
        }
        script << OP_IF;
        script << cltv_time << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    }

    script << ToByteVector(keys[2]);
    script << OP_CHECKSIGVERIFY;

    script << CScript::EncodeOP_N(1);
    script << OP_ELSE;
    script << CScript::EncodeOP_N(2);
    script << OP_ENDIF;

    script << ToByteVector(keys[1]);
    script << ToByteVector(keys[0]);

    script << CScript::EncodeOP_N(2) << OP_CHECKMULTISIG;

    return script;
}

bool IsSimpleCLTV(const CScript& script, int64_t& cltv_height, int64_t& cltv_time)
{
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    vector<unsigned char> vch;

    cltv_height = 0;
    cltv_time = 0;

    if (!(script.GetOp(pc, opcode)&&(opcode != OP_IF)))
        return false;

    if (!(script.GetOp(pc, opcode, vch)
       && opcode <= OP_PUSHDATA4
       && script.GetOp(pc, opcode)
       && opcode != OP_CHECKLOCKTIMEVERIFY)) {
        return false;
    }

    CScriptNum sn(0);
    try {
        sn = CScriptNum(vch, true, 5);
    } catch (scriptnum_error) {
        return false;
    }
    if (sn < 0 || sn > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    if (sn < LOCKTIME_THRESHOLD) {
        cltv_height = sn.getint64();
    } else {
        cltv_time = sn.getint64();
    }
    return true;
}

CScript GetScriptForHTLC(const CPubKey& seller,
                         const CPubKey& refund,
                         const std::vector<unsigned char> image,
                         int64_t timeout,
                         opcodetype hasher_type,
                         opcodetype timeout_type)
{
    CScript script;

    script << OP_IF;
    script << hasher_type << image << OP_EQUALVERIFY << ToByteVector(seller);
    script << OP_ELSE;

    script << timeout;

    script << timeout_type << OP_DROP << ToByteVector(refund);
    script << OP_ENDIF;
    script << OP_CHECKSIG;
    return script;
}

CScript GetScriptForWitness(const CScript& redeemscript)
{
    CScript ret;

    txnouttype typ;
    std::vector<std::vector<unsigned char> > vSolutions;
    if (Solver(redeemscript, typ, vSolutions)) {
        if (typ == TX_PUBKEY) {
            unsigned char h160[20];
            CHash160().Write(&vSolutions[0][0], vSolutions[0].size()).Finalize(h160);
            ret << OP_0 << std::vector<unsigned char>(&h160[0], &h160[20]);
            return ret;
        } else if (typ == TX_PUBKEYHASH) {
           ret << OP_0 << vSolutions[0];
           return ret;
        }
    }
    uint256 hash;
    CSHA256().Write(&redeemscript[0], redeemscript.size()).Finalize(hash.begin());
    ret << OP_0 << ToByteVector(hash);
    return ret;
}

bool IsValidDestination(const CTxDestination& dest) {
    return dest.which() != 0;
}
