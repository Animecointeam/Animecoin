// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/sign.h"

#include "key.h"
#include "keystore.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "uint256.h"

#include "core_io.h"

using namespace std;

typedef std::vector<unsigned char> valtype;

TransactionSignatureCreator::TransactionSignatureCreator(const CKeyStore* keystoreIn, const CTransaction* txToIn, unsigned int nInIn, int nHashTypeIn) : BaseSignatureCreator(keystoreIn), txTo(txToIn), nIn(nInIn), nHashType(nHashTypeIn), checker(txTo, nIn) {}

bool TransactionSignatureCreator::CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& address, const CScript& scriptCode) const
{
    CKey key;
    if (!keystore->GetKey(address, key))
        return false;

    uint256 hash = SignatureHash(scriptCode, *txTo, nIn, nHashType);
    if (!key.Sign(hash, vchSig))
        return false;
    vchSig.push_back((unsigned char)nHashType);
    return true;
}

static bool Sign1(const CKeyID& address, const BaseSignatureCreator& creator, const CScript& scriptCode, CScript& scriptSigRet)
{
    vector<unsigned char> vchSig;
    if (!creator.CreateSig(vchSig, address, scriptCode))
        return false;
    scriptSigRet << vchSig;    return true;
}

static bool SignN(const vector<valtype>& multisigdata, const BaseSignatureCreator& creator, const CScript& scriptCode, CScript& scriptSigRet)
{
    int nSigned = 0;
    int nRequired = multisigdata.front()[0];
    for (unsigned int i = 1; i < multisigdata.size()-1 && nSigned < nRequired; i++)
    {
        const valtype& pubkey = multisigdata[i];
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (Sign1(keyID, creator, scriptCode, scriptSigRet))
            ++nSigned;
    }
    return nSigned==nRequired;
}

/**
 * Sign scriptPubKey using signature made with creator.
 * Signatures are returned in scriptSigRet (or returns false if scriptPubKey can't be signed),
 * unless whichTypeRet is TX_SCRIPTHASH, in which case scriptSigRet is the redemption script.
 * Returns false if scriptPubKey could not be completely satisfied.
 */
static bool SignStep(const BaseSignatureCreator& creator, const CScript& scriptPubKey,
                     CScript& scriptSigRet, txnouttype& whichTypeRet, bool route)
{
    scriptSigRet.clear();

    vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, whichTypeRet, vSolutions))
        return false;

    CKeyID keyID;
    bool result = false;
    switch (whichTypeRet)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        printf ("NST\n");
        return false;
    case TX_PUBKEY:
        printf ("P2PK\n");
        keyID = CPubKey(vSolutions[0]).GetID();
        return Sign1(keyID, creator, scriptPubKey, scriptSigRet);
    case TX_PUBKEYHASH:
        printf ("P2PKH\n");
        keyID = CKeyID(uint160(vSolutions[0]));
        if (!Sign1(keyID, creator, scriptPubKey, scriptSigRet))
            return false;
        else
        {
            CPubKey vch;
            creator.KeyStore().GetPubKey(keyID, vch);
            scriptSigRet << ToByteVector(vch);
        }
        return true;
    case TX_SCRIPTHASH:
        result = creator.KeyStore().GetCScript(uint160(vSolutions[0]), scriptSigRet);
        printf ("P2SH script %s\n", ScriptToAsmStr (scriptSigRet).c_str());
        return result;

    case TX_MULTISIG:
        printf ("MS\n");
        scriptSigRet << OP_0; // workaround CHECKMULTISIG bug
        return (SignN(vSolutions, creator, scriptPubKey, scriptSigRet));

    case TX_ESCROW_CLTV:
        printf ("Escrow\n");
        if (route==0)
        {
            scriptSigRet << OP_0; // workaround CHECKMULTISIG bug
            vector<valtype> ms_data;
            ms_data.push_back((vSolutions.begin()+1)[0]);
            ms_data.push_back((vSolutions.begin()+3)[0]);
            ms_data.push_back((vSolutions.begin()+4)[0]);
            ms_data.push_back((vSolutions.begin()+5)[0]);
            unsigned int nSigsRequired = ms_data.front()[0];
            unsigned int nPubKeys = ms_data.size()-2;
            printf ("Multisig SignN, %u solutions, %u pubkeys, %u required. \n", ms_data.size(), nPubKeys, nSigsRequired);
            result = SignN(ms_data, creator, scriptPubKey, scriptSigRet);
            keyID = CPubKey(vSolutions[0]).GetID();
            result = Sign1(keyID, creator, scriptPubKey, scriptSigRet) && result;
            scriptSigRet << OP_1;
        }
        else
        {
            scriptSigRet << OP_0; // workaround CHECKMULTISIG bug
            vector<valtype> ms_data (vSolutions.begin()+2, vSolutions.begin()+vSolutions.size());
            unsigned int nSigsRequired = ms_data.front()[0];
            unsigned int nPubKeys = ms_data.size()-2;
            printf ("Multisig SignN, %u solutions, %u pubkeys, %u required. \n", ms_data.size(), nPubKeys, nSigsRequired);
            result = SignN(ms_data, creator, scriptPubKey, scriptSigRet) && result;
            scriptSigRet << OP_0;
        }
        printf ("CLTV script %s\n", ScriptToAsmStr (scriptSigRet).c_str());

        return result;

    case TX_TWOPARTY_CLTV:
        result = true;
        if (route==0)
        {
            keyID = CPubKey(vSolutions[1]).GetID();
            printf("buyer key id %i\n", keyID);
            if (!Sign1(keyID, creator, scriptPubKey, scriptSigRet)) {
                return false;
            }
            scriptSigRet << OP_1;
        }
        else
        {
            keyID = CPubKey(vSolutions[1]).GetID();
            printf("buyer key id %i\n", keyID);
            result = Sign1(keyID, creator, scriptPubKey, scriptSigRet);

            keyID = CPubKey(vSolutions[0]).GetID();
            printf("seller key id %i\n", keyID);
            result = !Sign1(keyID, creator, scriptPubKey, scriptSigRet) && result;
            scriptSigRet << OP_0;
        }

        printf ("CLTV script %s\n", ScriptToAsmStr (scriptSigRet).c_str());
        return result;
    }
    return false;
}

bool ProduceSignature(const BaseSignatureCreator& creator, const CScript& fromPubKey, CScript& scriptSig, bool route)
{
    txnouttype whichType;
    if (!SignStep(creator, fromPubKey, scriptSig, whichType, route))
        return false;

    if (whichType == TX_SCRIPTHASH)
    {
        // Solver returns the subscript that need to be evaluated;
        // the final scriptSig is the signatures from that
        // and then the serialized subscript:
        CScript subscript = scriptSig;

        txnouttype subType;
        bool fSolved =
                SignStep(creator, subscript, scriptSig, subType, route) && subType != TX_SCRIPTHASH;
        // Append serialized subscript whether or not it is completely signed:
        scriptSig << valtype(subscript.begin(), subscript.end());
        if (!fSolved) return false;
    }

    // Test solution
    return VerifyScript(scriptSig, fromPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, creator.Checker());
}

bool SignSignature(const CKeyStore &keystore, const CScript& fromPubKey, CMutableTransaction& txTo, unsigned int nIn, int nHashType, bool route)
{
    assert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];

    CTransaction txToConst(txTo);
    TransactionSignatureCreator creator(&keystore, &txToConst, nIn, nHashType);

    return ProduceSignature(creator, fromPubKey, txin.scriptSig, route);
}

bool SignSignature(const CKeyStore &keystore, const CTransaction& txFrom, CMutableTransaction& txTo, unsigned int nIn, int nHashType, bool route)
{
    assert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];
    assert(txin.prevout.n < txFrom.vout.size());
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    return SignSignature(keystore, txout.scriptPubKey, txTo, nIn, nHashType, route);
}

static CScript PushAll(const vector<valtype>& values)
{
    CScript result;
    for (const valtype& v : values) {
        if (v.size() == 0) {
            result << OP_0;
        } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        } else if (v.size() == 1 && v[0] == 0x81) {
            result << OP_1NEGATE;
        } else {
            result << v;
        }
    }
    return result;
}

static CScript CombineMultisig(const CScript& scriptPubKey, const BaseSignatureChecker& checker,
                               const vector<valtype>& vSolutions,
                               const vector<valtype>& sigs1, const vector<valtype>& sigs2)
{
    // Combine all the signatures we've got:
    set<valtype> allsigs;
    for (const valtype& v : sigs1)
    {
        if (!v.empty())
            allsigs.insert(v);
    }
    for (const valtype& v : sigs2)
    {
        if (!v.empty())
            allsigs.insert(v);
    }

    // Build a map of pubkey -> signature by matching sigs to pubkeys:
    assert(vSolutions.size() > 1);
    unsigned int nSigsRequired = vSolutions.front()[0];
    unsigned int nPubKeys = vSolutions.size()-2;
    printf ("Multisig combining, %u solutions, %u pubkeys, %u required. \n", vSolutions.size(), nPubKeys, nSigsRequired);
    map<valtype, valtype> sigs;
    for (const valtype& sig : allsigs)
    {
        for (unsigned int i = 0; i < nPubKeys; i++)
        {
            const valtype& pubkey = vSolutions[i+1];
            if (sigs.count(pubkey))
                continue; // Already got a sig for this pubkey

            if (checker.CheckSig(sig, pubkey, scriptPubKey))
            {
                sigs[pubkey] = sig;
                break;
            }
        }
    }
    // Now build a merged CScript:
    unsigned int nSigsHave = 0;
    CScript result; result << OP_0; // pop-one-too-many workaround
    for (unsigned int i = 0; i < nPubKeys && nSigsHave < nSigsRequired; i++)
    {
        if (sigs.count(vSolutions[i+1]))
        {
            result << sigs[vSolutions[i+1]];
            ++nSigsHave;
        }
    }
    // Fill any missing with OP_0:
    for (unsigned int i = nSigsHave; i < nSigsRequired; i++)
        result << OP_0;

    return result;
}

static CScript CombineSignatures(const CScript& scriptPubKey, const BaseSignatureChecker& checker,
                                 const txnouttype txType, const vector<valtype>& vSolutions,
                                 vector<valtype>& sigs1, vector<valtype>& sigs2, bool route)
{
    switch (txType)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
    case TX_TWOPARTY_CLTV:
        // Don't know anything about this, assume bigger one is correct:
        if (sigs1.size() >= sigs2.size())
            return PushAll(sigs1);
        return PushAll(sigs2);
    case TX_PUBKEY:
    case TX_PUBKEYHASH:
        // Signatures are bigger than placeholders or empty scripts:
        if (sigs1.empty() || sigs1[0].empty())
            return PushAll(sigs2);
        return PushAll(sigs1);
    case TX_SCRIPTHASH:
        if (sigs1.empty() || sigs1.back().empty())
            return PushAll(sigs2);
        else if (sigs2.empty() || sigs2.back().empty())
            return PushAll(sigs1);
        else
        {
            // Recur to combine:
            valtype spk = sigs1.back();
            CScript pubKey2(spk.begin(), spk.end());

            txnouttype txType2;
            vector<vector<unsigned char> > vSolutions2;
            Solver(pubKey2, txType2, vSolutions2);
            sigs1.pop_back();
            sigs2.pop_back();
            CScript result = CombineSignatures(pubKey2, checker, txType2, vSolutions2, sigs1, sigs2, route);
            result << spk;
            return result;
        }
    case TX_MULTISIG:
        return CombineMultisig(scriptPubKey, checker, vSolutions, sigs1, sigs2);
    case TX_ESCROW_CLTV:
        if (route==0)
        {
            vector<valtype> ms_data;
            ms_data.push_back((vSolutions.begin()+1)[0]);
            ms_data.push_back((vSolutions.begin()+3)[0]);
            ms_data.push_back((vSolutions.begin()+4)[0]);
            ms_data.push_back((vSolutions.begin()+5)[0]);
            CScript ret = CombineMultisig(scriptPubKey, checker, ms_data, sigs1, sigs2);
            ret << sigs1[0];
            ret << OP_1;
            printf ("Combined result: %s\n", ScriptToAsmStr (ret).c_str());
            return ret;
        }
        else
        {
            vector<valtype> ms_data (vSolutions.begin()+2, vSolutions.begin()+vSolutions.size());
            CScript ret = CombineMultisig(scriptPubKey, checker, ms_data, sigs1, sigs2);
            ret << OP_0;
            printf ("Combined result: %s\n", ScriptToAsmStr (ret).c_str());
            return ret;
        }
    }

    return CScript();
}

CScript CombineSignatures(const CScript& scriptPubKey, const CTransaction& txTo, unsigned int nIn,
                          const CScript& scriptSig1, const CScript& scriptSig2, bool route)
{
    TransactionSignatureChecker checker(&txTo, nIn);
    return CombineSignatures(scriptPubKey, checker, scriptSig1, scriptSig2, route);
}

CScript CombineSignatures(const CScript& scriptPubKey, const BaseSignatureChecker& checker,
                          const CScript& scriptSig1, const CScript& scriptSig2, bool route)
{
    txnouttype txType;
    vector<vector<unsigned char> > vSolutions;
    Solver(scriptPubKey, txType, vSolutions);

    vector<valtype> stack1;
    EvalScript(stack1, scriptSig1, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker());
    vector<valtype> stack2;
    EvalScript(stack2, scriptSig2, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker());

    return CombineSignatures(scriptPubKey, checker, txType, vSolutions, stack1, stack2, route);
}

namespace {
/** Dummy signature checker which accepts all signatures. */
class DummySignatureChecker : public BaseSignatureChecker
{
public:
    DummySignatureChecker() {}

    bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode) const override
    {
        return true;
    }
};
const DummySignatureChecker dummyChecker;
}

const BaseSignatureChecker& DummySignatureCreator::Checker() const
{
    return dummyChecker;
}

bool DummySignatureCreator::CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode) const
{
    // Create a dummy signature that is a valid DER-encoding
    vchSig.assign(72, '\000');
    vchSig[0] = 0x30;
    vchSig[1] = 69;
    vchSig[2] = 0x02;
    vchSig[3] = 33;
    vchSig[4] = 0x01;
    vchSig[4 + 33] = 0x02;
    vchSig[5 + 33] = 32;
    vchSig[6 + 33] = 0x01;
    vchSig[6 + 33 + 32] = SIGHASH_ALL;
    return true;
}
