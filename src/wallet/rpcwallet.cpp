// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "base58.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "rpc/server.h"
#include "init.h"
#include "net.h"
#include "net_processing.h" // for fFetchBlocksWhileFetchingHeaders, consider removal?
#include "policy/rbf.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validation.h"
#include "wallet.h"
#include "walletdb.h"

#include <stdint.h>

#include <univalue.h>

CWallet *GetWalletForJSONRPCRequest(const JSONRPCRequest& request)
{
    return pwalletMain;
}

std::string HelpRequiringPassphrase(CWallet * const pwallet)
{
    return pwallet && pwallet->IsCrypted()
        ? "\nRequires wallet passphrase to be set with walletpassphrase call."
        : "";
}

bool EnsureWalletIsAvailable(CWallet * const pwallet, bool avoidException)
{
    if (!pwallet) {
        if (!avoidException)
            throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (disabled)");
        else
            return false;
    }
    return true;
}

void EnsureWalletIsUnlocked(CWallet * const pwallet)
{
    if (pwallet->IsLocked()) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    }
}

void WalletTxToJSON(const CWalletTx& wtx, UniValue& entry)
{
    int confirms = wtx.GetDepthInMainChain();
    entry.pushKV("validated", wtx.fValidated);
    entry.pushKV("confirmations", confirms);
    if (wtx.IsCoinBase())
        entry.pushKV("generated", true);
    if (confirms > 0)
    {
        entry.pushKV("blockhash", wtx.hashBlock.GetHex());
        entry.pushKV("blockindex", wtx.nIndex);
        entry.pushKV("blocktime", mapBlockIndex[wtx.hashBlock]->GetBlockTime());
    } else {
        entry.pushKV("trusted", wtx.IsTrusted());
    }
    uint256 hash = wtx.GetHash();
    entry.pushKV("txid", hash.GetHex());
    UniValue conflicts(UniValue::VARR);
    for (const uint256& conflict : wtx.GetConflicts())
        conflicts.push_back(conflict.GetHex());
    entry.pushKV("walletconflicts", conflicts);
    entry.pushKV("time", wtx.GetTxTime());
    entry.pushKV("timereceived", (int64_t)wtx.nTimeReceived);

    // Add opt-in RBF status
    std::string rbfStatus = "no";
    if (confirms <= 0) {
        LOCK(mempool.cs);
        if (!mempool.exists(hash)) {
            if (SignalsOptInRBF(wtx)) {
                rbfStatus = "yes";
            } else {
                rbfStatus = "unknown";
            }
        } else if (IsRBFOptIn(*mempool.mapTx.find(hash), mempool)) {
            rbfStatus = "yes";
        }
    }
    entry.pushKV("bip125-replaceable", rbfStatus);

    for (const std::pair<const std::string,std::string>& item : wtx.mapValue)
        entry.pushKV(item.first, item.second);
}

std::string AccountFromValue(const UniValue& value)
{
    std::string strAccount = value.get_str();
    if (strAccount == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    return strAccount;
}

UniValue getnewaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
                "getnewaddress ( \"account\" )\n"
                "\nReturns a new Animecoin address for receiving payments.\n"
                "If 'account' is specified (recommended), it is added to the address book \n"
                "so payments received with the address will be credited to 'account'.\n"
                "\nArguments:\n"
                "1. \"account\"        (string, optional) The account name for the address to be linked to. if not provided, the default account \"\" is used. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created if there is no account by the given name.\n"
                "\nResult:\n"
                "\"address\"    (string) The new animecoin address\n"
                "\nExamples:\n"
                + HelpExampleCli("getnewaddress", "")
                + HelpExampleCli("getnewaddress", "\"\"")
                + HelpExampleCli("getnewaddress", "\"myaccount\"")
                + HelpExampleRpc("getnewaddress", "\"myaccount\"")
            );

    LOCK2(cs_main, pwallet->cs_wallet);

    // Parse the account first so we don't generate a key if there's an error
    std::string strAccount;
    if (!request.params[0].isNull())
        strAccount = AccountFromValue(request.params[0]);

    if (!pwallet->IsLocked()) {
        pwallet->TopUpKeyPool();
    }

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!pwallet->GetKeyFromPool(newKey)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    }
    CKeyID keyID = newKey.GetID();

    pwallet->SetAddressBook(keyID, strAccount, "receive");

    return CBitcoinAddress(keyID).ToString();
}


CBitcoinAddress GetAccountAddress(CWallet * const pwallet, std::string strAccount, bool bForceNew=false)
{
    CPubKey pubKey;
    if (!pwallet->GetAccountPubkey(pubKey, strAccount, bForceNew)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    }

    return CBitcoinAddress(pubKey.GetID());
}

UniValue getaccountaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "getaccountaddress \"account\"\n"
                "\nReturns the current Animecoin address for receiving payments to this account.\n"
                "\nArguments:\n"
                "1. \"account\"       (string, required) The account name for the address. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created and a new address created  if there is no account by the given name.\n"
                "\nResult:\n"
                "\"address\"          (string) The account animecoin address\n"
                "\nExamples:\n"
                + HelpExampleCli("getaccountaddress", "")
                + HelpExampleCli("getaccountaddress", "\"\"")
                + HelpExampleCli("getaccountaddress", "\"myaccount\"")
                + HelpExampleRpc("getaccountaddress", "\"myaccount\"")
            );

    LOCK2(cs_main, pwallet->cs_wallet);

    // Parse the account first so we don't generate a key if there's an error
    std::string strAccount = AccountFromValue(request.params[0]);

    UniValue ret(UniValue::VSTR);

    ret = GetAccountAddress(pwallet, strAccount).ToString();
    return ret;
}


UniValue getrawchangeaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0)
        throw std::runtime_error(
            "getrawchangeaddress\n"
            "\nReturns a new Animecoin address, for receiving change.\n"
            "This is for use with raw transactions, NOT normal use.\n"
            "\nResult:\n"
            "\"address\"    (string) The address\n"
            "\nExamples:\n"
            + HelpExampleCli("getrawchangeaddress", "")
            + HelpExampleRpc("getrawchangeaddress", "")
       );

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!pwallet->IsLocked()) {
        pwallet->TopUpKeyPool();
    }

    CReserveKey reservekey(pwallet);
    CPubKey vchPubKey;
    if (!reservekey.GetReservedKey(vchPubKey, true))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    reservekey.KeepKey();

    CKeyID keyID = vchPubKey.GetID();

    return CBitcoinAddress(keyID).ToString();
}


UniValue setaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
                "setaccount \"address\" \"account\"\n"
                "\nSets the account associated with the given address.\n"
                "\nArguments:\n"
                "1. \"address\"         (string, required) The animecoin address to be associated with an account.\n"
                "2. \"account\"         (string, required) The account to assign the address to.\n"
                "\nExamples:\n"
                + HelpExampleCli("setaccount", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\" \"tabby\"")
                + HelpExampleRpc("setaccount", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\", \"tabby\"")
            );

    LOCK2(cs_main, pwallet->cs_wallet);

    CBitcoinAddress address(request.params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Animecoin address");

    std::string strAccount;
    if (request.params.size() > 1)
        strAccount = AccountFromValue(request.params[1]);

    // Only add the account if the address is yours.
    if (IsMine(*pwallet, address.Get())) {
        // Detect when changing the account of an address that is the 'unused current key' of another account:
        if (pwallet->mapAddressBook.count(address.Get())) {
            std::string strOldAccount = pwallet->mapAddressBook[address.Get()].name;
            if (address == GetAccountAddress(pwallet, strOldAccount)) {
                GetAccountAddress(pwallet, strOldAccount, true);
            }
        }
        pwallet->SetAddressBook(address.Get(), strAccount, "receive");
    }
    else
        throw JSONRPCError(RPC_MISC_ERROR, "setaccount can only be used with own address");

    return NullUniValue;
}


UniValue getaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "getaccount \"address\"\n"
                "\nReturns the account associated with the given address.\n"
                "\nArguments:\n"
                "1. \"address\"         (string, required) The animecoin address for account lookup.\n"
                "\nResult:\n"
                "\"accountname\"        (string) the account address\n"
                "\nExamples:\n"
                + HelpExampleCli("getaccount", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\"")
                + HelpExampleRpc("getaccount", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\"")
            );

    LOCK2(cs_main, pwallet->cs_wallet);

    CBitcoinAddress address(request.params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Animecoin address");

    std::string strAccount;
    std::map<CTxDestination, CAddressBookData>::iterator mi = pwallet->mapAddressBook.find(address.Get());
    if (mi != pwallet->mapAddressBook.end() && !(*mi).second.name.empty()) {
        strAccount = (*mi).second.name;
    }
    return strAccount;
}


UniValue getaddressesbyaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "getaddressesbyaccount \"account\"\n"
                "\nReturns the list of addresses for the given account.\n"
                "\nArguments:\n"
                "1. \"account\"        (string, required) The account name.\n"
                "\nResult:\n"
                "[                     (json array of string)\n"
                "  \"address\"         (string) an animecoin address associated with the given account\n"
                "  ,...\n"
                "]\n"
                "\nExamples:\n"
                + HelpExampleCli("getaddressesbyaccount", "\"tabby\"")
                + HelpExampleRpc("getaddressesbyaccount", "\"tabby\"")
            );

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount = AccountFromValue(request.params[0]);

    // Find all addresses that have the given account
    UniValue ret(UniValue::VARR);
    for (const std::pair<const CBitcoinAddress, CAddressBookData>& item : pwallet->mapAddressBook)
    {
        const CBitcoinAddress& address = item.first;
        const std::string& strName = item.second.name;
        if (strName == strAccount)
            ret.push_back(address.ToString());
    }
    return ret;
}

static void SendMoney(CWallet * const pwallet, const CTxDestination &address, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew)
{
    CAmount curBalance = pwallet->GetBalance();

    // Check amount
    if (nValue <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    if (nValue > curBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    if (pwallet->GetBroadcastTransactions() && !g_connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    // Parse Animecoin address
    CScript scriptPubKey = GetScriptForDestination(address);

    // Create and send the transaction
    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nValue, fSubtractFeeFromAmount};
    vecSend.push_back(recipient);
    if (!pwallet->CreateTransaction(vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError)) {
        if (!fSubtractFeeFromAmount && nValue + nFeeRequired > curBalance)
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    CValidationState state;
    if (!pwallet->CommitTransaction(wtxNew, reservekey, g_connman.get(), state)) {
        strError = strprintf("Error: The transaction was rejected! Reason given: %s", state.GetRejectReason());
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
}

UniValue sendtoaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 5)
        throw std::runtime_error(
                "sendtoaddress \"address\" amount ( \"comment\" \"comment_to\" subtractfeefromamount )\n"
                "\nSend an amount to a given address. The amount is a real and is rounded to the nearest 0.00000001\n"
                + HelpRequiringPassphrase(pwallet) +
                "\nArguments:\n"
                "1. \"address\"            (string, required) The animecoin address to send to.\n"
                "2. \"amount\"             (numeric or string, required) The amount in " + CURRENCY_UNIT + " to send. eg 0.1\n"
                "3. \"comment\"            (string, optional) A comment used to store what the transaction is for. \n"
                "                             This is not part of the transaction, just kept in your wallet.\n"
                "4. \"comment_to\"         (string, optional) A comment to store the name of the person or organization \n"
                "                             to which you're sending the transaction. This is not part of the \n"
                "                             transaction, just kept in your wallet.\n"
                "5. subtractfeefromamount  (boolean, optional, default=false) The fee will be deducted from the amount being sent.\n"
                "                             The recipient will receive less bitcoins than you enter in the amount field.\n"
                "\nResult:\n"
                "\"txid\"                  (string) The transaction id.\n"
                "\nExamples:\n"
                + HelpExampleCli("sendtoaddress", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\" 0.1")
                + HelpExampleCli("sendtoaddress", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\" 0.1 \"donation\" \"seans outpost\"")
                + HelpExampleCli("sendtoaddress", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\" 0.1 \"\" \"\" true")
                + HelpExampleRpc("sendtoaddress", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\", 0.1, \"donation\", \"seans outpost\"")
            );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    CBitcoinAddress address(request.params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Animecoin address");

    // Amount
    CAmount nAmount = AmountFromValue(request.params[1]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

    // Wallet comments
    CWalletTx wtx;
    if (request.params.size() > 2 && !request.params[2].isNull() && !request.params[2].get_str().empty())
        wtx.mapValue["comment"] = request.params[2].get_str();
    if (request.params.size() > 3 && !request.params[3].isNull() && !request.params[3].get_str().empty())
        wtx.mapValue["to"]      = request.params[3].get_str();

    bool fSubtractFeeFromAmount = false;
    if (request.params.size() > 4)
        fSubtractFeeFromAmount = request.params[4].get_bool();

    EnsureWalletIsUnlocked(pwallet);

    SendMoney(pwallet, address.Get(), nAmount, fSubtractFeeFromAmount, wtx);

    return wtx.GetHash().GetHex();
}

UniValue listaddressgroupings(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "listaddressgroupings\n"
            "\nLists groups of addresses which have had their common ownership\n"
            "made public by common use as inputs or as the resulting change\n"
            "in past transactions\n"
            "\nResult:\n"
            "[\n"
            "  [\n"
            "    [\n"
            "      \"address\",     (string) The animecoin address\n"
            "      amount,                 (numeric) The amount in " + CURRENCY_UNIT + "\n"
            "      \"account\"             (string, optional) DEPRECATED. The account\n"
            "    ]\n"
            "    ,...\n"
            "  ]\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("listaddressgroupings", "")
            + HelpExampleRpc("listaddressgroupings", "")
        );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    UniValue jsonGroupings(UniValue::VARR);
    std::map<CTxDestination, CAmount> balances = pwallet->GetAddressBalances();
    for (std::set<CTxDestination> grouping : pwallet->GetAddressGroupings()) {
        UniValue jsonGrouping(UniValue::VARR);
        for (CTxDestination address : grouping)
        {
            UniValue addressInfo(UniValue::VARR);
            addressInfo.push_back(CBitcoinAddress(address).ToString());
            addressInfo.push_back(ValueFromAmount(balances[address]));
            {
                if (pwallet->mapAddressBook.find(CBitcoinAddress(address).Get()) != pwallet->mapAddressBook.end()) {
                    addressInfo.push_back(pwallet->mapAddressBook.find(CBitcoinAddress(address).Get())->second.name);
                }
            }
            jsonGrouping.push_back(addressInfo);
        }
        jsonGroupings.push_back(jsonGrouping);
    }
    return jsonGroupings;
}

UniValue signmessage(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
                "signmessage \"address\" \"message\"\n"
                "\nSign a message with the private key of an address"
                + HelpRequiringPassphrase(pwallet) + "\n"
                "\nArguments:\n"
                "1. \"address\"         (string, required) The animecoin address to use for the private key.\n"
                "2. \"message\"         (string, required) The message to create a signature of.\n"
                "\nResult:\n"
                "\"signature\"          (string) The signature of the message encoded in base 64\n"
                "\nExamples:\n"
                "\nUnlock the wallet for 30 seconds\n"
                + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
                "\nCreate the signature\n"
                + HelpExampleCli("signmessage", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\" \"my message\"") +
                "\nVerify the signature\n"
                + HelpExampleCli("verifymessage", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\" \"signature\" \"my message\"") +
                "\nAs json rpc\n"
                + HelpExampleRpc("signmessage", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\", \"my message\"")
            );

    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    std::string strAddress = request.params[0].get_str();
    std::string strMessage = request.params[1].get_str();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    CKey key;
    if (!pwallet->GetKey(keyID, key)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available");
    }

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(vchSig.data(), vchSig.size());
}

UniValue getreceivedbyaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
                "getreceivedbyaddress \"address\" ( minconf )\n"
                "\nReturns the total amount received by the given address in transactions with at least minconf confirmations.\n"
                "\nArguments:\n"
                "1. \"address\"         (string, required) The animecoin address for transactions.\n"
                "2. minconf             (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
                "\nResult:\n"
                "amount   (numeric) The total amount in " + CURRENCY_UNIT + " received at this address.\n"
                "\nExamples:\n"
                "\nThe amount from transactions with at least 1 confirmation\n"
                + HelpExampleCli("getreceivedbyaddress", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\"") +
                "\nThe amount including unconfirmed transactions, zero confirmations\n"
                + HelpExampleCli("getreceivedbyaddress", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\" 0") +
                "\nThe amount with at least 6 confirmation, very safe\n"
                + HelpExampleCli("getreceivedbyaddress", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\" 6") +
                "\nAs a json rpc call\n"
                + HelpExampleRpc("getreceivedbyaddress", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\", 6")
           );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    // Animecoin address
    CBitcoinAddress address = CBitcoinAddress(request.params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Animecoin address");
    CScript scriptPubKey = GetScriptForDestination(address.Get());
    if (!IsMine(*pwallet, scriptPubKey)) {
        return ValueFromAmount(0);
    }

    // Minimum confirmations
    int nMinDepth = 1;
    if (!request.params[1].isNull())
        nMinDepth = request.params[1].get_int();

    // Tally
    CAmount nAmount = 0;
    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;
        if (wtx.IsCoinBase() || !CheckFinalTx(wtx, -1, !wtx.fValidated)) // *wtx.tx
            continue;

        for (const CTxOut& txout : wtx.vout)
            if (txout.scriptPubKey == scriptPubKey)
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
    }

    return  ValueFromAmount(nAmount);
}


UniValue getreceivedbyaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
                "getreceivedbyaccount \"account\" ( minconf )\n"
                "\nReturns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.\n"
                "\nArguments:\n"
                "1. \"account\"      (string, required) The selected account, may be the default account using \"\".\n"
                "2. minconf          (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
                "\nResult:\n"
                "amount              (numeric) The total amount in " + CURRENCY_UNIT + " received for this account.\n"
                "\nExamples:\n"
                "\nAmount received by the default account with at least 1 confirmation\n"
                + HelpExampleCli("getreceivedbyaccount", "\"\"") +
                "\nAmount received at the tabby account including unconfirmed amounts with zero confirmations\n"
                + HelpExampleCli("getreceivedbyaccount", "\"tabby\" 0") +
                "\nThe amount with at least 6 confirmation, very safe\n"
                + HelpExampleCli("getreceivedbyaccount", "\"tabby\" 6") +
                "\nAs a json rpc call\n"
                + HelpExampleRpc("getreceivedbyaccount", "\"tabby\", 6")
            );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    // Minimum confirmations
    int nMinDepth = 1;
    if (!request.params[1].isNull())
        nMinDepth = request.params[1].get_int();

    // Get the set of pub keys assigned to account
    std::string strAccount = AccountFromValue(request.params[0]);
    std::set<CTxDestination> setAddress = pwallet->GetAccountAddresses(strAccount);

    // Tally
    CAmount nAmount = 0;
    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;
        if (wtx.IsCoinBase() || !CheckFinalTx(wtx, -1, !wtx.fValidated))
            continue;

        for (const CTxOut& txout : wtx.vout)
        {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*pwallet, address) && setAddress.count(address)) {
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
            }
        }
    }

    return ValueFromAmount(nAmount);
}

UniValue getbalance(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 3)
        throw std::runtime_error(
                "getbalance ( \"account\" minconf include_watchonly )\n"
                "\nIf account is not specified, returns the server's total available balance.\n"
                "If account is specified, returns the balance in the account.\n"
                "Note that the account \"\" is not the same as leaving the parameter out.\n"
                "The server total may be different to the balance in the default \"\" account.\n"
                "\nArguments:\n"
                "1. \"account\"      (string, optional) The selected account, or \"*\" for entire wallet. It may be the default account using \"\".\n"
                "2. minconf          (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
                "3. include_watchonly (bool, optional, default=false) Also include balance in watchonly addresses (see 'importaddress')\n"
                "\nResult:\n"
                "amount              (numeric) The total amount in " + CURRENCY_UNIT + " received for this account.\n"
                "\nExamples:\n"
                "\nThe total amount in the server across all accounts\n"
                + HelpExampleCli("getbalance", "") +
                "\nThe total amount in the server across all accounts, with at least 5 confirmations\n"
                + HelpExampleCli("getbalance", "\"*\" 6") +
                "\nThe total amount in the default account with at least 1 confirmation\n"
                + HelpExampleCli("getbalance", "\"\"") +
                "\nThe total amount in the account named tabby with at least 6 confirmations\n"
                + HelpExampleCli("getbalance", "\"tabby\" 6") +
                "\nAs a json rpc call\n"
                + HelpExampleRpc("getbalance", "\"tabby\", 6")
            );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.params.size() == 0)
        return  ValueFromAmount(pwallet->GetBalance());

    int nMinDepth = 1;
    if (!request.params[1].isNull())
        nMinDepth = request.params[1].get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if(!request.params[2].isNull())
        if(request.params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    if (request.params[0].get_str() == "*") {
        // Calculate total balance a different way from GetBalance()
        // (GetBalance() sums up all unspent TxOuts)
        // getbalance and "getbalance * 1 true" should return the same number
        CAmount nBalance = 0;
        for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
            const CWalletTx& wtx = pairWtx.second;
            if (!CheckFinalTx(wtx, -1, !wtx.fValidated) || wtx.GetBlocksToMaturity() > 0 || wtx.GetDepthInMainChain() < 0)
                continue;

            CAmount allFee;
            std::string strSentAccount;
            std::list<COutputEntry> listReceived;
            std::list<COutputEntry> listSent;
            wtx.GetAmounts(listReceived, listSent, allFee, strSentAccount, filter);
            if (wtx.GetDepthInMainChain() >= nMinDepth)
            {
                for (const COutputEntry& r : listReceived)
                    nBalance += r.amount;
            }
            for (const COutputEntry& s : listSent)
                nBalance -= s.amount;
            nBalance -= allFee;
        }
        return  ValueFromAmount(nBalance);
    }

    std::string strAccount = AccountFromValue(request.params[0]);

    CAmount nBalance = pwallet->GetAccountBalance(strAccount, nMinDepth, filter);

    return ValueFromAmount(nBalance);
}

UniValue getunconfirmedbalance(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0)
        throw std::runtime_error(
                "getunconfirmedbalance\n"
                "Returns the server's total unconfirmed balance\n");

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    return ValueFromAmount(pwallet->GetUnconfirmedBalance());
}


UniValue movecmd(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 3 || request.params.size() > 5)
        throw std::runtime_error(
                "move \"fromaccount\" \"toaccount\" amount ( minconf \"comment\" )\n"
                "\nMove a specified amount from one account in your wallet to another.\n"
                "\nArguments:\n"
                "1. \"fromaccount\"   (string, required) The name of the account to move funds from. May be the default account using \"\".\n"
                "2. \"toaccount\"     (string, required) The name of the account to move funds to. May be the default account using \"\".\n"
                "3. amount            (numeric) Quantity of " + CURRENCY_UNIT + " to move between accounts.\n"
                "4. minconf           (numeric, optional, default=1) Only use funds with at least this many confirmations.\n"
                "5. \"comment\"       (string, optional) An optional comment, stored in the wallet only.\n"
                "\nResult:\n"
                "true|false           (boolean) true if successful.\n"
                "\nExamples:\n"
                "\nMove 0.01 " + CURRENCY_UNIT + " from the default account to the account named tabby\n"
                + HelpExampleCli("move", "\"\" \"tabby\" 0.01") +
                "\nMove 0.01 " + CURRENCY_UNIT + " timotei to akiko with a comment and funds have 6 confirmations\n"
                + HelpExampleCli("move", "\"timotei\" \"akiko\" 0.01 6 \"happy birthday!\"") +
                "\nAs a json rpc call\n"
                + HelpExampleRpc("move", "\"timotei\", \"akiko\", 0.01, 6, \"happy birthday!\"")
            );

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strFrom = AccountFromValue(request.params[0]);
    std::string strTo = AccountFromValue(request.params[1]);
    CAmount nAmount = AmountFromValue(request.params[2]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    if (request.params.size() > 3)
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)request.params[3].get_int();
    std::string strComment;
    if (request.params.size() > 4)
        strComment = request.params[4].get_str();

    if (!pwallet->AccountMove(strFrom, strTo, nAmount, strComment)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");
    }

    return true;
}


UniValue sendfrom(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 3 || request.params.size() > 6)
        throw std::runtime_error(
                "sendfrom \"fromaccount\" \"toaddress\" amount ( minconf \"comment\" \"comment_to\" )\n"
                "\nSent an amount from an account to an animecoin address.\n"
                "The amount is a real and is rounded to the nearest 0.00000001."
                + HelpRequiringPassphrase(pwallet) + "\n"
                "\nArguments:\n"
                "1. \"fromaccount\"       (string, required) The name of the account to send funds from. May be the default account using \"\".\n"
                "2. \"toaddress\"         (string, required) The animecoin address to send funds to.\n"
                "3. amount                (numeric, required) The amount in " + CURRENCY_UNIT + " (transaction fee is added on top).\n"
                "4. minconf               (numeric, optional, default=1) Only use funds with at least this many confirmations.\n"
                "5. \"comment\"           (string, optional) A comment used to store what the transaction is for. \n"
                "                                     This is not part of the transaction, just kept in your wallet.\n"
                "6. \"comment_to\"        (string, optional) An optional comment to store the name of the person or organization \n"
                "                                     to which you're sending the transaction. This is not part of the transaction, \n"
                "                                     it is just kept in your wallet.\n"
                "\nResult:\n"
                "\"txid\"                 (string) The transaction id.\n"
                "\nExamples:\n"
                "\nSend 0.01 " + CURRENCY_UNIT + " from the default account to the address, must have at least 1 confirmation\n"
                + HelpExampleCli("sendfrom", "\"\" \"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\" 0.01") +
                "\nSend 0.01 from the tabby account to the given address, funds must have at least 6 confirmations\n"
                + HelpExampleCli("sendfrom", "\"tabby\" \"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\" 0.01 6 \"donation\" \"seans outpost\"") +
                "\nAs a json rpc call\n"
                + HelpExampleRpc("sendfrom", "\"tabby\", \"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\", 0.01, 6, \"donation\", \"seans outpost\"")
            );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount = AccountFromValue(request.params[0]);
    CBitcoinAddress address(request.params[1].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Animecoin address");
    CAmount nAmount = AmountFromValue(request.params[2]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    int nMinDepth = 1;
    if (request.params.size() > 3)
        nMinDepth = request.params[3].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (request.params.size() > 4 && !request.params[4].isNull() && !request.params[4].get_str().empty())
        wtx.mapValue["comment"] = request.params[4].get_str();
    if (request.params.size() > 5 && !request.params[5].isNull() && !request.params[5].get_str().empty())
        wtx.mapValue["to"]      = request.params[5].get_str();

    EnsureWalletIsUnlocked(pwallet);

    // Check funds
    CAmount nBalance = pwallet->GetAccountBalance(strAccount, nMinDepth, ISMINE_SPENDABLE);
    if (nAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    SendMoney(pwallet, address.Get(), nAmount, false, wtx);

    return wtx.GetHash().GetHex();
}


UniValue sendmany(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 5)
        throw std::runtime_error(
                "sendmany \"fromaccount\" {\"address\":amount,...} ( minconf \"comment\" {\"address\":true,...} )\n"
                "\nSend multiple times. Amounts are double-precision floating point numbers."
                + HelpRequiringPassphrase(pwallet) + "\n"
                "\nArguments:\n"
                "1. \"fromaccount\"         (string, required) The account to send the funds from, can be \"\" for the default account\n"
                "2. \"amounts\"             (string, required) A json object with addresses and amounts\n"
                "    {\n"
                "      \"address\":amount   (numeric) The animecoin address is the key, the numeric amount in " + CURRENCY_UNIT + " is the value\n"
                "      ,...\n"
                "    }\n"
                "3. minconf                 (numeric, optional, default=1) Only use the balance confirmed at least this many times.\n"
                "4. \"comment\"             (string, optional) A comment\n"
                "5. subtractfeefrom         (array, optional) A json array with addresses.\n"
                "                           The fee will be equally deducted from the amount of each selected address.\n"
                "                           Those recipients will receive less bitcoins than you enter in their corresponding amount field.\n"
                "                           Default for each address is false. If no addresses are specified here, the sender pays the fee.\n"
                "    {\n"
                "      \"address\":true     (boolean) Subtract fee from this address\n"
                "      ,...\n"
                "    }\n"
                "\nResult:\n"
                "\"txid\"                   (string) The transaction id for the send. Only 1 transaction is created regardless of \n"
                "                                    the number of addresses.\n"
                "\nExamples:\n"
                "\nSend two amounts to two different addresses:\n"
                + HelpExampleCli("sendmany", "\"tabby\" \"{\\\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\\\":0.01,\\\"Ad9gq1rYvKDiFWCQPnrXVBCZEhwmQYXNks\\\":0.02}\"") +
                "\nSend two amounts to two different addresses setting the confirmation and comment:\n"
                + HelpExampleCli("sendmany", "\"tabby\" \"{\\\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\\\":0.01,\\\"Ad9gq1rYvKDiFWCQPnrXVBCZEhwmQYXNks\\\":0.02}\" 6 \"testing\"") +
                "\nSend two amounts to two different addresses, subtract fee from amount:\n"
                + HelpExampleCli("sendmany", "\"\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"Ad9gq1rYvKDiFWCQPnrXVBCZEhwmQYXNks\\\":0.02}\" 1 \"\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":true,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":true}\"") +
                "\nAs a json rpc call\n"
                + HelpExampleRpc("sendmany", "\"tabby\", \"{\\\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\\\":0.01,\\\"Ad9gq1rYvKDiFWCQPnrXVBCZEhwmQYXNks\\\":0.02}\", 6, \"testing\"")
            );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    if (pwallet->GetBroadcastTransactions() && !g_connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    std::string strAccount = AccountFromValue(request.params[0]);
    UniValue sendTo = request.params[1].get_obj();
    int nMinDepth = 1;
    if (!request.params[2].isNull())
        nMinDepth = request.params[2].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (request.params.size() > 3 && !request.params[3].isNull() && !request.params[3].get_str().empty())
        wtx.mapValue["comment"] = request.params[3].get_str();

    UniValue subtractFeeFromAmount(UniValue::VOBJ);
    if (request.params.size() > 4)
        subtractFeeFromAmount = request.params[4].get_obj();

    std::set<CBitcoinAddress> setAddress;
    std::vector<CRecipient> vecSend;

    CAmount totalAmount = 0;
    std::vector<std::string> keys = sendTo.getKeys();
    for (const std::string& name_ : keys)
    {
        CBitcoinAddress address(name_);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Animecoin address: ")+name_);

        if (setAddress.count(address))
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ")+name_);
        setAddress.insert(address);

        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = AmountFromValue(sendTo[name_]);
        if (nAmount <= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
        totalAmount += nAmount;

        bool fSubtractFeeFromAmount = false;
        for (unsigned int idx = 0; idx < subtractFeeFromAmount.size(); idx++) {
            const UniValue& addr = subtractFeeFromAmount[idx];
            if (addr.get_str() == name_)
                fSubtractFeeFromAmount = true;
        }
        CRecipient recipient = {scriptPubKey, nAmount, fSubtractFeeFromAmount};
        vecSend.push_back(recipient);
    }

    EnsureWalletIsUnlocked(pwallet);

    // Check funds
    CAmount nBalance = pwallet->GetAccountBalance(strAccount, nMinDepth, ISMINE_SPENDABLE);
    if (totalAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send
    CReserveKey keyChange(pwallet);
    CAmount nFeeRequired = 0;
    int nChangePosRet = -1;
    std::string strFailReason;
    bool fCreated = pwallet->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, nChangePosRet, strFailReason);
    if (!fCreated)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strFailReason);
    CValidationState state;
    if (!pwallet->CommitTransaction(wtx, keyChange, g_connman.get(), state)) {
        strFailReason = strprintf("Transaction commit failed:: %s", state.GetRejectReason());
        throw JSONRPCError(RPC_WALLET_ERROR, strFailReason);
    }

    return wtx.GetHash().GetHex();
}

// Defined in rpc/misc.cpp
extern CScript _createmultisig_redeemScript(CWallet * const pwallet, const UniValue& params, const UniValue& options);

UniValue addmultisigaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
    {
        std::string msg = "addmultisigaddress nrequired [\"key\",...] ( { options } )\n"
            "\nAdd a nrequired-to-sign multisignature address to the wallet.\n"
            "Each key is an Animecoin address or hex-encoded public key.\n"
            "If 'account' is specified, assign address to that account.\n"

            "\nArguments:\n"
            "1. nrequired        (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "2. \"keys\"         (string, required) A json array of animecoin addresses or hex-encoded public keys\n"
            "     [\n"
            "       \"address\"  (string) animecoin address or hex-encoded public key\n"
            "       ...,\n"
            "     ]\n"
            "3. options        (object, optional)\n"
            "   {\n"
            "     \"cltv_height\"  (numeric, optional) Minimum block height before received funds can be spent\n"
            "   }\n"

            "\nResult:\n"
            "\"address\"         (string) An animecoin address associated with the keys.\n"

            "\nExamples:\n"
            "\nAdd a multisig address from 2 addresses\n"
            + HelpExampleCli("addmultisigaddress", "2 \"[\\\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\\\",\\\"Ad9gq1rYvKDiFWCQPnrXVBCZEhwmQYXNks\\\"]\"") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("addmultisigaddress", "2, \"[\\\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\\\",\\\"Ad9gq1rYvKDiFWCQPnrXVBCZEhwmQYXNks\\\"]\"")
        ;
        throw std::runtime_error(msg);
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount;
    UniValue options(UniValue::VOBJ);
    if (request.params.size() > 2 && !request.params[2].isNull()) {
        if (request.params.type() == UniValue::VSTR) {
            // Deprecated account parameter
            strAccount = AccountFromValue(request.params[2].get_str());
        } else {
            const UniValue& optionsIn = request.params[2].get_obj();
            std::vector<std::string> keys = optionsIn.getKeys();
            for (const std::string& key : keys) {
                const UniValue& val = optionsIn[key];
                if (key == "account") {
                    strAccount = AccountFromValue(val.get_str());
                    continue;
                }
                if (key == "cltv_time") {
                    throw std::runtime_error("cltv_time not supported");
                }
                options.pushKV(key, val);
            }
        }
    }

    // Construct using pay-to-script-hash:
    CScript inner = _createmultisig_redeemScript(pwallet, request.params, options);
    CScriptID innerID(inner);
    pwallet->AddCScript(inner);

    pwallet->SetAddressBook(innerID, strAccount, "send");
    return CBitcoinAddress(innerID).ToString();
}


struct tallyitem
{
    CAmount nAmount;
    int nConf;
    std::vector<uint256> txids;
    bool fIsWatchonly;
    tallyitem()
    {
        nAmount = 0;
        nConf = std::numeric_limits<int>::max();
        fIsWatchonly = false;
    }
};

UniValue ListReceived(CWallet * const pwallet, const UniValue& params, bool fByAccounts)
{
    // Minimum confirmations
    int nMinDepth = 1;
    if (!params[0].isNull())
        nMinDepth = params[0].get_int();

    // Whether to include empty accounts
    bool fIncludeEmpty = false;
    if (!params[1].isNull())
        fIncludeEmpty = params[1].get_bool();

    isminefilter filter = ISMINE_SPENDABLE;
    if(!params[2].isNull())
        if(params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    // Tally
    std::map<CBitcoinAddress, tallyitem> mapTally;
    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;

        if (wtx.IsCoinBase() || !CheckFinalTx(wtx, -1, !wtx.fValidated))
            continue;

        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < nMinDepth)
            continue;

        for (const CTxOut& txout : wtx.vout)
        {
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address))
                continue;

            isminefilter mine = IsMine(*pwallet, address);
            if(!(mine & filter))
                continue;

            tallyitem& item = mapTally[address];
            item.nAmount += txout.nValue;
            item.nConf = std::min(item.nConf, nDepth);
            item.txids.push_back(wtx.GetHash());
            if (mine & ISMINE_WATCH_ONLY)
                item.fIsWatchonly = true;
        }
    }

    // Reply
    UniValue ret(UniValue::VARR);
    std::map<std::string, tallyitem> mapAccountTally;
    for (const std::pair<CBitcoinAddress, CAddressBookData>& item : pwallet->mapAddressBook)
    {
        const CBitcoinAddress& address = item.first;
        const std::string& strAccount = item.second.name;
        std::map<CBitcoinAddress, tallyitem>::iterator it = mapTally.find(address);
        if (it == mapTally.end() && !fIncludeEmpty)
            continue;

        CAmount nAmount = 0;
        int nConf = std::numeric_limits<int>::max();
        bool fIsWatchonly = false;
        if (it != mapTally.end())
        {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
            fIsWatchonly = (*it).second.fIsWatchonly;
        }

        if (fByAccounts)
        {
            tallyitem& _item = mapAccountTally[strAccount];
            _item.nAmount += nAmount;
            _item.nConf = std::min(_item.nConf, nConf);
            _item.fIsWatchonly = fIsWatchonly;
        }
        else
        {
            UniValue obj(UniValue::VOBJ);
            if(fIsWatchonly)
                obj.pushKV("involvesWatchonly", true);
            obj.pushKV("address",       address.ToString());
            obj.pushKV("account",       strAccount);
            obj.pushKV("amount",        ValueFromAmount(nAmount));
            obj.pushKV("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf));
            if (!fByAccounts)
                obj.pushKV("label", strAccount);
            UniValue transactions(UniValue::VARR);
            if (it != mapTally.end())
            {
                for (const uint256& _item : (*it).second.txids)
                {
                    transactions.push_back(_item.GetHex());
                }
            }
            obj.pushKV("txids", transactions);
            ret.push_back(obj);
        }
    }

    if (fByAccounts)
    {
        for (const auto& entry : mapAccountTally)
        {
            CAmount nAmount = entry.second.nAmount;
            int nConf = entry.second.nConf;
            UniValue obj(UniValue::VOBJ);
            if (entry.second.fIsWatchonly)
                obj.pushKV("involvesWatchonly", true);
            obj.pushKV("account",       entry.first);
            obj.pushKV("amount",        ValueFromAmount(nAmount));
            obj.pushKV("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf));
            ret.push_back(obj);
        }
    }

    return ret;
}

UniValue listreceivedbyaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 3)
        throw std::runtime_error(
                "listreceivedbyaddress ( minconf include_empty include_watchonly)\n"
                "\nList balances by receiving address.\n"
                "\nArguments:\n"
                "1. minconf           (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
                "2. include_empty     (bool, optional, default=false) Whether to include addresses that haven't received any payments.\n"
                "3. include_watchonly (bool, optional, default=false) Whether to include watchonly addresses (see 'importaddress').\n"

                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"involvesWatchonly\" : \"true\",    (bool) Only returned if imported addresses were involved in transaction\n"
                "    \"address\" : \"receivingaddress\",  (string) The receiving address\n"
                "    \"account\" : \"accountname\",       (string) The account of the receiving address. The default account is \"\".\n"
                "    \"amount\" : x.xxx,                  (numeric) The total amount in " + CURRENCY_UNIT + " received by the address\n"
                "    \"confirmations\" : n,               (numeric) The number of confirmations of the most recent transaction included\n"
                "    \"label\" : \"label\",               (string) A comment for the address/transaction, if any\n"
                "    \"txids\": [\n"
                "       n,                                (numeric) The ids of transactions received with the address \n"
                "       ...\n"
                "    ]\n"
                "  }\n"
                "  ,...\n"
                "]\n"

                "\nExamples:\n"
                + HelpExampleCli("listreceivedbyaddress", "")
                + HelpExampleCli("listreceivedbyaddress", "6 true")
                + HelpExampleRpc("listreceivedbyaddress", "6, true, true")
            );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    return ListReceived(pwallet, request.params, false);
}

UniValue listreceivedbyaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 3)
        throw std::runtime_error(
                "listreceivedbyaccount ( minconf include_empty include_watchonly)\n"
                "\nList balances by account.\n"
                "\nArguments:\n"
                "1. minconf           (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
                "2. include_empty     (bool, optional, default=false) Whether to include accounts that haven't received any payments.\n"
                "3. include_watchonly (bool, optional, default=false) Whether to include watchonly addresses (see 'importaddress').\n"

                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"involvesWatchonly\" : \"true\",    (bool) Only returned if imported addresses were involved in transaction\n"
                "    \"account\" : \"accountname\",  (string) The account name of the receiving account\n"
                "    \"amount\" : x.xxx,             (numeric) The total amount received by addresses with this account\n"
                "    \"confirmations\" : n,          (numeric) The number of confirmations of the most recent transaction included\n"
                "    \"label\" : \"label\"           (string) A comment for the address/transaction, if any\n"
                "  }\n"
                "  ,...\n"
                "]\n"

                "\nExamples:\n"
                + HelpExampleCli("listreceivedbyaccount", "")
                + HelpExampleCli("listreceivedbyaccount", "6 true")
                + HelpExampleRpc("listreceivedbyaccount", "6, true, true")
            );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    return ListReceived(pwallet, request.params, true);
}

static void MaybePushAddress(UniValue & entry, const CTxDestination &dest)
{
    CBitcoinAddress addr;
    if (addr.Set(dest))
        entry.pushKV("address", addr.ToString());
}

/**
 * List transactions based on the given criteria.
 *
 * @param  pwallet    The wallet.
 * @param  wtx        The wallet transaction.
 * @param  strAccount The account, if any, or "*" for all.
 * @param  nMinDepth  The minimum confirmation depth.
 * @param  fLong      Whether to include the JSON version of the transaction.
 * @param  ret        The UniValue into which the result is stored.
 * @param  filter     The "is mine" filter bool.
 */
void ListTransactions(CWallet* const pwallet, const CWalletTx& wtx, const std::string& strAccount, int nMinDepth, bool fLong, UniValue& ret, const isminefilter& filter)
{
    CAmount nFee;
    std::string strSentAccount;
    std::list<COutputEntry> listReceived;
    std::list<COutputEntry> listSent;

    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, filter);

    bool fAllAccounts = (strAccount == std::string("*"));
    bool involvesWatchonly = wtx.IsFromMe(ISMINE_WATCH_ONLY);

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount))
    {
        for (const COutputEntry& s : listSent)
        {
            UniValue entry(UniValue::VOBJ);
            if (involvesWatchonly || (::IsMine(*pwallet, s.destination) & ISMINE_WATCH_ONLY)) {
                entry.pushKV("involvesWatchonly", true);
            }
            entry.pushKV("account", strSentAccount);
            MaybePushAddress(entry, s.destination);
            entry.pushKV("category", "send");
            entry.pushKV("amount", ValueFromAmount(-s.amount));
            if (pwallet->mapAddressBook.count(s.destination)) {
                entry.pushKV("label", pwallet->mapAddressBook[s.destination].name);
            }
            entry.pushKV("vout", s.vout);
            entry.pushKV("fee", ValueFromAmount(-nFee));
            if (fLong)
                WalletTxToJSON(wtx, entry);
            entry.pushKV("abandoned", wtx.isAbandoned());
            ret.push_back(entry);
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth)
    {
        for (const COutputEntry& r : listReceived)
        {
            std::string account;
            if (pwallet->mapAddressBook.count(r.destination)) {
                account = pwallet->mapAddressBook[r.destination].name;
            }
            if (fAllAccounts || (account == strAccount))
            {
                UniValue entry(UniValue::VOBJ);
                if (involvesWatchonly || (::IsMine(*pwallet, r.destination) & ISMINE_WATCH_ONLY)) {
                    entry.pushKV("involvesWatchonly", true);
                }
                entry.pushKV("account", account);
                MaybePushAddress(entry, r.destination);
                if (wtx.IsCoinBase())
                {
                    if (wtx.GetDepthInMainChain() < 1)
                        entry.pushKV("category", "orphan");
                    else if (wtx.GetBlocksToMaturity() > 0)
                        entry.pushKV("category", "immature");
                    else
                        entry.pushKV("category", "generate");
                }
                else
                {
                    entry.pushKV("category", "receive");
                }
                entry.pushKV("amount", ValueFromAmount(r.amount));
                if (pwallet->mapAddressBook.count(r.destination)) {
                    entry.pushKV("label", account);
                }
                entry.pushKV("vout", r.vout);
                if (fLong)
                    WalletTxToJSON(wtx, entry);
                ret.push_back(entry);
            }
        }
    }
}

void AcentryToJSON(const CAccountingEntry& acentry, const std::string& strAccount, UniValue& ret)
{
    bool fAllAccounts = (strAccount == std::string("*"));

    if (fAllAccounts || acentry.strAccount == strAccount)
    {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("account", acentry.strAccount);
        entry.pushKV("category", "move");
        entry.pushKV("time", acentry.nTime);
        entry.pushKV("amount", ValueFromAmount(acentry.nCreditDebit));
        entry.pushKV("otheraccount", acentry.strOtherAccount);
        entry.pushKV("comment", acentry.strComment);
        ret.push_back(entry);
    }
}

UniValue listtransactions(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 4)
        throw std::runtime_error(
                "listtransactions ( \"account\" count skip include_watchonly)\n"
                "\nReturns up to 'count' most recent transactions skipping the first 'from' transactions for account 'account'.\n"
                "\nArguments:\n"
                "1. \"account\"    (string, optional) The account name. If not included, it will list all transactions for all accounts.\n"
                "                                     If \"\" is set, it will list transactions for the default account.\n"
                "2. count          (numeric, optional, default=10) The number of transactions to return\n"
                "3. skip           (numeric, optional, default=0) The number of transactions to skip\n"
                "4. include_watchonly (bool, optional, default=false) Include transactions to watchonly addresses (see 'importaddress')\n"
                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"account\":\"accountname\",       (string) The account name associated with the transaction. \n"
                "                                                It will be \"\" for the default account.\n"
                "    \"address\":\"address\",    (string) The animecoin address of the transaction. Not present for \n"
                "                                                move transactions (category = move).\n"
                "    \"category\":\"send|receive|move\", (string) The transaction category. 'move' is a local (off blockchain)\n"
                "                                                transaction between accounts, and not associated with an address,\n"
                "                                                transaction id or block. 'send' and 'receive' transactions are \n"
                "                                                associated with an address, transaction id and block details\n"
                "    \"amount\": x.xxx,          (numeric) The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and for the\n"
                "                                         'move' category for moves outbound. It is positive for the 'receive' category,\n"
                "                                         and for the 'move' category for inbound funds.\n"
                "    \"label\": \"label\",       (string) A comment for the address/transaction, if any\n"
                "    \"vout\" : n,               (numeric) the vout value\n"
                "    \"fee\": x.xxx,             (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
                "                                         'send' category of transactions.\n"
                "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and \n"
                "                                         'receive' category of transactions. Negative confirmations indicate the\n"
                "                                         transation conflicts with the block chain\n"
                "    \"trusted\": xxx,           (bool) Whether we consider the outputs of this unconfirmed transaction safe to spend.\n"
                "    \"blockhash\": \"hashvalue\", (string) The block hash containing the transaction. Available for 'send' and 'receive'\n"
                "                                          category of transactions.\n"
                "    \"blockindex\": n,          (numeric) The block index containing the transaction. Available for 'send' and 'receive'\n"
                "                                          category of transactions.\n"
                "    \"txid\": \"transactionid\", (string) The transaction id. Available for 'send' and 'receive' category of transactions.\n"
                "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (midnight Jan 1 1970 GMT).\n"
                "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (midnight Jan 1 1970 GMT). Available \n"
                "                                          for 'send' and 'receive' category of transactions.\n"
                "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
                "    \"otheraccount\": \"accountname\",  (string) DEPRECATED. For the 'move' category of transactions, the account the funds came \n"
                "                                          from (for receiving funds, positive amounts), or went to (for sending funds,\n"
                "                                          negative amounts).\n"
                "    \"bip125-replaceable\": \"yes|no|unknown\",  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
                "                                                     may be unknown for unconfirmed transactions not in the mempool\n"
                "    \"abandoned\": xxx          (bool) 'true' if the transaction has been abandoned (inputs are respendable). Only available for the \n"
                "                                         'send' category of transactions.\n"
                "  }\n"
                "]\n"

                "\nExamples:\n"
                "\nList the most recent 10 transactions in the systems\n"
                + HelpExampleCli("listtransactions", "") +
                "\nList the most recent 10 transactions for the tabby account\n"
                + HelpExampleCli("listtransactions", "\"tabby\"") +
                "\nList transactions 100 to 120 from the tabby account\n"
                + HelpExampleCli("listtransactions", "\"tabby\" 20 100") +
                "\nAs a json rpc call\n"
                + HelpExampleRpc("listtransactions", "\"tabby\", 20, 100")
            );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount = "*";
    if (!request.params[0].isNull())
        strAccount = request.params[0].get_str();
    int nCount = 10;
    if (!request.params[1].isNull())
        nCount = request.params[1].get_int();
    int nFrom = 0;
    if (!request.params[2].isNull())
        nFrom = request.params[2].get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if(!request.params[3].isNull())
        if(request.params[3].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    UniValue ret(UniValue::VARR);

    const CWallet::TxItems & txOrdered = pwallet->wtxOrdered;

    // iterate backwards until we have nCount items to return:
    for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        if (pwtx != 0)
            ListTransactions(pwallet, *pwtx, strAccount, 0, true, ret, filter);
        CAccountingEntry *const pacentry = (*it).second.second;
        if (pacentry != 0)
            AcentryToJSON(*pacentry, strAccount, ret);

        if ((int)ret.size() >= (nCount+nFrom)) break;
    }
    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;

    std::vector<UniValue> arrTmp = ret.getValues();

    std::vector<UniValue>::iterator first = arrTmp.begin();
    std::advance(first, nFrom);
    std::vector<UniValue>::iterator last = arrTmp.begin();
    std::advance(last, nFrom+nCount);

    if (last != arrTmp.end()) arrTmp.erase(last, arrTmp.end());
    if (first != arrTmp.begin()) arrTmp.erase(arrTmp.begin(), first);

    std::reverse(arrTmp.begin(), arrTmp.end()); // Return oldest to newest

    ret.clear();
    ret.setArray();
    ret.push_backV(arrTmp);

    return ret;
}

UniValue listaccounts(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
                "listaccounts ( minconf include_watchonly)\n"
                "\nReturns Object that has account names as keys, account balances as values.\n"
                "\nArguments:\n"
                "1. minconf             (numeric, optional, default=1) Only include transactions with at least this many confirmations\n"
                "2. include_watchonly   (bool, optional, default=false) Include balances in watchonly addresses (see 'importaddress')\n"
                "\nResult:\n"
                "{                      (json object where keys are account names, and values are numeric balances\n"
                "  \"account\": x.xxx,  (numeric) The property name is the account name, and the value is the total balance for the account.\n"
                "  ...\n"
                "}\n"
                "\nExamples:\n"
                "\nList account balances where there at least 1 confirmation\n"
                + HelpExampleCli("listaccounts", "") +
                "\nList account balances including zero confirmation transactions\n"
                + HelpExampleCli("listaccounts", "0") +
                "\nList account balances for 6 or more confirmations\n"
                + HelpExampleCli("listaccounts", "6") +
                "\nAs json rpc call\n"
                + HelpExampleRpc("listaccounts", "6")
            );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    int nMinDepth = 1;
    if (request.params.size() > 0)
        nMinDepth = request.params[0].get_int();
    isminefilter includeWatchonly = ISMINE_SPENDABLE;
    if(request.params.size() > 1)
        if(request.params[1].get_bool())
            includeWatchonly = includeWatchonly | ISMINE_WATCH_ONLY;

    std::map<std::string, CAmount> mapAccountBalances;
    for (const std::pair<CTxDestination, CAddressBookData>& entry : pwallet->mapAddressBook) {
        if (IsMine(*pwallet, entry.first) & includeWatchonly) {  // This address belongs to me
            mapAccountBalances[entry.second.name] = 0;
        }
    }

    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;
        CAmount nFee;
        std::string strSentAccount;
        std::list<COutputEntry> listReceived;
        std::list<COutputEntry> listSent;
        int nDepth = wtx.GetDepthInMainChain();
        if (wtx.GetBlocksToMaturity() > 0 || nDepth < 0)
            continue;
        wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, includeWatchonly);
        mapAccountBalances[strSentAccount] -= nFee;
        for (const COutputEntry& s : listSent)
            mapAccountBalances[strSentAccount] -= s.amount;
        if (nDepth >= nMinDepth)
        {
            for (const COutputEntry& r : listReceived)
                if (pwallet->mapAddressBook.count(r.destination)) {
                    mapAccountBalances[pwallet->mapAddressBook[r.destination].name] += r.amount;
                }
                else
                    mapAccountBalances[""] += r.amount;
        }
    }

    const std::list<CAccountingEntry> & acentries = pwallet->laccentries;
    for (const CAccountingEntry& entry : acentries)
        mapAccountBalances[entry.strAccount] += entry.nCreditDebit;

    UniValue ret(UniValue::VOBJ);
    for (const std::pair<const std::string, CAmount>& accountBalance : mapAccountBalances) {
        ret.pushKV(accountBalance.first, ValueFromAmount(accountBalance.second));
    }
    return ret;
}

UniValue listsinceblock(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 4)
        throw std::runtime_error(
                "listsinceblock ( \"blockhash\" target_confirmations include_watchonly include_removed )\n"
                "\nGet all transactions in blocks since block [blockhash], or all transactions if omitted.\n"
                "If \"blockhash\" is no longer a part of the main chain, transactions from the fork point onward are included.\n"
                "Additionally, if include_removed is set, transactions affecting the wallet which were removed are returned in the \"removed\" array.\n"
                "\nArguments:\n"
                "1. \"blockhash\"            (string, optional) The block hash to list transactions since\n"
                "2. target_confirmations:    (numeric, optional, default=1) The confirmations required, must be 1 or more\n"
                "3. include_watchonly:       (bool, optional, default=false) Include transactions to watch-only addresses (see 'importaddress')\n"
                "4. include_removed:         (bool, optional, default=true) Show transactions that were removed due to a reorg in the \"removed\" array\n"
                "                                                           (not guaranteed to work on pruned nodes)\n"
                "\nResult:\n"
                "{\n"
                "  \"transactions\": [\n"
                "    \"account\":\"accountname\",       (string) The account name associated with the transaction. Will be \"\" for the default account.\n"
                "    \"address\":\"address\",    (string) The animecoin address of the transaction. Not present for move transactions (category = move).\n"
                "    \"category\":\"send|receive\",     (string) The transaction category. 'send' has negative amounts, 'receive' has positive amounts.\n"
                "    \"amount\": x.xxx,          (numeric) The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and for the 'move' category for moves \n"
                "                                          outbound. It is positive for the 'receive' category, and for the 'move' category for inbound funds.\n"
                "    \"vout\" : n,               (numeric) the vout value\n"
                "    \"fee\": x.xxx,             (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the 'send' category of transactions.\n"
                "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and 'receive' category of transactions.\n"
                "    \"blockhash\": \"hashvalue\",     (string) The block hash containing the transaction. Available for 'send' and 'receive' category of transactions.\n"
                "    \"blockindex\": n,          (numeric) The block index containing the transaction. Available for 'send' and 'receive' category of transactions.\n"
                "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
                "    \"txid\": \"transactionid\",  (string) The transaction id. Available for 'send' and 'receive' category of transactions.\n"
                "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT).\n"
                "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (Jan 1 1970 GMT). Available for 'send' and 'receive' category of transactions.\n"
                "    \"bip125-replaceable\": \"yes|no|unknown\",  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
                "                                                   may be unknown for unconfirmed transactions not in the mempool\n"
                "    \"abandoned\": xxx,         (bool) 'true' if the transaction has been abandoned (inputs are respendable). Only available for the 'send' category of transactions.\n"
                "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
                "    \"label\" : \"label\"       (string) A comment for the address/transaction, if any\n"
                "    \"to\": \"...\",            (string) If a comment to is associated with the transaction.\n"
                "  ],\n"
                "  \"removed\": [\n"
                "    <structure is the same as \"transactions\" above, only present if include_removed=true>\n"
                "    Note: transactions that were readded in the active chain will appear as-is in this array, and may thus have a positive confirmation count.\n"
                "  ],\n"
                "  \"lastblock\": \"lastblockhash\"     (string) The hash of the last block\n"
                "}\n"
                "\nExamples:\n"
                + HelpExampleCli("listsinceblock", "")
                + HelpExampleCli("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\" 6")
                + HelpExampleRpc("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\", 6")
            );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    const CBlockIndex* pindex = nullptr;    // Block index of the specified block or the common ancestor, if the block provided was in a deactivated chain.
    const CBlockIndex* paltindex = nullptr; // Block index of the specified block, even if it's in a deactivated chain.
    int target_confirms = 1;
    isminefilter filter = ISMINE_SPENDABLE;

    if (!request.params[0].isNull() && !request.params[0].get_str().empty()) {
        uint256 blockId;

        blockId.SetHex(request.params[0].get_str());
        BlockMap::iterator it = mapBlockIndex.find(blockId);
        if (it == mapBlockIndex.end()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        paltindex = pindex = it->second;
        if (chainActive[pindex->nHeight] != pindex) {
            // the block being asked for is a part of a deactivated chain;
            // we don't want to depend on its perceived height in the block
            // chain, we want to instead use the last common ancestor
            pindex = chainActive.FindFork(pindex);
        }
    }

    if (!request.params[1].isNull()) {
        target_confirms = request.params[1].get_int();

        if (target_confirms < 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
        }
    }

    if (!request.params[2].isNull() && request.params[2].get_bool()) {
        filter = filter | ISMINE_WATCH_ONLY;
    }

    bool include_removed = (request.params[3].isNull() || request.params[3].get_bool());

    int depth = pindex ? (1 + chainActive.Height() - pindex->nHeight) : -1;

    UniValue transactions(UniValue::VARR);

    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        CWalletTx tx = pairWtx.second;

        if (depth == -1 || tx.GetDepthInMainChain() < depth) {
            ListTransactions(pwallet, tx, "*", 0, true, transactions, filter);
        }
    }

    // when a reorg'd block is requested, we also list any relevant transactions
    // in the blocks of the chain that was detached
    UniValue removed(UniValue::VARR);
    while (include_removed && paltindex && paltindex != pindex) {
        CBlock block;
        if (!ReadBlockFromDisk(block, paltindex, Params().GetConsensus())) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
        }
        for (const CTransactionRef& tx : block.vtx) {
            if (pwallet->mapWallet.count(tx->GetHash()) > 0) {
                // We want all transactions regardless of confirmation count to appear here,
                // even negative confirmation ones, hence the big negative.
                ListTransactions(pwallet, pwallet->mapWallet[tx->GetHash()], "*", -100000000, true, removed, filter);
            }
        }
        paltindex = paltindex->pprev;

    }

    CBlockIndex *pblockLast = chainActive[chainActive.Height() + 1 - target_confirms];
    uint256 lastblock = pblockLast ? pblockLast->GetBlockHash() : uint256();

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("transactions", transactions);
    if (include_removed) ret.pushKV("removed", removed);
    ret.pushKV("lastblock", lastblock.GetHex());

    return ret;
}

UniValue gettransaction(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
                "gettransaction \"txid\" ( include_watchonly )\n"
                "\nGet detailed information about in-wallet transaction <txid>\n"
                "\nArguments:\n"
                "1. \"txid\"                  (string, required) The transaction id\n"
                "2. \"include_watchonly\"     (bool, optional, default=false) Whether to include watchonly addresses in balance calculation and details[]\n"
                "\nResult:\n"
                "{\n"
                "  \"amount\" : x.xxx,        (numeric) The transaction amount in " + CURRENCY_UNIT + "\n"
                "  \"fee\": x.xxx,            (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
                "                              'send' category of transactions.\n"
                "  \"confirmations\" : n,     (numeric) The number of confirmations\n"
                "  \"blockhash\" : \"hash\",  (string) The block hash\n"
                "  \"blockindex\" : xx,       (numeric) The block index\n"
                "  \"blocktime\" : ttt,       (numeric) The time in seconds since epoch (1 Jan 1970 GMT)\n"
                "  \"txid\" : \"transactionid\",   (string) The transaction id.\n"
                "  \"time\" : ttt,            (numeric) The transaction time in seconds since epoch (1 Jan 1970 GMT)\n"
                "  \"timereceived\" : ttt,    (numeric) The time received in seconds since epoch (1 Jan 1970 GMT)\n"
                "  \"bip125-replaceable\": \"yes|no|unknown\",  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
                "                                                   may be unknown for unconfirmed transactions not in the mempool\n"
                "  \"details\" : [\n"
                "    {\n"
                "      \"account\" : \"accountname\",      (string) DEPRECATED. The account name involved in the transaction, can be \"\" for the default account.\n"
                "      \"address\" : \"address\",   (string) The animecoin address involved in the transaction\n"
                "      \"category\" : \"send|receive\",    (string) The category, either 'send' or 'receive'\n"
                "      \"amount\" : x.xxx,                 (numeric) The amount in " + CURRENCY_UNIT + "\n"
                "      \"label\" : \"label\",              (string) A comment for the address/transaction, if any\n"
                "      \"vout\" : n,                       (numeric) the vout value\n"
                "      \"fee\": x.xxx,                     (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
                "                                           'send' category of transactions.\n"
                "      \"abandoned\": xxx                  (bool) 'true' if the transaction has been abandoned (inputs are respendable). Only available for the \n"
                "                                           'send' category of transactions.\n"
                "    }\n"
                "    ,...\n"
                "  ],\n"
                "  \"hex\" : \"data\"         (string) Raw data for transaction\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
                + HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\" true")
                + HelpExampleRpc("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    uint256 hash;
    hash.SetHex(request.params[0].get_str());

    isminefilter filter = ISMINE_SPENDABLE;
    if(!request.params[1].isNull())
        if(request.params[1].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    UniValue entry(UniValue::VOBJ);
    if (!pwallet->mapWallet.count(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    }
    const CWalletTx& wtx = pwallet->mapWallet[hash];

    CAmount nCredit = wtx.GetCredit(filter);
    CAmount nDebit = wtx.GetDebit(filter);
    CAmount nNet = nCredit - nDebit;
    CAmount nFee = (wtx.IsFromMe(filter) ? wtx.GetValueOut() - nDebit : 0);

    entry.pushKV("amount", ValueFromAmount(nNet - nFee));
    if (wtx.IsFromMe(filter))
        entry.pushKV("fee", ValueFromAmount(nFee));

    WalletTxToJSON(wtx, entry);

    UniValue details(UniValue::VARR);
    ListTransactions(pwallet, wtx, "*", 0, false, details, filter);
    entry.pushKV("details", details);

    std::string strHex = EncodeHexTx(static_cast<CTransaction>(wtx));
    entry.pushKV("hex", strHex);

    return entry;
}

UniValue abandontransaction(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "abandontransaction \"txid\"\n"
            "\nMark in-wallet transaction <txid> as abandoned\n"
            "This will mark this transaction and all its in-wallet descendants as abandoned which will allow\n"
            "for their inputs to be respent.  It can be used to replace \"stuck\" or evicted transactions.\n"
            "It only works on transactions which are not included in a block and are not currently in the mempool.\n"
            "It has no effect on transactions which are already conflicted or abandoned.\n"
            "\nArguments:\n"
            "1. \"txid\"    (string, required) The transaction id\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleRpc("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
        );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    uint256 hash;
    hash.SetHex(request.params[0].get_str());

    if (!pwallet->mapWallet.count(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    }
    if (!pwallet->AbandonTransaction(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not eligible for abandonment");
    }

    return NullUniValue;
}

UniValue backupwallet(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "backupwallet \"destination\"\n"
                "\nSafely copies current wallet file to destination, which can be a directory or a path with filename.\n"
                "\nArguments:\n"
                "1. \"destination\"   (string) The destination directory or file\n"
                "\nExamples:\n"
                + HelpExampleCli("backupwallet", "\"backup.dat\"")
                + HelpExampleRpc("backupwallet", "\"backup.dat\"")
            );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strDest = request.params[0].get_str();
    if (!pwallet->BackupWallet(strDest)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");
    }

    return NullUniValue;
}


UniValue keypoolrefill(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
                "keypoolrefill ( newsize )\n"
                "\nFills the keypool."
                + HelpRequiringPassphrase(pwallet) + "\n"
                "\nArguments\n"
                "1. newsize     (numeric, optional, default=100) The new keypool size\n"
                "\nExamples:\n"
                + HelpExampleCli("keypoolrefill", "")
                + HelpExampleRpc("keypoolrefill", "")
            );

    LOCK2(cs_main, pwallet->cs_wallet);

    // 0 is interpreted by TopUpKeyPool() as the default keypool size given by -keypool
    unsigned int kpSize = 0;
    if (!request.params[0].isNull()) {
        if (request.params[0].get_int() < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size.");
        kpSize = (unsigned int)request.params[0].get_int();
    }

    EnsureWalletIsUnlocked(pwallet);
    pwallet->TopUpKeyPool(kpSize);

    if (pwallet->GetKeyPoolSize() < kpSize) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");
    }

    return NullUniValue;
}


static void LockWallet(CWallet* pWallet)
{
    LOCK(pWallet->cs_wallet);
    pWallet->nRelockTime = 0;
    pWallet->Lock();
}

UniValue walletpassphrase(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (pwallet->IsCrypted() && (request.fHelp || request.params.size() != 2)) {
        throw std::runtime_error(
                "walletpassphrase \"passphrase\" timeout\n"
                "\nStores the wallet decryption key in memory for 'timeout' seconds.\n"
                "This is needed prior to performing transactions related to private keys such as sending animecoins\n"
                "\nArguments:\n"
                "1. \"passphrase\"     (string, required) The wallet passphrase\n"
                "2. timeout            (numeric, required) The time to keep the decryption key in seconds.\n"
                "\nNote:\n"
                "Issuing the walletpassphrase command while the wallet is already unlocked will set a new unlock\n"
                "time that overrides the old one.\n"
                "\nExamples:\n"
                "\nunlock the wallet for 60 seconds\n"
                + HelpExampleCli("walletpassphrase", "\"my pass phrase\" 60") +
                "\nLock the wallet again (before 60 seconds)\n"
                + HelpExampleCli("walletlock", "") +
                "\nAs json rpc call\n"
                + HelpExampleRpc("walletpassphrase", "\"my pass phrase\", 60")
            );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrase was called.");
    }

    // Note that the walletpassphrase is stored in request.params[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    strWalletPass = request.params[0].get_str().c_str();

    if (strWalletPass.length() > 0)
    {
        if (!pwallet->Unlock(strWalletPass)) {
            throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
        }
    }
    else
        throw std::runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");

    pwallet->TopUpKeyPool();

    int64_t nSleepTime = request.params[1].get_int64();
    pwallet->nRelockTime = GetTime() + nSleepTime;
    RPCRunLater(strprintf("lockwallet(%s)", pwallet->GetName()), boost::bind(LockWallet, pwallet), nSleepTime);

    return NullUniValue;
}


UniValue walletpassphrasechange(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (pwallet->IsCrypted() && (request.fHelp || request.params.size() != 2)) {
        throw std::runtime_error(
                "walletpassphrasechange \"oldpassphrase\" \"newpassphrase\"\n"
                "\nChanges the wallet passphrase from 'oldpassphrase' to 'newpassphrase'.\n"
                "\nArguments:\n"
                "1. \"oldpassphrase\"      (string) The current passphrase\n"
                "2. \"newpassphrase\"      (string) The new passphrase\n"
                "\nExamples:\n"
                + HelpExampleCli("walletpassphrasechange", "\"old one\" \"new one\"")
                + HelpExampleRpc("walletpassphrasechange", "\"old one\", \"new one\"")
            );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");
    }

    // TODO: get rid of these .c_str() calls by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = request.params[0].get_str().c_str();

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = request.params[1].get_str().c_str();

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
        throw std::runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");

    if (!pwallet->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass)) {
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }

    return NullUniValue;
}


UniValue walletlock(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (pwallet->IsCrypted() && (request.fHelp || request.params.size() != 0)) {
        throw std::runtime_error(
            "walletlock\n"
            "\nRemoves the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call walletpassphrase again\n"
            "before being able to call any methods which require the wallet to be unlocked.\n"
            "\nExamples:\n"
            "\nSet the passphrase for 2 minutes to perform a transaction\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\" 120") +
            "\nPerform a send (requires passphrase set)\n"
            + HelpExampleCli("sendtoaddress", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\" 1.0") +
            "\nClear the passphrase since we are done before 2 minutes is up\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("walletlock", "")
        );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletlock was called.");
    }

    pwallet->Lock();
    pwallet->nRelockTime = 0;

    return NullUniValue;
}


UniValue encryptwallet(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (!pwallet->IsCrypted() && (request.fHelp || request.params.size() != 1)) {
        throw std::runtime_error(
                "encryptwallet \"passphrase\"\n"
                "\nEncrypts the wallet with 'passphrase'. This is for first time encryption.\n"
                "After this, any calls that interact with private keys such as sending or signing \n"
                "will require the passphrase to be set prior the making these calls.\n"
                "Use the walletpassphrase call for this, and then walletlock call.\n"
                "If the wallet is already encrypted, use the walletpassphrasechange call.\n"
                "Note that this will shutdown the server.\n"
                "\nArguments:\n"
                "1. \"passphrase\"    (string) The pass phrase to encrypt the wallet with. It must be at least 1 character, but should be long.\n"
                "\nExamples:\n"
                "\nEncrypt you wallet\n"
                + HelpExampleCli("encryptwallet", "\"my pass phrase\"") +
                "\nNow set the passphrase to use the wallet, such as for signing or sending animecoins\n"
                + HelpExampleCli("walletpassphrase", "\"my pass phrase\"") +
                "\nNow we can so something like sign\n"
                + HelpExampleCli("signmessage", "\"address\" \"test message\"") +
                "\nNow lock the wallet again by removing the passphrase\n"
                + HelpExampleCli("walletlock", "") +
                "\nAs a json rpc call\n"
                + HelpExampleRpc("encryptwallet", "\"my pass phrase\"")
            );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");
    }

    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass = request.params[0].get_str().c_str();

    if (strWalletPass.length() < 1)
        throw std::runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");

    if (!pwallet->EncryptWallet(strWalletPass)) {
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");
    }

    // BDB seems to have a bad habit of writing old data into
    // slack space in .dat files; that is bad if the old data is
    // unencrypted private keys. So:
    StartShutdown();
    return "wallet encrypted; Animecoin server stopping, restart to run with encrypted wallet. The keypool has been flushed and a new HD seed was generated (if you are using HD). You need to make a new backup.";
}

UniValue lockunspent(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
                "lockunspent unlock [{\"txid\":\"txid\",\"vout\":n},...]\n"
                "\nUpdates list of temporarily unspendable outputs.\n"
                "Temporarily lock (unlock=false) or unlock (unlock=true) specified transaction outputs.\n"
                "A locked transaction output will not be chosen by automatic coin selection, when spending animecoins.\n"
                "Locks are stored in memory only. Nodes start with zero locked outputs, and the locked output list\n"
                "is always cleared (by virtue of process exit) when a node stops or fails.\n"
                "Also see the listunspent call\n"
                "\nArguments:\n"
                "1. unlock            (boolean, required) Whether to unlock (true) or lock (false) the specified transactions\n"
                "2. \"transactions\"  (string, required) A json array of objects. Each object the txid (string) vout (numeric)\n"
                "     [           (json array of json objects)\n"
                "       {\n"
                "         \"txid\":\"id\",    (string) The transaction id\n"
                "         \"vout\": n         (numeric) The output number\n"
                "       }\n"
                "       ,...\n"
                "     ]\n"

                "\nResult:\n"
                "true|false    (boolean) Whether the command was successful or not\n"

                "\nExamples:\n"
                "\nList the unspent transactions\n"
                + HelpExampleCli("listunspent", "") +
                "\nLock an unspent transaction\n"
                + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
                "\nList the locked transactions\n"
                + HelpExampleCli("listlockunspent", "") +
                "\nUnlock the transaction again\n"
                + HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
                "\nAs a json rpc call\n"
                + HelpExampleRpc("lockunspent", "false, \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"")
            );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.params.size() == 1)
        RPCTypeCheck(request.params, {UniValue::VBOOL});
    else
        RPCTypeCheck(request.params, {UniValue::VBOOL, UniValue::VARR});

    bool fUnlock = request.params[0].get_bool();

    if (request.params.size() == 1) {
        if (fUnlock)
            pwallet->UnlockAllCoins();
        return true;
    }

    UniValue outputs = request.params[1].get_array();
    for (unsigned int idx = 0; idx < outputs.size(); idx++) {
        const UniValue& output = outputs[idx];
        if (!output.isObject())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected object");
        const UniValue& o = output.get_obj();

        RPCTypeCheckObj(o,
            {
                {"txid", UniValueType(UniValue::VSTR)},
                {"vout", UniValueType(UniValue::VNUM)},
            });

        std::string txid = find_value(o, "txid").get_str();
        if (!IsHex(txid))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected hex txid");

        int nOutput = find_value(o, "vout").get_int();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        COutPoint outpt(uint256S(txid), nOutput);

        if (fUnlock)
            pwallet->UnlockCoin(outpt);
        else
            pwallet->LockCoin(outpt);
    }

    return true;
}

UniValue listlockunspent(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0)
        throw std::runtime_error(
            "listlockunspent\n"
            "\nReturns list of temporarily unspendable outputs.\n"
            "See the lockunspent call to lock and unlock transactions for spending.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"txid\" : \"transactionid\",     (string) The transaction id locked\n"
            "    \"vout\" : n                      (numeric) The vout value\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            "\nList the unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n"
            + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n"
            + HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n"
            + HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("listlockunspent", "")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    std::vector<COutPoint> vOutpts;
    pwallet->ListLockedCoins(vOutpts);

    UniValue ret(UniValue::VARR);

    for (const COutPoint& outpt : vOutpts) {
        UniValue o(UniValue::VOBJ);

        o.pushKV("txid", outpt.hash.GetHex());
        o.pushKV("vout", (int)outpt.n);
        ret.push_back(o);
    }

    return ret;
}

UniValue settxfee(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 1)
        throw std::runtime_error(
                "settxfee amount\n"
                "\nSet the transaction fee per kB.\n"
                "\nArguments:\n"
                "1. amount         (numeric, required) The transaction fee in " + CURRENCY_UNIT + "/kB rounded to the nearest 0.00000001\n"
                "\nResult\n"
                "true|false        (boolean) Returns true if successful\n"
                "\nExamples:\n"
                + HelpExampleCli("settxfee", "0.00001")
                + HelpExampleRpc("settxfee", "0.00001")
            );

    LOCK2(cs_main, pwallet->cs_wallet);

    // Amount
    CAmount nAmount = AmountFromValue(request.params[0]);

    payTxFee = CFeeRate(nAmount, 1000);
    return true;
}

UniValue getwalletinfo(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getwalletinfo\n"
            "Returns an object containing various wallet state info.\n"
            "\nResult:\n"
            "{\n"
                "  \"walletversion\": xxxxx,          (numeric) the wallet version\n"
                "  \"balance\": xxxxxxx,              (numeric) the total confirmed balance of the wallet in " + CURRENCY_UNIT + "\n"
                "  \"unconfirmed_balance\": xxx,      (numeric) the total unconfirmed balance of the wallet in " + CURRENCY_UNIT + "\n"
                "  \"immature_balance\": xxxxxx,      (numeric) the total immature balance of the wallet in " + CURRENCY_UNIT + "\n"
                "  \"txcount\": xxxxxxx,              (numeric) the total number of transactions in the wallet\n"
                "  \"keypoololdest\": xxxxxx,         (numeric) the timestamp (seconds since Unix epoch) of the oldest pre-generated key in the key pool\n"
                "  \"keypoolsize\": xxxx,             (numeric) how many new keys are pre-generated (only counts external keys)\n"
                "  \"keypoolsize_hd_internal\": xxxx, (numeric) how many new keys are pre-generated for internal use (used for change outputs, only appears if the wallet is using this feature, otherwise external keys are used)\n"
                "  \"unlocked_until\": ttt,           (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
                "  \"paytxfee\": x.xxxx,              (numeric) the transaction fee configuration, set in " + CURRENCY_UNIT + "/kB\n"
                "  \"hdmasterkeyid\": \"<hash160>\"     (string) the Hash160 of the HD master pubkey\n"
                "  \"spv_bestblock_height\": x,    (numeric) the height of the latest SPV scanned block\n"
                "  \"spv_bestblock_hash\": x,      (string) the hash of the latest SPV scanned block\n"
                "  \"spv_headerschain_height\": x, (numeric) the height of the wallets headers-chain tip\n"
                "  \"spv_scan_started\": ttt,      (numeric) Timestamp of the last started SPV blocks scan\n"
                "  \"spv_blocks_requested\": x,    (numeric) the amount of requested blocks in the current scan\n"
                "  \"spv_blocks_loaded\": x,       (numeric) the amount of loaded blocks in the current scan\n"
                "  \"spv_blocks_processed\": x,    (numeric) the amount of processed blocks in the current scan\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getwalletinfo", "")
            + HelpExampleRpc("getwalletinfo", "")
        );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    UniValue obj(UniValue::VOBJ);

    size_t kpExternalSize = pwallet->KeypoolCountExternalKeys();
    obj.pushKV("walletversion", pwallet->GetVersion());
    obj.pushKV("balance",       ValueFromAmount(pwallet->GetBalance()));
    obj.pushKV("unconfirmed_balance", ValueFromAmount(pwallet->GetUnconfirmedBalance()));
    obj.pushKV("immature_balance",    ValueFromAmount(pwallet->GetImmatureBalance()));
    obj.pushKV("txcount",       (int)pwallet->mapWallet.size());
    obj.pushKV("keypoololdest", pwallet->GetOldestKeyPoolTime());
    obj.pushKV("keypoolsize", (int64_t)kpExternalSize);
    CKeyID masterKeyID = pwallet->GetHDChain().masterKeyID;
    if (!masterKeyID.IsNull() && pwallet->CanSupportFeature(FEATURE_HD_SPLIT)) {
        obj.pushKV("keypoolsize_hd_internal",   (int64_t)(pwallet->GetKeyPoolSize() - kpExternalSize));
    }
    if (pwallet->IsCrypted()) {
        obj.pushKV("unlocked_until", pwallet->nRelockTime);
    }
    obj.pushKV("paytxfee",      ValueFromAmount(payTxFee.GetFeePerK()));
    if (!masterKeyID.IsNull())
        obj.pushKV("hdmasterkeyid", masterKeyID.GetHex());
    obj.pushKV("spv_enabled", (int)(pwallet->IsSPVEnabled()));
    obj.pushKV("spv_bestblock_height", (int)(pwallet->pNVSBestBlock ? pwallet->pNVSBestBlock->nHeight : 0));
    obj.pushKV("spv_bestblock_hash", (pwallet->pNVSBestBlock ? pwallet->pNVSBestBlock->GetBlockHash().GetHex() : ""));
    obj.pushKV("spv_headerschain_height", (int)(pwallet->pNVSLastKnownBestHeader ? pwallet->pNVSLastKnownBestHeader->nHeight : 0));
    std::shared_ptr<CAuxiliaryBlockRequest> blockRequest = CAuxiliaryBlockRequest::GetCurrentRequest();
    obj.pushKV("spv_scan_started", (!blockRequest ? 0 : UniValue(blockRequest->created)));
    obj.pushKV("spv_blocks_requested", (int64_t)(!blockRequest ? 0 : blockRequest->vBlocksToDownload.size()));
    obj.pushKV("spv_blocks_loaded", (int)(!blockRequest ? 0 : blockRequest->amountOfBlocksLoaded()));
    obj.pushKV("spv_blocks_processed", (!blockRequest ? 0 : (int64_t)blockRequest->processedUpToSize));

    return obj;
}

UniValue resendwallettransactions(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "resendwallettransactions\n"
            "Immediately re-broadcast unconfirmed wallet transactions to all peers.\n"
            "Intended only for testing; the wallet code periodically re-broadcasts\n"
            "automatically.\n"
            "Returns array of transaction ids that were re-broadcast.\n"
            );

    if (!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    LOCK2(cs_main, pwallet->cs_wallet);

    std::vector<uint256> txids = pwallet->ResendWalletTransactionsBefore(GetTime(), g_connman.get());
    UniValue result(UniValue::VARR);
    for (const uint256& txid : txids)
    {
        result.push_back(txid.ToString());
    }
    return result;
}

UniValue listunspent(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 4)
        throw std::runtime_error(
                "listunspent ( minconf maxconf  [\"addresses\",...] [include_unsafe] )\n"
                "\nReturns array of unspent transaction outputs\n"
            "with between minconf and maxconf (inclusive) confirmations.\n"
                "Optionally filter to only include txouts paid to specified addresses.\n"
            "Results are an array of Objects, each of which has:\n"
                "{txid, vout, scriptPubKey, amount, confirmations}\n"
                "\nArguments:\n"
                "1. minconf          (numeric, optional, default=1) The minimum confirmations to filter\n"
                "2. maxconf          (numeric, optional, default=9999999) The maximum confirmations to filter\n"
                "3. \"addresses\"    (string) A json array of animecoin addresses to filter\n"
                "    [\n"
                "      \"address\"   (string) animecoin address\n"
                "      ,...\n"
                "    ]\n"
                "4. include_unsafe (bool, optional, default=true) Include outputs that are not safe to spend\n"
                "                  because they come from unconfirmed untrusted transactions or unconfirmed\n"
                "                  replacement transactions (cases where we are less sure that a conflicting\n"
                "                  transaction won't be mined).\n"
                "\nResult\n"
                "[                   (array of json object)\n"
                "  {\n"
                "    \"txid\" : \"txid\",        (string) the transaction id \n"
                "    \"vout\" : n,               (numeric) the vout value\n"
                "    \"address\" : \"address\",  (string) the animecoin address\n"
                "    \"account\" : \"account\",  (string) The associated account, or \"\" for the default account\n"
                "    \"scriptPubKey\" : \"key\", (string) the script key\n"
                "    \"amount\" : x.xxx,         (numeric) the transaction amount in " + CURRENCY_UNIT + "\n"
                "    \"confirmations\" : n,      (numeric) The number of confirmations\n"
                "    \"spendable\" : xxx,        (bool) Whether we have the private keys to spend this output\n"
                "    \"solvable\" : xxx          (bool) Whether we know how to spend this output, ignoring the lack of keys\n"
                "    \"redeemScript\" : n        (string) The redeemScript if scriptPubKey is P2SH\n"
                "  }\n"
                "  ,...\n"
                "]\n"

                "\nExamples\n"
                + HelpExampleCli("listunspent", "")
                + HelpExampleCli("listunspent", "6 9999999 \"[\\\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\\\",\\\"Ad9gq1rYvKDiFWCQPnrXVBCZEhwmQYXNks\\\"]\"")
                + HelpExampleRpc("listunspent", "6, 9999999 \"[\\\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\\\",\\\"Ad9gq1rYvKDiFWCQPnrXVBCZEhwmQYXNks\\\"]\"")
            );

    int nMinDepth = 1;
    if (request.params.size() > 0 && !request.params[0].isNull()) {
        RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
        nMinDepth = request.params[0].get_int();
    }

    int nMaxDepth = 9999999;
    if (request.params.size() > 1 && !request.params[1].isNull()) {
        RPCTypeCheckArgument(request.params[1], UniValue::VNUM);
        nMaxDepth = request.params[1].get_int();
    }

    std::set<CBitcoinAddress> setAddress;
    if (request.params.size() > 2 && !request.params[2].isNull()) {
        RPCTypeCheckArgument(request.params[2], UniValue::VARR);
        UniValue inputs = request.params[2].get_array();
        for (unsigned int idx = 0; idx < inputs.size(); idx++) {
            const UniValue& input = inputs[idx];
            CBitcoinAddress address(input.get_str());
            if (!address.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Animecoin address: ")+input.get_str());
            if (setAddress.count(address))
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ")+input.get_str());
           setAddress.insert(address);
        }
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    bool include_unsafe = true;
    if (request.params.size() > 3 && !request.params[3].isNull()) {
        RPCTypeCheckArgument(request.params[3], UniValue::VBOOL);
        include_unsafe = request.params[3].get_bool();
    }

    UniValue results(UniValue::VARR);
    std::vector<COutput> vecOutputs;
    LOCK2(cs_main, pwallet->cs_wallet);
    pwalletMain->AvailableCoins(vecOutputs, !include_unsafe, nullptr, true);
    for (const COutput& out : vecOutputs) {
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth)
            continue;

        CTxDestination address;
        const CScript& scriptPubKey = out.tx->vout[out.i].scriptPubKey;
        bool fValidAddress = ExtractDestination(scriptPubKey, address);

        if (setAddress.size() && (!fValidAddress || !setAddress.count(address)))
            continue;

        UniValue entry(UniValue::VOBJ);
        entry.pushKV("txid", out.tx->GetHash().GetHex());
        entry.pushKV("vout", out.i);

        if (fValidAddress) {
            entry.pushKV("address", CBitcoinAddress(address).ToString());

            if (pwallet->mapAddressBook.count(address)) {
                entry.pushKV("account", pwallet->mapAddressBook[address].name);
            }

            if (scriptPubKey.IsPayToScriptHash()) {
                const CScriptID& hash = boost::get<CScriptID>(address);
                CScript redeemScript;
                if (pwallet->GetCScript(hash, redeemScript)) {
                    entry.pushKV("redeemScript", HexStr(redeemScript.begin(), redeemScript.end()));
                }
            }
        }

        entry.pushKV("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end()));
        entry.pushKV("amount", ValueFromAmount(out.tx->vout[out.i].nValue));
        entry.pushKV("confirmations", out.nDepth);
        entry.pushKV("spendable", out.IsSpendableAfter(*chainActive.Tip(), *pwalletMain));
        entry.pushKV("solvable", out.IsSolvableAfter(*chainActive.Tip(), *pwalletMain));
        results.push_back(entry);
    }

    return results;
}

UniValue fundrawtransaction(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

   if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
               "fundrawtransaction \"hexstring\" ( options )\n"
                            "\nAdd inputs to a transaction until it has enough in value to meet its out value.\n"
                            "This will not modify existing inputs, and will add one change output to the outputs.\n"
                            "Note that inputs which were signed may need to be resigned after completion since in/outputs have been added.\n"
                            "The inputs added will not be signed, use signrawtransaction for that.\n"
                            "Note that all existing inputs must have their previous output transaction be in the wallet.\n"
                            "Note that all inputs selected must be of standard form and P2SH scripts must be"
                            "in the wallet using importaddress or addmultisigaddress (to calculate fees).\n"
                            "You can see whether this is the case by checking the \"solvable\" field in the listunspent output.\n"
                            "Only pay-to-pubkey, multisig, and P2SH versions thereof are currently supported for watch-only\n"
                            "\nArguments:\n"
                            "1. \"hexstring\"           (string, required) The hex string of the raw transaction\n"
                            "2. options                 (object, optional)\n"
                            "   {\n"
                            "     \"changeAddress\"     (string, optional, default pool address) The animecoin address to receive the change\n"
                            "     \"changePosition\"    (numeric, optional, default random) The index of the change output\n"
                            "     \"includeWatching\"   (boolean, optional, default false) Also select inputs which are watch only\n"
                            "     \"lockUnspents\"      (boolean, optional, default false) Lock selected unspent outputs\n"
                            "     \"feeRate\"           (numeric, optional, default not set: makes wallet determine the fee) Set a specific feerate (" + CURRENCY_UNIT + " per KB)\n"
                            "   }\n"
                            "                         for backward compatibility: passing in a true instzead of an object will result in {\"includeWatching\":true}\n"
                            "\nResult:\n"
                            "{\n"
                            "  \"hex\":       \"value\", (string)  The resulting raw transaction (hex-encoded string)\n"
                            "  \"fee\":       n,         (numeric) Fee in " + CURRENCY_UNIT + " the resulting transaction pays\n"
                            "  \"changepos\": n          (numeric) The position of the added change output, or -1\n"
                            "}\n"
                            "\nExamples:\n"
                            "\nCreate a transaction with no inputs\n"
                            + HelpExampleCli("createrawtransaction", "\"[]\" \"{\\\"myaddress\\\":0.01}\"") +
                            "\nAdd sufficient unsigned inputs to meet the output value\n"
                            + HelpExampleCli("fundrawtransaction", "\"rawtransactionhex\"") +
                            "\nSign the transaction\n"
                            + HelpExampleCli("signrawtransaction", "\"fundedtransactionhex\"") +
                            "\nSend the transaction\n"
                            + HelpExampleCli("sendrawtransaction", "\"signedtransactionhex\"")
                            );

   RPCTypeCheck(request.params, {UniValue::VSTR});

   // Make sure the results are valid at least up to the most recent block
   // the user could have gotten from another RPC command prior to now
   pwallet->BlockUntilSyncedToCurrentChain();

   CTxDestination changeAddress = CNoDestination();
   int changePosition = -1;
   bool includeWatching = false;
   bool lockUnspents = false;
   CFeeRate feeRate = CFeeRate(0);
   bool overrideEstimatedFeerate = false;

   if (!request.params[1].isNull()) {
     if (request.params[1].type() == UniValue::VBOOL) {
       // backward compatibility bool only fallback
       includeWatching = request.params[1].get_bool();
     }
     else {
         RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VOBJ});

       UniValue options = request.params[1];

       RPCTypeCheckObj(options,
           {
               {"changeAddress", UniValueType(UniValue::VSTR)},
               {"changePosition", UniValueType(UniValue::VNUM)},
               {"includeWatching", UniValueType(UniValue::VBOOL)},
               {"lockUnspents", UniValueType(UniValue::VBOOL)},
               {"feeRate", UniValueType()}, // will be checked below
           },
           true, true);

       if (options.exists("changeAddress")) {
           CBitcoinAddress address(options["changeAddress"].get_str());

           if (!address.IsValid())
               throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "changeAddress must be a valid animecoin address");

           changeAddress = address.Get();
       }

       if (options.exists("changePosition"))
           changePosition = options["changePosition"].get_int();

       if (options.exists("includeWatching"))
           includeWatching = options["includeWatching"].get_bool();

       if (options.exists("lockUnspents"))
           lockUnspents = options["lockUnspents"].get_bool();

       if (options.exists("feeRate"))
       {
           feeRate = CFeeRate(AmountFromValue(options["feeRate"]));
           overrideEstimatedFeerate = true;
       }
     }
   }

    // parse hex string from parameter
    CTransaction origTx;
    if (!DecodeHexTx(origTx, request.params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    if (changePosition != -1 && (changePosition < 0 || (unsigned int)changePosition > origTx.vout.size()))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "changePosition out of bounds");

    CMutableTransaction tx(origTx);
    CAmount nFeeOut;
    std::string strFailReason;

    if (!pwallet->FundTransaction(tx, nFeeOut, overrideEstimatedFeerate, feeRate, changePosition, strFailReason, includeWatching, lockUnspents, changeAddress)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strFailReason);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(tx));
    result.pushKV("changepos", changePosition);
    result.pushKV("fee", ValueFromAmount(nFeeOut));

    return result;
}

UniValue setspv(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
                            "setspv (true|false)\n"
                            "\nEnabled or disabled full block SPV mode.\n"
                            "\nArguments:\n"
                            "1. state             (boolean, optional) enables or disables the spv mode\n"
                            "\nResult:\n"
                            "   status: <true|false> (\"true\" if the spv mode is enabled)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("setspv", "\"true\"")
                            + HelpExampleRpc("setspv", "\"true\"")
                            );

    if (request.params.size() == 1)
    {
        pwallet->setSPVEnabled(request.params[0].get_bool());
        fFetchBlocksWhileFetchingHeaders = !request.params[0].get_bool();
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("status", UniValue(pwallet->IsSPVEnabled()));
    return ret;
}

UniValue sethdseed(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(
            "sethdseed ( \"newkeypool\" \"seed\" )\n"
            "\nSet or generate a new HD wallet seed. Non-HD wallets will not be upgraded to being a HD wallet. Wallets that are already\n"
            "HD will have a new HD seed set so that new keys added to the keypool will be derived from this new seed.\n"
            "\nNote that you will need to MAKE A NEW BACKUP of your wallet after setting the HD wallet seed.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "1. \"newkeypool\"         (boolean, optional, default=true) Whether to flush old unused addresses, including change addresses, from the keypool and regenerate it.\n"
            "                             If true, the next address from getnewaddress and change address from getrawchangeaddress will be from this new seed.\n"
            "                             If false, addresses (including change addresses if the wallet already had HD Chain Split enabled) from the existing\n"
            "                             keypool will be used until it has been depleted.\n"
            "2. \"seed\"               (string, optional) The WIF private key to use as the new HD seed; if not provided a random seed will be used.\n"
            "                             The seed value can be retrieved using the dumpwallet command. It is the private key marked hdmaster=1\n"
            "\nExamples:\n"
            + HelpExampleCli("sethdseed", "")
            + HelpExampleCli("sethdseed", "false")
            + HelpExampleCli("sethdseed", "true \"wifkey\"")
            + HelpExampleRpc("sethdseed", "true, \"wifkey\"")
            );
    }

    if (IsInitialBlockDownload()) {
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Cannot set a new HD seed while still in Initial Block Download");
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    // Do not do anything to non-HD wallets
    if (!pwallet->IsHDEnabled()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot set a HD seed on a non-HD wallet. Start with -upgradewallet in order to upgrade a non-HD wallet to HD");
    }

    EnsureWalletIsUnlocked(pwallet);

    bool flush_key_pool = true;
    if (!request.params[0].isNull()) {
        flush_key_pool = request.params[0].get_bool();
    }

    CPubKey master_pub_key;
    if (request.params[1].isNull()) {
        master_pub_key = pwallet->GenerateNewHDMasterKey();
    } else {
        CBitcoinSecret vchSecret;
        vchSecret.SetString(request.params[1].get_str());
        CKey key = vchSecret.GetKey();
        //CKey key = DecodeSecret(request.params[1].get_str());
        if (!key.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
        }

        if (HaveKey(*pwallet, key)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Already have this key (either as an HD seed or as a loose private key)");
        }

        master_pub_key = pwallet->DeriveNewMasterHDKey(key);
    }

    pwallet->SetHDMasterKey(master_pub_key);
    if (flush_key_pool) pwallet->NewKeyPool();

    return NullUniValue;
}

extern UniValue dumpprivkey(const JSONRPCRequest& request); // in rpcdump.cpp
extern UniValue importprivkey(const JSONRPCRequest& request);
extern UniValue importaddress(const JSONRPCRequest& request);
extern UniValue importpubkey(const JSONRPCRequest& request);
extern UniValue dumpwallet(const JSONRPCRequest& request);
extern UniValue importwallet(const JSONRPCRequest& request);
extern UniValue importprunedfunds(const JSONRPCRequest& request);
extern UniValue removeprunedfunds(const JSONRPCRequest& request);
extern UniValue importmulti(const JSONRPCRequest& request);

static const CRPCCommand commands[] =
{ //  category              name                        actor (function)           okSafeMode
    //  --------------------- ------------------------    -----------------------    ----------
  { "rawtransactions",    "fundrawtransaction",       &fundrawtransaction,       false,  {"hexstring","options"} },
  { "hidden",             "resendwallettransactions", &resendwallettransactions, true,   {} },
  { "wallet",             "abandontransaction",       &abandontransaction,       false,  {"txid"} },
  { "wallet",             "addmultisigaddress",       &addmultisigaddress,       true,   {"nrequired","keys","account"} },
//  { "wallet",             "addwitnessaddress",        &addwitnessaddress,        true,   {"address"} },
  { "wallet",             "backupwallet",             &backupwallet,             true,   {"destination"} },
  { "wallet",             "dumpprivkey",              &dumpprivkey,              true,   {"address"}  },
  { "wallet",             "dumpwallet",               &dumpwallet,               true,   {"filename"} },
  { "wallet",             "encryptwallet",            &encryptwallet,            true,   {"passphrase"} },
  { "wallet",             "getaccountaddress",        &getaccountaddress,        true,   {"account"} },
  { "wallet",             "getaccount",               &getaccount,               true,   {"address"} },
  { "wallet",             "getaddressesbyaccount",    &getaddressesbyaccount,    true,   {"account"} },
  { "wallet",             "getbalance",               &getbalance,               false,  {"account","minconf","include_watchonly"} },
  { "wallet",             "getnewaddress",            &getnewaddress,            true,   {"account"} },
  { "wallet",             "getrawchangeaddress",      &getrawchangeaddress,      true,   {} },
  { "wallet",             "getreceivedbyaccount",     &getreceivedbyaccount,     false,  {"account","minconf"} },
  { "wallet",             "getreceivedbyaddress",     &getreceivedbyaddress,     false,  {"address","minconf"} },
  { "wallet",             "gettransaction",           &gettransaction,           false,  {"txid","include_watchonly"} },
  { "wallet",             "getunconfirmedbalance",    &getunconfirmedbalance,    false,  {} },
  { "wallet",             "getwalletinfo",            &getwalletinfo,            false,  {} },
  { "wallet",             "importmulti",              &importmulti,              true,   {"requests","options"} },
  { "wallet",             "importprivkey",            &importprivkey,            true,   {"privkey","label","rescan"} },
  { "wallet",             "importwallet",             &importwallet,             true,   {"filename"} },
  { "wallet",             "importaddress",            &importaddress,            true,   {"address","label","rescan","p2sh"} },
  { "wallet",             "importprunedfunds",        &importprunedfunds,        true,   {"rawtransaction","txoutproof"} },
  { "wallet",             "importpubkey",             &importpubkey,             true,   {"pubkey","label","rescan"} },
  { "wallet",             "keypoolrefill",            &keypoolrefill,            true,   {"newsize"} },
  { "wallet",             "listaccounts",             &listaccounts,             false,  {"minconf","include_watchonly"} },
  { "wallet",             "listaddressgroupings",     &listaddressgroupings,     false,  {} },
  { "wallet",             "listlockunspent",          &listlockunspent,          false,  {} },
  { "wallet",             "listreceivedbyaccount",    &listreceivedbyaccount,    false,  {"minconf","include_empty","include_watchonly"} },
  { "wallet",             "listreceivedbyaddress",    &listreceivedbyaddress,    false,  {"minconf","include_empty","include_watchonly"} },
  { "wallet",             "listsinceblock",           &listsinceblock,           false,  {"blockhash","target_confirmations","include_watchonly","include_removed"} },
  { "wallet",             "listtransactions",         &listtransactions,         false,  {"account","count","skip","include_watchonly"} },
  { "wallet",             "listunspent",              &listunspent,              false,  {"minconf","maxconf","addresses","include_unsafe"} },
  { "wallet",             "lockunspent",              &lockunspent,              true,   {"unlock","transactions"} },
  { "wallet",             "move",                     &movecmd,                  false,  {"fromaccount","toaccount","amount","minconf","comment"} },
  { "wallet",             "sendfrom",                 &sendfrom,                 false,  {"fromaccount","toaddress","amount","minconf","comment","comment_to"} },
  { "wallet",             "sendmany",                 &sendmany,                 false,  {"fromaccount","amounts","minconf","comment","subtractfeefrom"} },
  { "wallet",             "sendtoaddress",            &sendtoaddress,            false,  {"address","amount","comment","comment_to","subtractfeefromamount"} },
  { "wallet",             "setaccount",               &setaccount,               true,   {"address","account"} },
  { "wallet",             "settxfee",                 &settxfee,                 true,   {"amount"} },
  { "wallet",             "signmessage",              &signmessage,              true,   {"address","message"} },
  { "wallet",             "walletlock",               &walletlock,               true,   {} },
  { "wallet",             "walletpassphrasechange",   &walletpassphrasechange,   true,   {"oldpassphrase","newpassphrase"} },
  { "wallet",             "walletpassphrase",         &walletpassphrase,         true,   {"passphrase","timeout"} },
  { "wallet",             "removeprunedfunds",        &removeprunedfunds,        true,   {"txid"} },
  { "wallet",             "sethdseed",                &sethdseed,                true,   {"newkeypool","seed"} },
  { "wallet",             "setspv",                   &setspv,                   true,   {"state"} },
};

void RegisterWalletRPCCommands(CRPCTable &t)
{
    if (GetBoolArg("-disablewallet", false))
        return;

    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
