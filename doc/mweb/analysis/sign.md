# Signing Process (MWEB & Non-MWEB)

## Functions


Typical flow (non-MWEB):

Consumer -> CWallet::SignTransaction -> ScriptPubKeyMan::SignTransaction -> ::SignTransaction


### wallet.cpp

There are 2 `SignTransaction` functions in `CWallet`. They are both public, with a few different consumers.

1. `SignTransaction(mtx, coins, sighash, input_errors)` just calls `SignTransaction` for each spkman.
```cpp
bool CWallet::SignTransaction(CMutableTransaction& tx, const std::map<AnyOutputID, AnyCoin>& coins, int sighash, std::map<int, bilingual_str>& input_errors) const
{
    // Try to sign with all ScriptPubKeyMans
    for (ScriptPubKeyMan* spk_man : GetAllScriptPubKeyMans()) {
        // spk_man->SignTransaction will return true if the transaction is complete,
        // so we can exit early and return true if that happens
        if (spk_man->SignTransaction(tx, coins, sighash, input_errors)) {
            return true;
        }
    }

    // At this point, one input was not fully signed otherwise we would have exited already
    return false;
}
```

2. `SignTransaction(mtx)` fetches inputs first (i.e. builds coins map), before calling into `SignTransaction(mtx, coins, sighash, input_errors)`.
```cpp
bool CWallet::SignTransaction(CMutableTransaction& tx) const
{
    AssertLockHeld(cs_wallet);

    // Build coins map
    std::map<AnyOutputID, AnyCoin> coins;
    for (const AnyInput& tx_input : tx.GetInputs()) {
        const CWalletTx* wtx = FindPrevTx(tx_input);
        AnyOutputID input_id = tx_input.GetID();
        if (wtx == nullptr || !wtx->HasOutput(input_id)) {
            return false;
        }

        int prev_height = wtx->state<TxStateConfirmed>() ? wtx->state<TxStateConfirmed>()->confirmed_block_height : 0;
        if (input_id.IsMWEB()) {
            // MW: TODO - Build a mw::UTXO somehow. We probably need to find a way to store leaf_idx in TxStateConfirmed
        } else {
            const COutPoint& outpoint = input_id.ToOutPoint();
            const bool is_pegout = wtx->IsHogEx(); // If the previous tx was a hogex, the coin must have been a pegout
            coins[input_id] = AnyCoin(outpoint, Coin(wtx->tx->vout[outpoint.n], prev_height, wtx->IsCoinBase(), is_pegout));
        }
    }
    std::map<int, bilingual_str> input_errors;
    return SignTransaction(tx, coins, SIGHASH_DEFAULT, input_errors);
}
```


### scriptpubkeyman.cpp


1. `LegacyScriptPubKeyMan::SignTransaction` - Simple passthrough to `::SignTransaction()`:
```cpp
bool LegacyScriptPubKeyMan::SignTransaction(CMutableTransaction& tx, const std::map<AnyOutputID, AnyCoin>& coins, int sighash, std::map<int, bilingual_str>& input_errors) const
{
    return ::SignTransaction(tx, this, coins, sighash, input_errors);
}
```


2. `DescriptorScriptPubKeyMan::SignTransaction` - Loads signing providers, merges keys, then calls `::SignTransaction()`:
```cpp
bool DescriptorScriptPubKeyMan::SignTransaction(CMutableTransaction& tx, const std::map<AnyOutputID, AnyCoin>& coins, int sighash, std::map<int, bilingual_str>& input_errors) const
{
    std::unique_ptr<FlatSigningProvider> keys = std::make_unique<FlatSigningProvider>();
    for (const auto& coin_pair : coins) {
        if (coin_pair.second.IsMWEB()) {
            // MW: TODO - Descriptors - Get signing provider
            continue;
        }
        std::unique_ptr<FlatSigningProvider> coin_keys = GetSigningProvider(coin_pair.second.ToLTC().out.scriptPubKey, true);
        if (!coin_keys) {
            continue;
        }
        keys->Merge(std::move(*coin_keys));
    }

    return ::SignTransaction(tx, keys.get(), coins, sighash, input_errors);
}
```


### sign.cpp

This holds the actual function that calls into `ProduceSignature`. Main 2 consumers are `LegacyScriptPubKeyMan::SignTransaction()` and `DescriptorScriptPubKeyMan::SignTransaction()`.

Logic:
1. Initialize PrecomputedTransactionData using the spent outputs (CTxOut's) provided in the coins map
2. Build signature for each input
3. Verify scripts/signatures

```cpp
bool SignTransaction(CMutableTransaction& mtx, const SigningProvider* keystore, const std::map<AnyOutputID, AnyCoin>& coins, int nHashType, std::map<int, bilingual_str>& input_errors)
{
    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mtx);

    PrecomputedTransactionData txdata;
    std::vector<CTxOut> spent_outputs;
    for (const CTxIn& txin : mtx.vin) {
        auto coin = coins.find(txin.prevout);
        if (coin == coins.end() || coin->second.IsSpent()) {
            txdata.Init(txConst, /*spent_outputs=*/{}, /*force=*/true);
            break;
        } else {
            spent_outputs.emplace_back(coin->second.ToLTC().out);
        }
    }
    if (spent_outputs.size() == mtx.vin.size()) {
        txdata.Init(txConst, std::move(spent_outputs), true);
    }

    // Sign what we can:
    for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
        CTxIn& txin = mtx.vin[i];
        auto coin = coins.find(txin.prevout);
        if (coin == coins.end() || coin->second.IsSpent()) {
            input_errors[i] = _("Input not found or already spent");
            continue;
        }
        const CTxOut& txout = coin->second.ToLTC().out;
        const CScript& prevPubKey = txout.scriptPubKey;
        const CAmount& amount = txout.nValue;

        SignatureData sigdata = DataFromTransaction(mtx, i, txout);
        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mtx.vout.size())) {
            ProduceSignature(*keystore, MutableTransactionSignatureCreator(mtx, i, amount, &txdata, nHashType), prevPubKey, sigdata);
        }

        UpdateInput(txin, sigdata);

        // amount must be specified for valid segwit signature
        if (amount == MAX_MONEY && !txin.scriptWitness.IsNull()) {
            input_errors[i] = _("Missing amount");
            continue;
        }

        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyScript(txin.scriptSig, prevPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, i, amount, txdata, MissingDataBehavior::FAIL), &serror)) {
            if (serror == SCRIPT_ERR_INVALID_STACK_OPERATION) {
                // Unable to sign input and verification failed (possible attempt to partially sign).
                input_errors[i] = Untranslated("Unable to sign input, invalid stack size (possibly missing key)");
            } else if (serror == SCRIPT_ERR_SIG_NULLFAIL) {
                // Verification failed (possibly due to insufficient signatures).
                input_errors[i] = Untranslated("CHECK(MULTI)SIG failing with non-zero signature (possibly need more signatures)");
            } else {
                input_errors[i] = Untranslated(ScriptErrorString(serror));
            }
        } else {
            // If this input succeeds, make sure there is no error set for it
            input_errors.erase(i);
        }
    }
    return input_errors.empty();
}
```
