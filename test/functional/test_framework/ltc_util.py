#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Random assortment of utility functions"""

import os
from typing import List, Optional

from test_framework.messages import COIN, COutPoint, CTransaction, CTxIn, CTxOut, Hash, from_hex, MWEBHeader, MWEBTxBody, MWEBInput, MWEBOutput, MWEBKernel, MWEBTransaction
from test_framework.mweb.crypto import BlindingFactor, pedersen_blind_sum
from test_framework.util import get_datadir_path, initialize_datadir, satoshi_round
from test_framework.script_util import DUMMY_P2WPKH_SCRIPT, hogaddr_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode

FIRST_MWEB_HEIGHT = 432

"""Create a txout with a given amount and scriptPubKey

Mines coins as needed.

confirmed - txouts created will be confirmed in the blockchain;
            unconfirmed otherwise.
"""
def make_utxo(test_framework, node, amount, confirmed=True, scriptPubKey=DUMMY_P2WPKH_SCRIPT) -> Optional[COutPoint]:
    fee = 1*COIN
    while node.getbalance() < satoshi_round((amount + fee)/COIN):
        test_framework.generate(node, 100, sync_fun=test_framework.no_op)

    new_addr = node.getnewaddress()
    txid = node.sendtoaddress(new_addr, satoshi_round((amount+fee)/COIN))
    tx1 = node.getrawtransaction(txid, 1)
    txid = int(txid, 16)
    i = None

    for i, txout in enumerate(tx1['vout']):
        if txout['scriptPubKey']['address'] == [new_addr]:
            break
    assert i is not None

    tx2 = CTransaction()
    tx2.vin = [CTxIn(COutPoint(txid, i))]
    tx2.vout = [CTxOut(amount, scriptPubKey)]
    tx2.rehash()

    signed_tx = node.signrawtransactionwithwallet(tx2.serialize().hex())

    txid = node.sendrawtransaction(signed_tx['hex'], 0)

    # If requested, ensure txouts are confirmed.
    if confirmed:
        mempool_size = len(node.getrawmempool())
        while mempool_size > 0:
            test_framework.generate(node, 1, sync_fun=test_framework.no_op)
            new_size = len(node.getrawmempool())
            # Error out if we have something stuck in the mempool, as this
            # would likely be a bug.
            assert new_size < mempool_size
            mempool_size = new_size

    return COutPoint(int(txid, 16), 0)

"""Generates all pre-MWEB blocks, pegs coins into the MWEB,
then mines the first MWEB block which includes that pegin.

mining_node - The node to use to generate blocks
"""
def setup_mweb_chain(mining_node, pegin_amount=1):
    mining_node.generate(FIRST_MWEB_HEIGHT - 1, invalid_call=False)
    mining_node.sendtoaddress(mining_node.getnewaddress(address_type='mweb'), pegin_amount)
    mining_node.generate(1, invalid_call=False)

def get_hogex_tx(node: TestNode, block_hash = None) -> Optional[CTransaction]:
    block_hash = block_hash or node.getbestblockhash()
    best_block = node.getblock(block_hash, 2)
    hogex_tx = from_hex(CTransaction(), best_block['tx'][-1]['hex'])

    if hogex_tx.is_valid() and hogex_tx.hogex:
        return hogex_tx
    else:
        return None

def get_hog_addr_txout(node: TestNode) -> Optional[CTxOut]:
    best_block = node.getblock(node.getbestblockhash(), 2)

    hogex_tx: Optional[CTransaction] = get_hogex_tx(node)
    if hogex_tx is None or len(hogex_tx.vout) == 0:
        return None
    
    return hogex_tx.vout[0]

def get_mweb_header(node: TestNode, block_hash = None) -> Optional[MWEBHeader]:
    block_hash = block_hash or node.getbestblockhash()
    best_block = node.getblock(block_hash, 2)
    if not 'mweb' in best_block:
        return None

    mweb_header = MWEBHeader()
    mweb_header.from_json(best_block['mweb'])
    return mweb_header

def create_hogex(node, mweb_hash, amount=None) -> Optional[CTransaction]:
    hogex_tx: Optional[CTransaction] = get_hogex_tx(node)
    if hogex_tx is None or len(hogex_tx.vout) == 0:
        return None

    if hasattr(mweb_hash, "to_byte_arr"):
        mweb_hash = mweb_hash.to_byte_arr()
    elif isinstance(mweb_hash, str):
        mweb_hash = bytes.fromhex(mweb_hash)

    tx = CTransaction()
    tx.vin.append(CTxIn(COutPoint(int(hogex_tx.rehash(), 16), 0)))
    tx.vout.append(CTxOut(hogex_tx.vout[0].nValue if amount is None else amount, hogaddr_script(mweb_hash)))
    tx.hogex = True
    tx.rehash()
    return tx

""" Create a non-HD wallet from a temporary v15.1.0 node.

Returns the path of the wallet.dat.
"""
def create_non_hd_wallet(chain, options) -> str:    
    version = 150100
    bin_dir = os.path.join(options.previous_releases_path, 'v0.15.1', 'bin')
    initialize_datadir(options.tmpdir, 10, chain)
    data_dir = get_datadir_path(options.tmpdir, 10)

    # adjust conf for pre 17
    conf_file = os.path.join(data_dir, 'litecoin.conf')
    with open(conf_file, 'r', encoding='utf8') as conf:
        conf_data = conf.read()
    with open(conf_file, 'w', encoding='utf8') as conf:
        conf.write(conf_data.replace('[regtest]', ''))

    v15_node = TestNode(
        i=10,
        datadir=data_dir,
        chain=chain,
        rpchost=None,
        timewait=60,
        timeout_factor=1.0,
        litecoind=os.path.join(bin_dir, 'litecoind'),
        litecoin_cli=os.path.join(bin_dir, 'litecoin-cli'),
        version=version,
        coverage_dir=None,
        cwd=options.tmpdir,
        extra_args=["-usehd=0"],
    )
    v15_node.start()
    v15_node.wait_for_cookie_credentials()  # ensure cookie file is available to avoid race condition
    v15_node.wait_for_rpc_connection()
    v15_node.stop_node(wait=0)
    v15_node.wait_until_stopped()
    
    return os.path.join(v15_node.datadir, chain, "wallet.dat")


def mweb_aggregate_txs(txs: List[MWEBTransaction]) -> Optional[MWEBTransaction]:
    if len(txs) == 0:
        return None

    if len(txs) == 1:
        return txs[0]
    
    inputs: List[MWEBInput] = []
    outputs: List[MWEBOutput] = []
    kernels: List[MWEBKernel] = []
    kernel_offsets: List[BlindingFactor] = []
    stealth_offsets: List[BlindingFactor] = []
    
    # Collect all the inputs, outputs, kernels, and owner sigs from the txs
    for tx in txs:
        for input in tx.body.mweb_inputs:
            inputs.append(input)
        #inputs.extend(tx.body.mweb_inputs)
        outputs.extend(tx.body.mweb_outputs)
        kernels.extend(tx.body.mweb_kernels)
        
        kernel_offset = BlindingFactor.from_bytes(tx.kernel_offset.to_byte_arr())
        stealth_offset = BlindingFactor.from_bytes(tx.stealth_offset.to_byte_arr())
        if kernel_offset is None or stealth_offset is None:
            return None

        kernel_offsets.append(kernel_offset)
        stealth_offsets.append(stealth_offset)

    # Sum the offsets up to give us an aggregate offsets for the transaction.
    kernel_offset = Hash.from_byte_arr(pedersen_blind_sum(kernel_offsets).to_bytes())
    stealth_offset = Hash.from_byte_arr(pedersen_blind_sum(stealth_offsets).to_bytes())

    # Build a new aggregate tx
    body = MWEBTxBody.new_sorted(inputs, outputs, kernels)
    tx = MWEBTransaction(kernel_offset=kernel_offset, stealth_offset=stealth_offset, body=body)
    tx.rehash()

    return tx
