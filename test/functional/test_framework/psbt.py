#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import base64
import struct

from io import BytesIO

from .messages import (
    CTransaction,
    deser_compact_size,
    deser_string,
    from_binary,
    ser_compact_size,
)


# global types
PSBT_GLOBAL_UNSIGNED_TX = 0x00
PSBT_GLOBAL_XPUB = 0x01
PSBT_GLOBAL_TX_VERSION = 0x02
PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03
PSBT_GLOBAL_INPUT_COUNT = 0x04
PSBT_GLOBAL_OUTPUT_COUNT = 0x05
PSBT_GLOBAL_TX_MODIFIABLE = 0x06
PSBT_GLOBAL_MWEB_TX_OFFSET = 0x90
PSBT_GLOBAL_MWEB_TX_STEALTH_OFFSET = 0x91
PSBT_GLOBAL_MWEB_KERNEL_COUNT = 0x92
PSBT_GLOBAL_VERSION = 0xfb
PSBT_GLOBAL_PROPRIETARY = 0xfc

# per-input types
PSBT_IN_NON_WITNESS_UTXO = 0x00
PSBT_IN_WITNESS_UTXO = 0x01
PSBT_IN_PARTIAL_SIG = 0x02
PSBT_IN_SIGHASH_TYPE = 0x03
PSBT_IN_REDEEM_SCRIPT = 0x04
PSBT_IN_WITNESS_SCRIPT = 0x05
PSBT_IN_BIP32_DERIVATION = 0x06
PSBT_IN_FINAL_SCRIPTSIG = 0x07
PSBT_IN_FINAL_SCRIPTWITNESS = 0x08
PSBT_IN_POR_COMMITMENT = 0x09
PSBT_IN_RIPEMD160 = 0x0a
PSBT_IN_SHA256 = 0x0b
PSBT_IN_HASH160 = 0x0c
PSBT_IN_HASH256 = 0x0d
PSBT_IN_PREVIOUS_TXID = 0x0e
PSBT_IN_OUTPUT_INDEX = 0x0f
PSBT_IN_SEQUENCE = 0x10
PSBT_IN_REQUIRED_TIME_LOCKTIME = 0x11
PSBT_IN_REQUIRED_HEIGHT_LOCKTIME = 0x12
PSBT_IN_TAP_KEY_SIG = 0x13
PSBT_IN_TAP_SCRIPT_SIG = 0x14
PSBT_IN_TAP_LEAF_SCRIPT = 0x15
PSBT_IN_TAP_BIP32_DERIVATION = 0x16
PSBT_IN_TAP_INTERNAL_KEY = 0x17
PSBT_IN_TAP_MERKLE_ROOT = 0x18
PSBT_IN_MWEB_OUTPUT_ID = 0x90
PSBT_IN_MWEB_COMMIT = 0x91
PSBT_IN_MWEB_OUTPUT_PUBKEY = 0x92
PSBT_IN_MWEB_INPUT_PUBKEY = 0x93
PSBT_IN_MWEB_FEATURES = 0x94
PSBT_IN_MWEB_INPUT_SIG = 0x95
PSBT_IN_MWEB_ADDR_DESCRIPTOR = 0x96
PSBT_IN_MWEB_AMOUNT = 0x97
PSBT_IN_MWEB_SHARED_SECRET = 0x98
PSBT_IN_MWEB_KEY_EXCHANGE_PK = 0x99
PSBT_IN_MWEB_EXTRA_DATA = 0x9C
PSBT_IN_PROPRIETARY = 0xfc

# per-output types
PSBT_OUT_REDEEM_SCRIPT = 0x00
PSBT_OUT_WITNESS_SCRIPT = 0x01
PSBT_OUT_BIP32_DERIVATION = 0x02
PSBT_OUT_AMOUNT = 0x03
PSBT_OUT_SCRIPT = 0x04
PSBT_OUT_TAP_INTERNAL_KEY = 0x05
PSBT_OUT_TAP_TREE = 0x06
PSBT_OUT_TAP_BIP32_DERIVATION = 0x07
PSBT_OUT_MWEB_STEALTH_ADDRESS = 0x90
PSBT_OUT_MWEB_COMMIT = 0x91
PSBT_OUT_MWEB_FEATURES = 0x92
PSBT_OUT_MWEB_SENDER_PUBKEY = 0x93
PSBT_OUT_MWEB_OUTPUT_PUBKEY = 0x94
PSBT_OUT_MWEB_STANDARD_FIELDS = 0x95
PSBT_OUT_MWEB_RANGEPROOF = 0x96
PSBT_OUT_MWEB_SIG = 0x97
PSBT_OUT_MWEB_EXTRA_DATA = 0x98
PSBT_OUT_PROPRIETARY = 0xfc

# per-kernel types
PSBT_KERN_EXCESS_COMMIT = 0x00
PSBT_KERN_STEALTH_COMMIT = 0x01
PSBT_KERN_FEE = 0x02
PSBT_KERN_PEGIN_AMOUNT = 0x03
PSBT_KERN_PEGOUT = 0x04
PSBT_KERN_LOCK_HEIGHT = 0x05
PSBT_KERN_FEATURES = 0x06
PSBT_KERN_EXTRA_DATA = 0x07
PSBT_KERN_SIG = 0x08
PSBT_KERN_PROPRIETARY = 0xfc


class PSBTMap:
    """Class for serializing and deserializing PSBT maps"""

    def __init__(self, map=None):
        self.map = map if map is not None else {}

    def deserialize(self, f):
        m = {}
        while True:
            k = deser_string(f)
            if len(k) == 0:
                break
            v = deser_string(f)
            if len(k) == 1:
                k = k[0]
            assert k not in m
            m[k] = v
        self.map = m

    def serialize(self):
        m = b""
        for k,v in self.map.items():
            if isinstance(k, int) and 0 <= k and k <= 255:
                k = bytes([k])
            m += ser_compact_size(len(k)) + k
            m += ser_compact_size(len(v)) + v
        m += b"\x00"
        return m

class PSBT:
    """Class for serializing and deserializing PSBTs"""

    def __init__(self, *, g=None, i=None, o=None, k=None):
        self.g = g if g is not None else PSBTMap()
        self.i = i if i is not None else []
        self.o = o if o is not None else []
        self.k = k if k is not None else []
        self.tx = None
        self.in_count = len(i) if i is not None else None
        self.out_count = len(o) if o is not None else None
        self.kernel_count = len(k) if k is not None else None
        self.version = None

    def deserialize(self, f):
        assert f.read(5) == b"psbt\xff"
        self.g = from_binary(PSBTMap, f)

        self.version = 0
        if PSBT_GLOBAL_VERSION in self.g.map:
            assert PSBT_GLOBAL_INPUT_COUNT in self.g.map
            assert PSBT_GLOBAL_OUTPUT_COUNT in self.g.map
            self.version = struct.unpack("<I", self.g.map[PSBT_GLOBAL_VERSION])[0]
            assert self.version in [0, 2]
        if self.version == 2:
            self.in_count = deser_compact_size(BytesIO(self.g.map[PSBT_GLOBAL_INPUT_COUNT]))
            self.out_count = deser_compact_size(BytesIO(self.g.map[PSBT_GLOBAL_OUTPUT_COUNT]))
            self.kernel_count = 0
            if PSBT_GLOBAL_MWEB_KERNEL_COUNT in self.g.map:
                self.kernel_count = deser_compact_size(BytesIO(self.g.map[PSBT_GLOBAL_MWEB_KERNEL_COUNT]))
        else:
            assert PSBT_GLOBAL_UNSIGNED_TX in self.g.map
            self.tx = from_binary(CTransaction, self.g.map[PSBT_GLOBAL_UNSIGNED_TX])
            self.in_count = len(self.tx.vin)
            self.out_count = len(self.tx.vout)
            self.kernel_count = 0

        self.i = [from_binary(PSBTMap, f) for _ in range(self.in_count)]
        self.o = [from_binary(PSBTMap, f) for _ in range(self.out_count)]
        self.k = [from_binary(PSBTMap, f) for _ in range(self.kernel_count)]
        return self

    def serialize(self):
        assert isinstance(self.g, PSBTMap)
        assert isinstance(self.i, list) and all(isinstance(x, PSBTMap) for x in self.i)
        assert isinstance(self.o, list) and all(isinstance(x, PSBTMap) for x in self.o)
        assert isinstance(self.k, list) and all(isinstance(x, PSBTMap) for x in self.k)
        if self.version is not None and self.version == 2:
            self.g.map[PSBT_GLOBAL_INPUT_COUNT] = ser_compact_size(len(self.i))
            self.g.map[PSBT_GLOBAL_OUTPUT_COUNT] = ser_compact_size(len(self.o))
            if self.k:
                self.g.map[PSBT_GLOBAL_MWEB_KERNEL_COUNT] = ser_compact_size(len(self.k))
            elif PSBT_GLOBAL_MWEB_KERNEL_COUNT in self.g.map:
                del self.g.map[PSBT_GLOBAL_MWEB_KERNEL_COUNT]

        psbt = [x.serialize() for x in [self.g] + self.i + self.o + self.k]
        return b"psbt\xff" + b"".join(psbt)

    def make_blank(self):
        """
        Remove all fields except for required fields depending on version
        """
        if self.version == 0:
            for m in self.i + self.o:
                m.map.clear()

            self.g = PSBTMap(map={PSBT_GLOBAL_UNSIGNED_TX: self.g.map[PSBT_GLOBAL_UNSIGNED_TX]})
        elif self.version == 2:
            new_g = {
                PSBT_GLOBAL_TX_VERSION: self.g.map[PSBT_GLOBAL_TX_VERSION],
                PSBT_GLOBAL_INPUT_COUNT: self.g.map[PSBT_GLOBAL_INPUT_COUNT],
                PSBT_GLOBAL_OUTPUT_COUNT: self.g.map[PSBT_GLOBAL_OUTPUT_COUNT],
                PSBT_GLOBAL_VERSION: self.g.map[PSBT_GLOBAL_VERSION],
            }
            if PSBT_GLOBAL_MWEB_KERNEL_COUNT in self.g.map:
                new_g[PSBT_GLOBAL_MWEB_KERNEL_COUNT] = self.g.map[PSBT_GLOBAL_MWEB_KERNEL_COUNT]
            self.g = PSBTMap(map=new_g)

            new_i = []
            for m in self.i:
                new_i.append(PSBTMap(map={
                    PSBT_IN_PREVIOUS_TXID: m.map[PSBT_IN_PREVIOUS_TXID],
                    PSBT_IN_OUTPUT_INDEX: m.map[PSBT_IN_OUTPUT_INDEX],
                }))
            self.i = new_i

            new_o = []
            for m in self.o:
                new_o.append(PSBTMap(map={
                    PSBT_OUT_SCRIPT: m.map[PSBT_OUT_SCRIPT],
                    PSBT_OUT_AMOUNT: m.map[PSBT_OUT_AMOUNT],
                }))
            self.o = new_o
            self.k = [PSBTMap() for _ in self.k]
        else:
            assert False

    def to_base64(self):
        return base64.b64encode(self.serialize()).decode("utf8")

    @classmethod
    def from_base64(cls, b64psbt):
        return from_binary(cls, base64.b64decode(b64psbt))
