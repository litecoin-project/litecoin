#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Minimal litecoin_scrypt replacement for the functional test framework."""

import hashlib


def getPoWHash(header):
    """Return Litecoin's scrypt_1024_1_1_256 proof-of-work hash."""
    if not isinstance(header, (bytes, bytearray, memoryview)):
        raise TypeError("header must be a bytes-like object")

    header = bytes(header)
    if len(header) != 80:
        raise ValueError(f"expected 80-byte block header, got {len(header)}")

    return hashlib.scrypt(header, salt=header, n=1024, r=1, p=1, dklen=32)
