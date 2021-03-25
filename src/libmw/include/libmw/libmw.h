#pragma once

// Copyright (c) 2018-2020 David Burkett
// Copyright (c) 2020 The Litecoin Developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include "defs.h"
#include "node.h"
#include "wallet.h"
#include "miner.h"
#include "interfaces/chain_interface.h"
#include "interfaces/db_interface.h"

#include <memory>
#include <cstdint>

LIBMW_NAMESPACE

MWIMPORT libmw::HeaderRef DeserializeHeader(const std::vector<uint8_t>& bytes);
MWIMPORT std::vector<uint8_t> SerializeHeader(const libmw::HeaderRef& header);

MWIMPORT libmw::BlockRef DeserializeBlock(const std::vector<uint8_t>& bytes);
MWIMPORT std::vector<uint8_t> SerializeBlock(const libmw::BlockRef& block);

MWIMPORT libmw::BlockUndoRef DeserializeBlockUndo(const std::vector<uint8_t>& bytes);
MWIMPORT std::vector<uint8_t> SerializeBlockUndo(const libmw::BlockUndoRef& blockUndo);

MWIMPORT libmw::TxRef DeserializeTx(const std::vector<uint8_t>& bytes);
MWIMPORT std::vector<uint8_t> SerializeTx(const libmw::TxRef& tx);

MWIMPORT libmw::StateRef DeserializeState(const std::vector<uint8_t>& bytes);
MWIMPORT std::vector<uint8_t> SerializeState(const libmw::StateRef& state);

MWIMPORT libmw::Coin DeserializeCoin(const std::vector<uint8_t>& bytes);
MWIMPORT std::vector<uint8_t> SerializeCoin(const libmw::Coin& coin);

END_NAMESPACE // libmw