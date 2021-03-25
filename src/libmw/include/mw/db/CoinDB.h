#pragma once

#include <mw/models/crypto/Commitment.h>
#include <mw/models/tx/UTXO.h>
#include <libmw/interfaces/db_interface.h>
#include <unordered_map>

// Forward Declarations
class Database;

class CoinDB
{
public:
	using UPtr = std::unique_ptr<CoinDB>;

	CoinDB(libmw::IDBWrapper* pDBWrapper, libmw::IDBBatch* pBatch = nullptr);
	~CoinDB();

	//
	// Retrieve UTXOs for the given commitments.
	// If there are multiple UTXOs for a commitment, the most recent will be returned.
	//
	std::unordered_map<Commitment, UTXO::CPtr> GetUTXOs(
		const std::vector<Commitment>& commitments
	) const;

	//
	// Add the UTXOs
	//
	void AddUTXOs(const std::vector<UTXO::CPtr>& utxos);

	//
	// Removes the UTXOs for the given commitments.
	// If there are multiple UTXOs for a commitment, the most recent will be removed.
	// DatabaseException thrown if no UTXOs are found fo a commitment.
	//
	void RemoveUTXOs(const std::vector<Commitment>& commitment);

	//
	// Removes all of the UTXOs from the database.
	// This is useful when resyncing the chain.
	//
	void RemoveAllUTXOs();

private:
	std::unique_ptr<Database> m_pDatabase;
};