#pragma once

#include <mw/models/tx/UTXO.h>
#include <mw/interfaces/db_interface.h>
#include <unordered_map>

// Forward Declarations
class Database;

class CoinDB
{
public:
	using UPtr = std::unique_ptr<CoinDB>;

	CoinDB(mw::DBWrapper* pDBWrapper, mw::DBBatch* pBatch = nullptr);
	~CoinDB();

	//
	// Retrieve UTXOs with matching output IDs.
	// If there are multiple UTXOs for an output ID, the most recent will be returned.
	//
	std::unordered_map<mw::Hash, mw::UTXO::CPtr> GetUTXOs(
		const std::vector<mw::Hash>& output_ids
	) const;

	//
	// Add the UTXOs
	//
	void AddUTXOs(const std::vector<mw::UTXO::CPtr>& utxos);

	//
	// Removes the UTXOs for the given output IDs.
	// If there are multiple UTXOs for an output ID, the most recent will be removed.
	// DatabaseException thrown if no UTXOs are found for an output ID.
	//
    void RemoveUTXOs(const std::vector<mw::Hash>& output_ids);

private:
	std::unique_ptr<Database> m_pDatabase;
};
