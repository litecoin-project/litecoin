#pragma once

#include <dbwrapper.h>
#include <mw/models/tx/Coin.h>
#include <unordered_map>

// Forward Declarations
class Database;

class CoinDB
{
public:
	using UPtr = std::unique_ptr<CoinDB>;

	CoinDB(CDBWrapper* pDBWrapper, CDBBatch* pBatch = nullptr);
	~CoinDB();

	//
	// Retrieve coins with matching output IDs.
	// If there are multiple coins for an output ID, the most recent will be returned.
	//
	std::unordered_map<mw::Hash, mw::Coin::CPtr> GetCoins(
		const std::vector<mw::Hash>& output_ids
	) const;

	//
	// Add the coins.
	//
	void AddCoins(const std::vector<mw::Coin::CPtr>& coins);

	//
	// Removes the coins for the given output IDs.
	// If there are multiple coins for an output ID, the most recent will be removed.
	// DatabaseException thrown if no coins are found for an output ID.
	//
    void RemoveCoins(const std::vector<mw::Hash>& output_ids);

private:
	std::unique_ptr<Database> m_pDatabase;
};
