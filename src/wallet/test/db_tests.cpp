// Copyright (c) 2018-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <fs.h>
#include <test/util/setup_common.h>
#include <util/translation.h>
#include <wallet/bdb.h>

#include <fstream>
#include <memory>
#include <string>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(db_tests, BasicTestingSetup)

static std::shared_ptr<BerkeleyEnvironment> GetWalletEnv(const fs::path& path, fs::path& database_filename)
{
    fs::path data_file = BDBDataFile(path);
    database_filename = data_file.filename();
    return GetBerkeleyEnv(data_file.parent_path(), false);
}

BOOST_AUTO_TEST_CASE(getwalletenv_file)
{
    fs::path test_name = "test_name.dat";
    const fs::path datadir = m_args.GetDataDirNet();
    fs::path file_path = datadir / test_name;
    std::ofstream f{file_path};
    f.close();

    fs::path filename;
    std::shared_ptr<BerkeleyEnvironment> env = GetWalletEnv(file_path, filename);
    BOOST_CHECK_EQUAL(filename, test_name);
    BOOST_CHECK_EQUAL(env->Directory(), datadir);
}

BOOST_AUTO_TEST_CASE(getwalletenv_directory)
{
    fs::path expected_name = "wallet.dat";
    const fs::path datadir = m_args.GetDataDirNet();

    fs::path filename;
    std::shared_ptr<BerkeleyEnvironment> env = GetWalletEnv(datadir, filename);
    BOOST_CHECK_EQUAL(filename, expected_name);
    BOOST_CHECK_EQUAL(env->Directory(), datadir);
}

BOOST_AUTO_TEST_CASE(getwalletenv_g_dbenvs_multiple)
{
    fs::path datadir = m_args.GetDataDirNet() / "1";
    fs::path datadir_2 = m_args.GetDataDirNet() / "2";
    fs::path filename;

    std::shared_ptr<BerkeleyEnvironment> env_1 = GetWalletEnv(datadir, filename);
    std::shared_ptr<BerkeleyEnvironment> env_2 = GetWalletEnv(datadir, filename);
    std::shared_ptr<BerkeleyEnvironment> env_3 = GetWalletEnv(datadir_2, filename);

    BOOST_CHECK(env_1 == env_2);
    BOOST_CHECK(env_2 != env_3);
}

BOOST_AUTO_TEST_CASE(getwalletenv_g_dbenvs_free_instance)
{
    fs::path datadir = gArgs.GetDataDirNet() / "1";
    fs::path datadir_2 = gArgs.GetDataDirNet() / "2";
    fs::path filename;

    std::shared_ptr <BerkeleyEnvironment> env_1_a = GetWalletEnv(datadir, filename);
    std::shared_ptr <BerkeleyEnvironment> env_2_a = GetWalletEnv(datadir_2, filename);
    env_1_a.reset();

    std::shared_ptr<BerkeleyEnvironment> env_1_b = GetWalletEnv(datadir, filename);
    std::shared_ptr<BerkeleyEnvironment> env_2_b = GetWalletEnv(datadir_2, filename);

    BOOST_CHECK(env_1_a != env_1_b);
    BOOST_CHECK(env_2_a == env_2_b);
}

BOOST_AUTO_TEST_CASE(rewrite_replaces_database_atomically)
{
    const fs::path wallet_path = m_args.GetDataDirNet() / "rewrite_wallet";
    DatabaseOptions options;
    options.verify = false;
    DatabaseStatus status;
    bilingual_str error;
    std::unique_ptr<BerkeleyDatabase> database = MakeBerkeleyDatabase(wallet_path, options, status, error);
    BOOST_REQUIRE(database);
    BOOST_REQUIRE(status == DatabaseStatus::SUCCESS);

    {
        std::unique_ptr<DatabaseBatch> batch = database->MakeBatch();
        BOOST_REQUIRE(batch->Write(std::string{"keep"}, uint32_t{1}));
        BOOST_REQUIRE(batch->Write(std::string{"skip"}, uint32_t{2}));
    }

    // A failed earlier attempt can leave a partial replacement behind. It
    // must not contribute records when the rewrite is retried.
    {
        Db stale(database->env->dbenv.get(), 0);
        BOOST_REQUIRE_EQUAL(stale.open(nullptr, "wallet.dat.rewrite", "main", DB_BTREE, DB_CREATE, 0), 0);
        CDataStream key(SER_DISK, CLIENT_VERSION);
        CDataStream value(SER_DISK, CLIENT_VERSION);
        key << std::string{"stale"};
        value << uint32_t{3};
        Dbt db_key(key.data(), key.size());
        Dbt db_value(value.data(), value.size());
        BOOST_REQUIRE_EQUAL(stale.put(nullptr, &db_key, &db_value, 0), 0);
        BOOST_REQUIRE_EQUAL(stale.close(0), 0);
    }

    BOOST_REQUIRE(database->Rewrite("\x04skip"));
    database->ReloadDbEnv();

    {
        std::unique_ptr<DatabaseBatch> batch = database->MakeBatch();
        uint32_t value{0};
        BOOST_CHECK(batch->Read(std::string{"keep"}, value));
        BOOST_CHECK_EQUAL(value, 1U);
        BOOST_CHECK(!batch->Read(std::string{"skip"}, value));
        BOOST_CHECK(!batch->Read(std::string{"stale"}, value));
    }
    BOOST_CHECK(!fs::exists(wallet_path / "wallet.dat.rewrite"));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
