#include <catch.hpp>

#include <mw/crypto/Crypto.h>
#include <mw/crypto/Random.h>

TEST_CASE("Crypto::AddCommitment")
{
    // Test adding blinded commitment with transparent one
    {
        BlindingFactor blind_a = Random::CSPRNG<32>().GetBigInt();

        Commitment commit_a = Crypto::CommitBlinded(3, blind_a);
        Commitment commit_b = Crypto::CommitTransparent(2);

        Commitment sum = Crypto::AddCommitments(
            std::vector<Commitment>({ commit_a, commit_b }),
            std::vector<Commitment>()
        );
        Commitment expected = Crypto::CommitBlinded(5, blind_a);

        REQUIRE(sum == expected);
    }

    // Test adding 2 blinded commitments
    {
        BlindingFactor blind_a = Random::CSPRNG<32>().GetBigInt();
        BlindingFactor blind_b = Random::CSPRNG<32>().GetBigInt();

        Commitment commit_a = Crypto::CommitBlinded(3, blind_a);
        Commitment commit_b = Crypto::CommitBlinded(2, blind_b);
        Commitment sum = Crypto::AddCommitments(
            std::vector<Commitment>({ commit_a, commit_b }),
            std::vector<Commitment>()
        );

        BlindingFactor blind_c = Crypto::AddBlindingFactors({ blind_a, blind_b });
        Commitment commit_c = Crypto::CommitBlinded(5, blind_c);
        REQUIRE(commit_c == sum);
    }

    // Test adding negative blinded commitment
    {
        BlindingFactor blind_a = Random::CSPRNG<32>().GetBigInt();
        BlindingFactor blind_b = Random::CSPRNG<32>().GetBigInt();

        Commitment commit_a = Crypto::CommitBlinded(3, blind_a);
        Commitment commit_b = Crypto::CommitBlinded(2, blind_b);
        Commitment difference = Crypto::AddCommitments(
            std::vector<Commitment>({ commit_a }),
            std::vector<Commitment>({ commit_b })
        );

        BlindingFactor blind_c = Crypto::AddBlindingFactors({ blind_a }, { blind_b });
        Commitment commit_c = Crypto::CommitBlinded(1, blind_c);
        REQUIRE(commit_c == difference);
    }
}