Send flows that do commit:
1. SendMoney (sendtoaddress/sendmany) calls CommitTransaction after CreateTransaction in spend.cpp (line 150) and spend.cpp (line 170), and CommitTransaction is where wallet broadcast happens when enabled in wallet.cpp (line 2540) and wallet.cpp (line 2571).
2. send/sendall only commit when add_to_wallet=true (and not returning PSBT); otherwise they return hex/PSBT and skip commit in spend.cpp (line 80) and spend.cpp (line 117).

Funding workflows don’t commit:
1. TransactionDraft::FundTransaction uses CreateTransaction but never calls CommitTransaction in transactiondraft.cpp (line 178) (used by fundrawtransaction/walletcreatefundedpsbt).
1. The wallet interface exposes a create/commit split: interfaces::createTransaction returns a tx without committing in interfaces.cpp (line 337), and interfaces::commitTransaction is a separate call in interfaces.cpp (line 360).


Here are the non-test consumers/workflows that reach CreateTransaction (only four direct call sites):
1. Wallet interface path: `interfaces::Wallet::createTransaction` calls it directly for GUI/other interface consumers in interfaces.cpp (line 337).
2. sendtoaddress/sendmany: `SendMoney` calls it directly in spend.cpp (line 165), invoked by `sendtoaddress` (spend.cpp (line 218)) and `sendmany` (spend.cpp (line 320)).
3. fund/send/sendall/PSBT funder: `TransactionDraft::FundTransaction` calls it in transactiondraft.cpp (line 178), used by `fundrawtransaction` (spend.cpp (line 730)), send (spend.cpp (line 1111)), `sendall` (spend.cpp (line 1233)), and `walletcreatefundedpsbt` (spend.cpp (line 1561)).
4. Fee bumping: feebumper::CreateRateBumpTransaction calls it in feebumper.cpp (line 294), used by bumpfee/psbtbumpfee (spend.cpp (line 1108)) and the wallet interface bump flow (interfaces.cpp (line 379)).