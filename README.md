Proof of Work
Litecoin uses Scrypt Proof of Work (PoW), with parameters N=1024, r=1 and p=1. The salt is the same 80 bytes as the input. The output is 256bits (32 bytes). The scrypt implementation in C++ used by Litecoin Core is adapted from Colin Perseval's Tarsnap, and can be found in src/crypto/scrypt.cpp.

Scrypt during mining
$ litecoind getwork
{
    "midstate" : "40fd268321efcf60e625707d4e31f9deadd13157e228985de8a10a057b98ed4d",
    "data" : "0000000105e9a54b7f65b46864bc90f55d67cccd8b6404a02f5e064a6df69282adf6e2e5f7f953b0632b25b099858b717bb7b24084148cfa841a89f106bc6b655b18d2ed4ebb191a1d018ea700000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000",
    "hash1" : "00000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000010000",
    "target" : "0000000000000000000000000000000000000000000000000000a78e01000000"
}


The data field is stored in big-endian format. We need to cover that to little-endian for each of the fields in the data because we can pass it to the hashing function.

Data is broken down to:

Version - 00000001 (4 bytes) Previous hash - 05e9a54b7f65b46864bc90f55d67cccd8b6404a02f5e064a6df69282adf6e2e5 (32 bytes) Merkle root - f7f953b0632b25b099858b717bb7b24084148cfa841a89f106bc6b655b18d2ed (32 bytes) Timestamp - 4ebb191a (4 bytes) Bits (target in compact form) - 1d018ea7 (4 bytes) Nonce - 00000000 (4 bytes)
01000000 Previous hash becomes e5e2f6.....a5e905 Merkle root becomes edd218...53f9f7 Timestamp becomes 1a19bb4e Bits becomes a78e011d And Nonce is a 32-bit integer you choose that will make the scrypt hash be less than the target.

Remember that you will need to convert the 32-bit nonce to hex and little-endian also. So if you are trying the nonce 2504433986. The hex version is 9546a142 in big-endian and 42a14695 in little-endian.

You then concatenate these little-endian hex strings together to get the header string (80 bytes) you input into scrypt
$ ./dbdump.py --datadir=/home/mining/.litecoin/ --block 29255
Block height: 29255
BLOCK adf6e2e56df692822f5e064a8b6404a05d67cccd64bc90f57f65b46805e9a54b
Next block: 0000000000000000000000000000000000000000000000000000000000000000
Time: Wed Nov  9 16:15:52 2011 Nonce: 3562614017
nBits: 0x0x1d018ea7
hashMerkleRoot: 0x066b2a758399d5f19b5c6073d09b500d925982adc4b3edd352efe14667a8ca9f
Previous block: 279f6330ccbbb9103b9e3a5350765052081ddbae898f1ef6b8c64f3bcef715f6
1 transactions:
1 tx in, 1 out
TxIn: COIN GENERATED coinbase:04b217bb4e022309
TxOut: value: 50.000000 pubkey: 1HXG8MWvUFNU3pLpQUJueSC4kHcrNepuwC Script: 65:0448...b8cd CHECKSIG

Raw block header: 01000000f615f7ce3b4fc6b8f61e8f89aedb1d0852507650533a9e3b10b9bbcc30639f279fcaa86746e1ef52d3edb3c4ad8259920d509bd073605c9bf1d59983752a6b06b817bb4ea78e011d012d59d4
This python script be used to get a block hash, which matches the expect hash of block #29255

import hashlib
import ltc_scrypt

header_hex = "01000000f615f7ce3b4fc6b8f61e8f89aedb1d0852507650533a9e3b10b9bbcc30639f279fcaa86746e1ef52d3edb3c4ad8259920d509bd073605c9bf1d59983752a6b06b817bb4ea78e011d012d59d4"
header_bin = header_hex.decode('hex')

# sha256d hash
hash = hashlib.sha256(hashlib.sha256(header_bin).digest()).digest()
hash.encode('hex_codec')
hash[::-1].encode('hex_codec')    # convert from big-endian to little-endian
# hash = adf6e2e56df692822f5e064a8b6404a05d67cccd64bc90f57f65b46805e9a54b

# scrypt hash
scrypt = ltc_scrypt.getPoWHash(header_bin)
scrypt.encode('hex_codec')
scrypt[::-1].encode('hex_codec')    # convert from big-endian to little-endian
# scrypt hash = 0000000110c8357966576df46f3b802ca897
