# Stealth Addresses

Transacting on the MWEB happens via stealth addresses. Stealth addresses are supported using the *Dual-Key Stealth Address Protocol (DKSAP)*.
These addresses consist of 2 secp256k1 public keys <code>(A<sub>i</sub>, B<sub>i</sub>)</code> which are derived from 2 master keypairs <code>(a, A)</code> and <code>(b, B)</code>,
and which can be used repeatedly to generate new outputs that are unlinkable by those without knowledge of the master keys.

### Notation
* <code>G</code>, <code>H</code>, and <code>J</code> are curve generator points
* Uppercase letter in code font (<code>A</code>, <code>A<sub>i</sub></code>, etc.) represents a secp256k1 public key
* Lowercase letter in code font (<code>a</code>, <code>a<sub>i</sub></code>, etc.) represents a scalar
* A letter in single quotes (<code>'K'</code>) represents the ASCII value of the character literal
* <code>HASH32(x||y||z)</code> represents the standard 32-byte `BLAKE3` hash of the conjoined serializations of `x`, `y`, and `z`
    * <code>HASH32(...)</code> outputs are interpreted as scalars modulo the curve order
* <code>COMMIT(v,x) = v⋅H + x⋅G</code> represents the pedersen commitment generated with value <code>v</code> and blinding factor <code>x</code>.
* <code>BLIND_SWITCH(v,r) = r + HASH32(r⋅G + v⋅H || r⋅J)</code> represents the blinding factor for a value <code>v</code> and randomness <code>r</code>.
* <code>x[y,z]</code> suffix represents the byte range from <code>y</code> to <code>z</code> (inclusive, zero-based indices) of the input <code>x</code>

### Address Generation

Unique stealth addresses should be generated deterministically from a master scan keypair <code>(a, A)</code> and master spend keypair <code>(b, B)</code> using the following process:

1. Choose the lowest unused address index <code>i</code>
2. Calculate one-time spend keypair <code>(b<sub>i</sub>, B<sub>i</sub>)</code> as:<br/>
    <code>b<sub>i</sub> = b + HASH32(A||i||a)</code><br/>
    <code>B<sub>i</sub> = b<sub>i</sub>⋅G</code>
3. Calculate one-time scan keypair <code>(a<sub>i</sub>, A<sub>i</sub>)</code> as:<br/>
    <code>a<sub>i</sub> = a⋅b<sub>i</sub></code><br/>
    <code>A<sub>i</sub> = a<sub>i</sub>⋅G</code>

### Outputs

Outputs consist of the following data:

* <code>C<sub>o</sub></code> - The pedersen commitment to the value.
* Output message, <code>m</code>, consisting of:
  * <code>K<sub>o</sub></code> - The receiver's one-time public key.
  * <code>K<sub>e</sub></code> - The key exchange public key.
  * <code>K<sub>s</sub></code> - The sender's public key.
  * <code>t</code> - The view tag. This is the first byte of the shared secret.
  * <code>v'</code> - The masked value.
  * <code>n'</code> - The masked nonce.
* A signature of the <code>m</code> using the sender's key <code>k<sub>s</sub></code>.
* A rangeproof of <code>C<sub>o</sub></code> that also commits to the <code>m</code>.

### Output Construction

To create an output for value <code>v</code> to a receiver's stealth address <code>(A<sub>i</sub>,B<sub>i</sub>)</code>:

1. Generate a random sender keypair <code>(k<sub>s</sub>, K<sub>s</sub>)</code>.
2. Derive the nonce <code>n = HASH32('N'||k<sub>s</sub>)[0,15]</code>
3. Derive the sending key <code>s = HASH32('S'||A<sub>i</sub>||B<sub>i</sub>||v||n)</code>
4. Derive the shared secret <code>e = HASH32('D'||s⋅A<sub>i</sub>)</code>. The view tag is <code>t = e[0]</code>.
5. Calculate the receiver's one-time public key <code>K<sub>o</sub> = HASH32('O'||e)⋅B<sub>i</sub></code>
6. Calculate the key exchange pubkey <code>K<sub>e</sub> = s⋅B<sub>i</sub></code>
7. Encrypt the value using <code>v' = v &oplus; HASH32('Y'||e)[0,7]</code>
8. Encrypt the nonce using <code>n' = n &oplus; HASH32('X'||e)[0,15]</code>
9. Calculate the blinding factor <code>x = BLIND_SWITCH(v,HASH32('B'||e))</b></code>
10. Calculate the commitment <code>C<sub>o</sub> = COMMIT(v,x)</code>
11. Generate the rangeproof <code>&pi;</code> for <code>C<sub>o</sub></code>, committing also to the output message <code>m</code>. TODO: Link to 'm' definition and rangeproof spec
12. Sign the message <code>HASH32(C<sub>o</sub>||K<sub>s</sub>||K<sub>o</sub>||HASH32(m)||HASH32(&pi;))</code> using the sender key <code>k<sub>s</sub></code>.


### Output Identification

To check if an output belongs to a wallet:

1. Calculate the ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) shared secret <code>e = HASH32('D'||a⋅K<sub>e</sub>)</code>
2. If the first byte of <code>e</code> does not match the view tag <code>t</code>, the output does not belong to the wallet.
3. Calculate the one-time spend pubkey: <code>B<sub>i</sub> = K<sub>o</sub> - HASH32('O'||e)⋅G</code>
4. Lookup the index <code>i</code> that generates <code>B<sub>i</sub></code> from the wallet's map <code>B<sub>i</sub>->i</code>. If not found, the output does not belong to the wallet.
5. Derive the 64-byte mask <code>m = HASH64(e)</code>
6. Decrypt the value <code>v = v' &oplus; m[32,39]</code>.
7. Verify that <code>SWITCH(v,m[0-31]) =? C<sub>o</sub></code>
8. Decrypt the nonce <code>n = n' &oplus; m[40,55]</code>.
9. Calculate the send key <code>s = HASH32('S'||A<sub>i</sub>||B<sub>i</sub>||v||n)</code>
10. Verify that <code>K<sub>e</sub> =? s⋅B<sub>i</sub></code>.

If all verifications succeed, the output belongs to the wallet, and is safe to use.

#### Spend Key Recovery

The spend key can be recovered by <code>k<sub>o</sub> = HASH32('O'||e) + a<sub>i</sub></code>.

Derivation proof:<br/>
<pre>
<code>k<sub>o</sub> = HASH32('O'||e) + a<sub>i</sub></code>
K<sub>o</sub> = B<sub>i</sub> + HASH32('O'||e)⋅G = (b<sub>i</sub> + HASH32('O'||e))⋅G
a<sub>i</sub> = a⋅b<sub>i</sub> => k<sub>o</sub> = b<sub>i</sub> + HASH32('O'||e) = (a<sup>-1</sup>⋅a<sub>i</sub>) + HASH32('O'||e)
</pre>

### Wallet Implementation Notes

* The wallet must keep a map <code>B<sub>i</sub>->i</code> of all used spend pubkeys and the next several unused ones.
* To be consistent with Litecoin Core, we recommend using the following derivation paths:
  * Master scan key <code>(a, A)</code>: <code>m/0'/100'/0'</code>
  * Master spend key <code>(b, B)</code>: <code>m/0'/100'/1'</code>

