pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "@zk-email/circuits/utils/array.circom";
include "@zk-email/circuits/utils/hash.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/lib/base64.circom";
include "ecdsa/ecdsa.circom";

template ES256(
    n,
    k,
    maxMessageLength
) {
    signal input message[maxMessageLength];
    signal input messageLength; 

    signal input sig_r[k];
    signal input sig_s[k];
    signal input pubkey[2][k];

    signal output sha[256];

    // Assert message length fits in ceil(log2(maxMessageLength))
    component n2bMessageLength = Num2Bits(log2Ceil(maxMessageLength));
    n2bMessageLength.in <== messageLength;

    // Assert message data after messageLength are zeros
    AssertZeroPadding(maxMessageLength)(message, messageLength);

    // Calculate SHA256 hash of the message
    sha <== Sha256Bytes(maxMessageLength)(message, messageLength);

      // Need to take message hash mod P, since it is an element of the base field
    var ret[100] = get_p256_prime(n, k);
    var p[k];
    for (var i = 0; i < k; i++) p[i] = ret[i];

    var padded_message_hash[2*k];
    for (var i = 0; i < k; i++) padded_message_hash[i] = sha[i];
    for (var i = k; i < k*2; i++) padded_message_hash[i] = 0;

    component message_hash_modder = bn_BigMod(n, k);
    message_hash_modder.a <== padded_message_hash;
    message_hash_modder.b <== p;

    signal message_hash_mod_p[k] <== message_hash_modder.mod;

    // Verify the signature
    component ecdsa = ECDSAVerifyNoPubkeyCheck(n, k);
    ecdsa.r <== sig_r;
    ecdsa.s <== sig_s;
    ecdsa.msghash <== message_hash_mod_p;
    ecdsa.pubkey <== pubkey;
    
}
