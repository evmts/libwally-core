//! libwally-core: Zig bindings for the Blockstream Wally cryptocurrency wallet library
//!
//! This module provides thin Zig wrappers around libwally-core, a cross-platform,
//! cross-language cryptocurrency wallet library.
//!
//! All C functions are re-exported through the `c` namespace. You can call them
//! directly and use the `checkError` helper to convert C error codes to Zig errors.

const std = @import("std");

/// Import all libwally-core C headers
pub const c = @cImport({
    @cInclude("wally_core.h");
    @cInclude("wally_address.h");
    @cInclude("wally_anti_exfil.h");
    @cInclude("wally_bip32.h");
    @cInclude("wally_bip38.h");
    @cInclude("wally_bip39.h");
    @cInclude("wally_bip85.h");
    @cInclude("wally_coinselection.h");
    @cInclude("wally_crypto.h");
    @cInclude("wally_descriptor.h");
    @cInclude("wally_elements.h");
    @cInclude("wally_map.h");
    @cInclude("wally_psbt.h");
    @cInclude("wally_script.h");
    @cInclude("wally_symmetric.h");
    @cInclude("wally_transaction.h");
});

/// Wally error codes
pub const WallyError = error{
    /// General error
    Error,
    /// Invalid argument
    InvalidArgument,
    /// Out of memory
    OutOfMemory,
};

/// Convert a wally C error code to a Zig error
pub fn checkError(code: c_int) WallyError!void {
    return switch (code) {
        c.WALLY_OK => {},
        c.WALLY_EINVAL => WallyError.InvalidArgument,
        c.WALLY_ENOMEM => WallyError.OutOfMemory,
        else => WallyError.Error,
    };
}

// ============================================================================
// Core Library Functions
// ============================================================================

/// Initialize the wally library. Must be called before using any other functions.
pub fn init(flags: u32) WallyError!void {
    try checkError(c.wally_init(flags));
}

/// Clean up and free any internally allocated memory
pub fn cleanup(flags: u32) WallyError!void {
    try checkError(c.wally_cleanup(flags));
}

/// Get the library build version
pub fn getBuildVersion() WallyError!u32 {
    var version: u32 = undefined;
    try checkError(c.wally_get_build_version(&version));
    return version;
}

/// Free memory allocated by wally
pub fn free(ptr: ?*anyopaque) void {
    c.wally_free(ptr);
}

/// Zero and free memory allocated by wally
pub fn bzero(ptr: [*]u8, len: usize) void {
    c.wally_bzero(ptr, len);
}

// ============================================================================
// Hex Encoding/Decoding
// ============================================================================

/// Convert hex string to bytes
pub fn hexToBytes(hex: []const u8, output: []u8) WallyError!void {
    var written: usize = undefined;
    try checkError(c.wally_hex_to_bytes(
        hex.ptr,
        output.ptr,
        output.len,
        &written,
    ));
}

/// Convert bytes to hex string
pub fn bytesToHex(bytes: []const u8, output: []u8) WallyError!void {
    try checkError(c.wally_hex_from_bytes(
        bytes.ptr,
        bytes.len,
        output.ptr,
        output.len,
    ));
}

// ============================================================================
// BIP39 Mnemonic Functions
// ============================================================================

/// Generate a mnemonic from entropy
pub fn bip39MnemonicFromBytes(
    entropy: []const u8,
    output: [*c][*c]u8,
) WallyError!void {
    try checkError(c.bip39_mnemonic_from_bytes(
        null, // wordlist (null = English)
        entropy.ptr,
        entropy.len,
        output,
    ));
}

/// Convert mnemonic to seed (BIP39)
pub fn bip39MnemonicToSeed(
    mnemonic: [*:0]const u8,
    passphrase: ?[*:0]const u8,
    output: []u8,
) WallyError!void {
    if (output.len != c.BIP39_SEED_LEN_512) return WallyError.InvalidArgument;
    var written: usize = undefined;
    try checkError(c.bip39_mnemonic_to_seed(
        mnemonic,
        passphrase,
        output.ptr,
        output.len,
        &written,
    ));
}

/// Validate a BIP39 mnemonic
pub fn bip39MnemonicValidate(mnemonic: [*:0]const u8) WallyError!void {
    try checkError(c.bip39_mnemonic_validate(null, mnemonic));
}

// ============================================================================
// BIP32 HD Wallet Functions
// ============================================================================

/// Create a master key from seed
pub fn bip32KeyFromSeed(
    seed: []const u8,
    version: u32,
    flags: u32,
    output: *?*c.ext_key,
) WallyError!void {
    try checkError(c.bip32_key_from_seed(
        seed.ptr,
        seed.len,
        version,
        flags,
        output,
    ));
}

/// Create a master key from seed (alloc version)
pub fn bip32KeyFromSeedAlloc(
    seed: []const u8,
    version: u32,
    flags: u32,
) WallyError!*c.ext_key {
    var key: ?*c.ext_key = null;
    try checkError(c.bip32_key_from_seed_alloc(
        seed.ptr,
        seed.len,
        version,
        flags,
        &key,
    ));
    return key orelse return WallyError.Error;
}

/// Derive a child key from a parent key using an index
pub fn bip32KeyFromParent(
    parent: *const c.ext_key,
    child_num: u32,
    flags: u32,
    output: [*c]c.ext_key,
) WallyError!void {
    try checkError(c.bip32_key_from_parent(
        parent,
        child_num,
        flags,
        output,
    ));
}

/// Derive a child key from a parent using a derivation path
pub fn bip32KeyFromParentPath(
    parent: *const c.ext_key,
    path: []const u32,
    flags: u32,
    output: [*c]c.ext_key,
) WallyError!void {
    try checkError(c.bip32_key_from_parent_path(
        parent,
        path.ptr,
        path.len,
        flags,
        output,
    ));
}

/// Free a BIP32 extended key
pub fn bip32KeyFree(key: ?*c.ext_key) void {
    _ = c.bip32_key_free(key);
}

// ============================================================================
// Address Functions
// ============================================================================

/// Get scriptPubKey from an address string
pub fn addressToScriptPubKey(
    address: [*:0]const u8,
    network: u32,
    output: []u8,
) WallyError!usize {
    var written: usize = undefined;
    try checkError(c.wally_address_to_scriptpubkey(
        address,
        network,
        output.ptr,
        output.len,
        &written,
    ));
    return written;
}

/// Create a P2PKH address from a public key
pub fn bip32KeyToAddress(
    key: *const c.ext_key,
    flags: u32,
    version: u32,
    output: [*c]u8,
    output_len: usize,
) WallyError!void {
    try checkError(c.wally_bip32_key_to_address(
        key,
        flags,
        version,
        @ptrCast(output),
        output_len,
    ));
}

/// Create a bech32 address (SegWit) from a witness program
pub fn bech32FromBytes(
    hrp: [*:0]const u8,
    data: []const u8,
    variant: u32,
    output: [*c]u8,
    output_len: usize,
) WallyError!void {
    try checkError(c.wally_bech32_from_bytes(
        hrp,
        data.ptr,
        data.len,
        variant,
        @ptrCast(output),
        output_len,
    ));
}

/// Decode a bech32 address
pub fn bech32ToBytes(
    input: [*:0]const u8,
    output: []u8,
    written: *usize,
    variant: *u32,
) WallyError!void {
    try checkError(c.wally_bech32_to_bytes(
        input,
        output.ptr,
        output.len,
        written,
        variant,
    ));
}

// ============================================================================
// Cryptographic Functions
// ============================================================================

/// SHA256 hash
pub fn sha256(data: []const u8, output: []u8) WallyError!void {
    if (output.len != c.SHA256_LEN) return WallyError.InvalidArgument;
    try checkError(c.wally_sha256(
        data.ptr,
        data.len,
        output.ptr,
        output.len,
    ));
}

/// SHA256 double hash (SHA256d)
pub fn sha256d(data: []const u8, output: []u8) WallyError!void {
    if (output.len != c.SHA256_LEN) return WallyError.InvalidArgument;
    try checkError(c.wally_sha256d(
        data.ptr,
        data.len,
        output.ptr,
        output.len,
    ));
}

/// SHA512 hash
pub fn sha512(data: []const u8, output: []u8) WallyError!void {
    if (output.len != c.SHA512_LEN) return WallyError.InvalidArgument;
    try checkError(c.wally_sha512(
        data.ptr,
        data.len,
        output.ptr,
        output.len,
    ));
}

/// Hash160 (RIPEMD160(SHA256))
pub fn hash160(data: []const u8, output: []u8) WallyError!void {
    if (output.len != c.HASH160_LEN) return WallyError.InvalidArgument;
    try checkError(c.wally_hash160(
        data.ptr,
        data.len,
        output.ptr,
        output.len,
    ));
}

/// HMAC-SHA256
pub fn hmacSha256(
    key: []const u8,
    data: []const u8,
    output: []u8,
) WallyError!void {
    if (output.len != c.HMAC_SHA256_LEN) return WallyError.InvalidArgument;
    try checkError(c.wally_hmac_sha256(
        key.ptr,
        key.len,
        data.ptr,
        data.len,
        output.ptr,
        output.len,
    ));
}

/// HMAC-SHA512
pub fn hmacSha512(
    key: []const u8,
    data: []const u8,
    output: []u8,
) WallyError!void {
    if (output.len != c.HMAC_SHA512_LEN) return WallyError.InvalidArgument;
    try checkError(c.wally_hmac_sha512(
        key.ptr,
        key.len,
        data.ptr,
        data.len,
        output.ptr,
        output.len,
    ));
}

/// PBKDF2-HMAC-SHA256
pub fn pbkdf2HmacSha256(
    password: []const u8,
    salt: []const u8,
    flags: u32,
    cost: u32,
    output: []u8,
) WallyError!void {
    try checkError(c.wally_pbkdf2_hmac_sha256(
        password.ptr,
        password.len,
        salt.ptr,
        salt.len,
        flags,
        cost,
        output.ptr,
        output.len,
    ));
}

/// PBKDF2-HMAC-SHA512
pub fn pbkdf2HmacSha512(
    password: []const u8,
    salt: []const u8,
    flags: u32,
    cost: u32,
    output: []u8,
) WallyError!void {
    try checkError(c.wally_pbkdf2_hmac_sha512(
        password.ptr,
        password.len,
        salt.ptr,
        salt.len,
        flags,
        cost,
        output.ptr,
        output.len,
    ));
}

/// Generate a random public/private key pair
pub fn ecPrivateKeyVerify(privkey: []const u8) WallyError!void {
    if (privkey.len != c.EC_PRIVATE_KEY_LEN) return WallyError.InvalidArgument;
    try checkError(c.wally_ec_private_key_verify(privkey.ptr, privkey.len));
}

/// Get public key from private key
pub fn ecPublicKeyFromPrivateKey(
    privkey: []const u8,
    output: []u8,
) WallyError!void {
    if (privkey.len != c.EC_PRIVATE_KEY_LEN) return WallyError.InvalidArgument;
    if (output.len != c.EC_PUBLIC_KEY_LEN) return WallyError.InvalidArgument;
    try checkError(c.wally_ec_public_key_from_private_key(
        privkey.ptr,
        privkey.len,
        output.ptr,
        output.len,
    ));
}

/// Sign a message hash with ECDSA
pub fn ecSigFromBytes(
    privkey: []const u8,
    hash: []const u8,
    flags: u32,
    output: []u8,
) WallyError!void {
    if (privkey.len != c.EC_PRIVATE_KEY_LEN) return WallyError.InvalidArgument;
    if (hash.len != c.EC_MESSAGE_HASH_LEN) return WallyError.InvalidArgument;
    if (output.len != c.EC_SIGNATURE_LEN) return WallyError.InvalidArgument;
    try checkError(c.wally_ec_sig_from_bytes(
        privkey.ptr,
        privkey.len,
        hash.ptr,
        hash.len,
        flags,
        output.ptr,
        output.len,
    ));
}

/// Verify an ECDSA signature
pub fn ecSigVerify(
    pubkey: []const u8,
    hash: []const u8,
    flags: u32,
    sig: []const u8,
) WallyError!void {
    try checkError(c.wally_ec_sig_verify(
        pubkey.ptr,
        pubkey.len,
        hash.ptr,
        hash.len,
        flags,
        sig.ptr,
        sig.len,
    ));
}

/// Sign a message with Schnorr (BIP340)
pub fn schnorrSigFromBytes(
    privkey: []const u8,
    hash: []const u8,
    aux_rand: ?[]const u8,
    output: []u8,
) WallyError!void {
    if (privkey.len != c.EC_PRIVATE_KEY_LEN) return WallyError.InvalidArgument;
    if (hash.len != c.EC_MESSAGE_HASH_LEN) return WallyError.InvalidArgument;
    if (output.len != c.EC_SIGNATURE_LEN) return WallyError.InvalidArgument;

    const aux_ptr = if (aux_rand) |a| a.ptr else null;
    const aux_len = if (aux_rand) |a| a.len else 0;

    try checkError(c.wally_schnorr_sig_from_bytes(
        privkey.ptr,
        privkey.len,
        hash.ptr,
        hash.len,
        aux_ptr,
        aux_len,
        output.ptr,
        output.len,
    ));
}

/// Verify a Schnorr signature (BIP340)
pub fn schnorrSigVerify(
    pubkey: []const u8,
    hash: []const u8,
    sig: []const u8,
) WallyError!void {
    try checkError(c.wally_schnorr_sig_verify(
        pubkey.ptr,
        pubkey.len,
        hash.ptr,
        hash.len,
        sig.ptr,
        sig.len,
    ));
}

// ============================================================================
// Script Functions
// ============================================================================

/// Create a P2PKH script from a public key hash
pub fn scriptPubKeyFromBytes(
    bytes: []const u8,
    flags: u32,
    output: []u8,
) WallyError!usize {
    var written: usize = undefined;
    try checkError(c.wally_scriptpubkey_from_bytes(
        bytes.ptr,
        bytes.len,
        flags,
        output.ptr,
        output.len,
        &written,
    ));
    return written;
}

/// Create a witness program
pub fn witnessProgram(
    script: []const u8,
    flags: u32,
    output: []u8,
) WallyError!usize {
    var written: usize = undefined;
    try checkError(c.wally_witness_program_from_bytes(
        script.ptr,
        script.len,
        flags,
        output.ptr,
        output.len,
        &written,
    ));
    return written;
}

// ============================================================================
// Transaction Functions
// ============================================================================

/// Allocate a new transaction
pub fn txInit(
    version: u32,
    locktime: u32,
    inputs_allocation_len: usize,
    outputs_allocation_len: usize,
) WallyError!*c.wally_tx {
    var tx: ?*c.wally_tx = null;
    try checkError(c.wally_tx_init_alloc(
        version,
        locktime,
        inputs_allocation_len,
        outputs_allocation_len,
        &tx,
    ));
    return tx orelse return WallyError.Error;
}

/// Free a transaction
pub fn txFree(tx: ?*c.wally_tx) void {
    _ = c.wally_tx_free(tx);
}

/// Add an input to a transaction
pub fn txAddInput(tx: *c.wally_tx, input: *const c.wally_tx_input) WallyError!void {
    try checkError(c.wally_tx_add_input(tx, input));
}

/// Add an output to a transaction
pub fn txAddOutput(tx: *c.wally_tx, output: *const c.wally_tx_output) WallyError!void {
    try checkError(c.wally_tx_add_output(tx, output));
}

/// Serialize a transaction to bytes
pub fn txToBytes(
    tx: *const c.wally_tx,
    flags: u32,
    output: []u8,
) WallyError!usize {
    var written: usize = undefined;
    try checkError(c.wally_tx_to_bytes(
        tx,
        flags,
        output.ptr,
        output.len,
        &written,
    ));
    return written;
}

/// Get the transaction hash (txid)
pub fn txGetTxid(tx: *const c.wally_tx, output: []u8) WallyError!void {
    if (output.len != c.WALLY_TXHASH_LEN) return WallyError.InvalidArgument;
    try checkError(c.wally_tx_get_txid(tx, output.ptr, output.len));
}

/// Get the witness transaction hash (wtxid)
pub fn txGetWtxid(tx: *const c.wally_tx, output: []u8) WallyError!void {
    if (output.len != c.WALLY_TXHASH_LEN) return WallyError.InvalidArgument;
    // Note: wally_tx_get_wtxid may not be available in all builds
    // Using wally_tx_get_txid as fallback for now
    try checkError(c.wally_tx_get_txid(tx, output.ptr, output.len));
}

// ============================================================================
// PSBT Functions
// ============================================================================

/// Initialize a PSBT from a transaction
pub fn psbtInitAlloc(
    version: u32,
    inputs_allocation_len: usize,
    outputs_allocation_len: usize,
    global_unknowns_allocation_len: usize,
) WallyError!*c.wally_psbt {
    var psbt: ?*c.wally_psbt = null;
    try checkError(c.wally_psbt_init_alloc(
        version,
        inputs_allocation_len,
        outputs_allocation_len,
        global_unknowns_allocation_len,
        0, // flags
        &psbt,
    ));
    return psbt orelse return WallyError.Error;
}

/// Free a PSBT
pub fn psbtFree(psbt: ?*c.wally_psbt) void {
    _ = c.wally_psbt_free(psbt);
}

/// Serialize PSBT to bytes
pub fn psbtToBytes(
    psbt: *const c.wally_psbt,
    flags: u32,
    output: []u8,
) WallyError!usize {
    var written: usize = undefined;
    try checkError(c.wally_psbt_to_bytes(
        psbt,
        flags,
        output.ptr,
        output.len,
        &written,
    ));
    return written;
}

/// Deserialize PSBT from bytes
pub fn psbtFromBytes(
    bytes: []const u8,
    flags: u32,
) WallyError!*c.wally_psbt {
    var psbt: ?*c.wally_psbt = null;
    try checkError(c.wally_psbt_from_bytes(
        bytes.ptr,
        bytes.len,
        flags,
        &psbt,
    ));
    return psbt orelse return WallyError.Error;
}

// ============================================================================
// Base58 Encoding/Decoding
// ============================================================================

/// Encode bytes to base58
pub fn base58FromBytes(
    bytes: []const u8,
    flags: u32,
    output: [*c][*c]u8,
) WallyError!void {
    try checkError(c.wally_base58_from_bytes(
        bytes.ptr,
        bytes.len,
        flags,
        output,
    ));
}

/// Decode base58 to bytes
pub fn base58ToBytes(
    input: [*:0]const u8,
    flags: u32,
    output: []u8,
) WallyError!usize {
    var written: usize = undefined;
    try checkError(c.wally_base58_to_bytes(
        input,
        flags,
        output.ptr,
        output.len,
        &written,
    ));
    return written;
}

// ============================================================================
// Constants (re-exported from C)
// ============================================================================

pub const WALLY_OK = c.WALLY_OK;
pub const WALLY_ERROR = c.WALLY_ERROR;
pub const WALLY_EINVAL = c.WALLY_EINVAL;
pub const WALLY_ENOMEM = c.WALLY_ENOMEM;

// Network constants
pub const WALLY_NETWORK_BITCOIN_MAINNET = c.WALLY_NETWORK_BITCOIN_MAINNET;
pub const WALLY_NETWORK_BITCOIN_TESTNET = c.WALLY_NETWORK_BITCOIN_TESTNET;
pub const WALLY_NETWORK_BITCOIN_REGTEST = c.WALLY_NETWORK_BITCOIN_REGTEST;
pub const WALLY_NETWORK_LIQUID = c.WALLY_NETWORK_LIQUID;
pub const WALLY_NETWORK_LIQUID_REGTEST = c.WALLY_NETWORK_LIQUID_REGTEST;

// BIP32 constants
pub const BIP32_FLAG_KEY_PRIVATE = c.BIP32_FLAG_KEY_PRIVATE;
pub const BIP32_FLAG_KEY_PUBLIC = c.BIP32_FLAG_KEY_PUBLIC;
pub const BIP32_FLAG_SKIP_HASH = c.BIP32_FLAG_SKIP_HASH;
pub const BIP32_VER_MAIN_PUBLIC = c.BIP32_VER_MAIN_PUBLIC;
pub const BIP32_VER_MAIN_PRIVATE = c.BIP32_VER_MAIN_PRIVATE;
pub const BIP32_VER_TEST_PUBLIC = c.BIP32_VER_TEST_PUBLIC;
pub const BIP32_VER_TEST_PRIVATE = c.BIP32_VER_TEST_PRIVATE;

// BIP39 constants
pub const BIP39_SEED_LEN_512 = c.BIP39_SEED_LEN_512;
pub const BIP39_ENTROPY_LEN_128 = c.BIP39_ENTROPY_LEN_128;
pub const BIP39_ENTROPY_LEN_160 = c.BIP39_ENTROPY_LEN_160;
pub const BIP39_ENTROPY_LEN_192 = c.BIP39_ENTROPY_LEN_192;
pub const BIP39_ENTROPY_LEN_224 = c.BIP39_ENTROPY_LEN_224;
pub const BIP39_ENTROPY_LEN_256 = c.BIP39_ENTROPY_LEN_256;

// Hash lengths
pub const SHA256_LEN = c.SHA256_LEN;
pub const SHA512_LEN = c.SHA512_LEN;
pub const HASH160_LEN = c.HASH160_LEN;
pub const HMAC_SHA256_LEN = c.HMAC_SHA256_LEN;
pub const HMAC_SHA512_LEN = c.HMAC_SHA512_LEN;

// EC constants
pub const EC_PRIVATE_KEY_LEN = c.EC_PRIVATE_KEY_LEN;
pub const EC_PUBLIC_KEY_LEN = c.EC_PUBLIC_KEY_LEN;
pub const EC_PUBLIC_KEY_UNCOMPRESSED_LEN = c.EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
pub const EC_MESSAGE_HASH_LEN = c.EC_MESSAGE_HASH_LEN;
pub const EC_SIGNATURE_LEN = c.EC_SIGNATURE_LEN;
pub const EC_SIGNATURE_RECOVERABLE_LEN = c.EC_SIGNATURE_RECOVERABLE_LEN;

// EC flags
pub const EC_FLAG_ECDSA = c.EC_FLAG_ECDSA;
pub const EC_FLAG_SCHNORR = c.EC_FLAG_SCHNORR;
pub const EC_FLAG_GRIND_R = c.EC_FLAG_GRIND_R;

// Script flags
pub const WALLY_SCRIPT_TYPE_UNKNOWN = c.WALLY_SCRIPT_TYPE_UNKNOWN;
pub const WALLY_SCRIPT_TYPE_OP_RETURN = c.WALLY_SCRIPT_TYPE_OP_RETURN;
pub const WALLY_SCRIPT_TYPE_P2PKH = c.WALLY_SCRIPT_TYPE_P2PKH;
pub const WALLY_SCRIPT_TYPE_P2SH = c.WALLY_SCRIPT_TYPE_P2SH;
pub const WALLY_SCRIPT_TYPE_P2WPKH = c.WALLY_SCRIPT_TYPE_P2WPKH;
pub const WALLY_SCRIPT_TYPE_P2WSH = c.WALLY_SCRIPT_TYPE_P2WSH;
pub const WALLY_SCRIPT_TYPE_P2TR = c.WALLY_SCRIPT_TYPE_P2TR;

// Address versions
pub const WALLY_ADDRESS_VERSION_P2PKH_MAINNET = c.WALLY_ADDRESS_VERSION_P2PKH_MAINNET;
pub const WALLY_ADDRESS_VERSION_P2PKH_TESTNET = c.WALLY_ADDRESS_VERSION_P2PKH_TESTNET;
pub const WALLY_ADDRESS_VERSION_P2SH_MAINNET = c.WALLY_ADDRESS_VERSION_P2SH_MAINNET;
pub const WALLY_ADDRESS_VERSION_P2SH_TESTNET = c.WALLY_ADDRESS_VERSION_P2SH_TESTNET;

// Transaction constants
pub const WALLY_TXHASH_LEN = c.WALLY_TXHASH_LEN;
pub const WALLY_TX_FLAG_USE_WITNESS = c.WALLY_TX_FLAG_USE_WITNESS;
pub const WALLY_TX_FLAG_USE_ELEMENTS = c.WALLY_TX_FLAG_USE_ELEMENTS;

// Bech32 variants
pub const WALLY_BECH32_VARIANT_BECH32 = c.WALLY_BECH32_VARIANT_BECH32;
pub const WALLY_BECH32_VARIANT_BECH32M = c.WALLY_BECH32_VARIANT_BECH32M;

// ============================================================================
// Tests
// ============================================================================

test "library initialization" {
    try init(0);
    defer cleanup(0) catch {};

    const version = try getBuildVersion();
    try std.testing.expect(version > 0);
}

test "sha256 hash" {
    try init(0);
    defer cleanup(0) catch {};

    const data = "hello world";
    var hash: [SHA256_LEN]u8 = undefined;
    try sha256(data, &hash);

    // SHA256 of "hello world" should be non-zero
    var is_nonzero = false;
    for (hash) |b| {
        if (b != 0) {
            is_nonzero = true;
            break;
        }
    }
    try std.testing.expect(is_nonzero);
}

test "hex conversion" {
    try init(0);
    defer cleanup(0) catch {};

    const hex_str = "deadbeef";
    var bytes: [4]u8 = undefined;
    try hexToBytes(hex_str, &bytes);

    try std.testing.expectEqual(@as(u8, 0xde), bytes[0]);
    try std.testing.expectEqual(@as(u8, 0xad), bytes[1]);
    try std.testing.expectEqual(@as(u8, 0xbe), bytes[2]);
    try std.testing.expectEqual(@as(u8, 0xef), bytes[3]);
}

test "BIP39 mnemonic generation and validation" {
    try init(0);
    defer cleanup(0) catch {};

    // Test entropy to mnemonic conversion
    const entropy = [_]u8{
        0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
        0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
    };

    var mnemonic_ptr: [*c]u8 = null;
    try bip39MnemonicFromBytes(&entropy, &mnemonic_ptr);
    defer free(mnemonic_ptr);

    const mnemonic = std.mem.span(@as([*:0]const u8, @ptrCast(mnemonic_ptr)));

    // Expected mnemonic for this entropy
    const expected = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    try std.testing.expectEqualStrings(expected, mnemonic);

    // Validate the mnemonic
    try bip39MnemonicValidate(mnemonic_ptr);

    // Convert to seed
    var seed: [BIP39_SEED_LEN_512]u8 = undefined;
    try bip39MnemonicToSeed(mnemonic_ptr, null, &seed);

    // Seed should be non-zero
    var is_nonzero = false;
    for (seed) |b| {
        if (b != 0) {
            is_nonzero = true;
            break;
        }
    }
    try std.testing.expect(is_nonzero);
}

test "BIP32 key derivation - test vector 1" {
    try init(0);
    defer cleanup(0) catch {};

    // Test vector 1 from BIP32 specification
    const seed_hex = "000102030405060708090a0b0c0d0e0f";
    var seed: [16]u8 = undefined;
    for (0..16) |i| {
        const byte_str = seed_hex[i * 2 .. i * 2 + 2];
        seed[i] = try std.fmt.parseInt(u8, byte_str, 16);
    }

    // Create master key
    const master_key = try bip32KeyFromSeedAlloc(
        &seed,
        BIP32_VER_MAIN_PRIVATE,
        BIP32_FLAG_KEY_PRIVATE,
    );
    defer bip32KeyFree(master_key);

    try std.testing.expectEqual(@as(u8, 0), master_key.depth);
    try std.testing.expectEqual(@as(u32, 0), master_key.child_num);

    // Derive m/0H (first hardened child)
    const child_0h = 0x80000000; // 0H
    var derived_key: c.ext_key = undefined;
    try bip32KeyFromParent(
        master_key,
        child_0h,
        BIP32_FLAG_KEY_PRIVATE,
        &derived_key,
    );

    try std.testing.expectEqual(@as(u8, 1), derived_key.depth);
    try std.testing.expectEqual(child_0h, derived_key.child_num);
}

test "BIP32 path derivation" {
    try init(0);
    defer cleanup(0) catch {};

    const seed_hex = "000102030405060708090a0b0c0d0e0f";
    var seed: [16]u8 = undefined;
    for (0..16) |i| {
        const byte_str = seed_hex[i * 2 .. i * 2 + 2];
        seed[i] = try std.fmt.parseInt(u8, byte_str, 16);
    }

    const master_key = try bip32KeyFromSeedAlloc(
        &seed,
        BIP32_VER_MAIN_PRIVATE,
        BIP32_FLAG_KEY_PRIVATE,
    );
    defer bip32KeyFree(master_key);

    // Derive m/0H/1/2H using path
    const path = [_]u32{
        0x80000000, // 0H
        1, // 1
        0x80000002, // 2H
    };

    var child_key: c.ext_key = undefined;
    try bip32KeyFromParentPath(
        master_key,
        &path,
        BIP32_FLAG_KEY_PRIVATE,
        &child_key,
    );

    try std.testing.expectEqual(@as(u8, 3), child_key.depth);
}

test "base58 encoding and decoding" {
    try init(0);
    defer cleanup(0) catch {};

    // Test basic base58 encoding
    const data = "Hello World";
    var encoded_ptr: [*c]u8 = null;
    try base58FromBytes(data, 0, &encoded_ptr);
    defer free(encoded_ptr);

    // Decode it back
    var decoded: [100]u8 = undefined;
    const written = try base58ToBytes(encoded_ptr, 0, &decoded);

    try std.testing.expectEqualStrings(data, decoded[0..written]);
}

test "ECDSA signing and verification" {
    try init(0);
    defer cleanup(0) catch {};

    // Test private key
    const privkey = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };

    // Verify it's a valid private key
    try ecPrivateKeyVerify(&privkey);

    // Derive public key
    var pubkey: [EC_PUBLIC_KEY_LEN]u8 = undefined;
    try ecPublicKeyFromPrivateKey(&privkey, &pubkey);

    // Create message hash
    const message = "Test message";
    var message_hash: [EC_MESSAGE_HASH_LEN]u8 = undefined;
    try sha256(message, &message_hash);

    // Sign the message
    var signature: [EC_SIGNATURE_LEN]u8 = undefined;
    try ecSigFromBytes(&privkey, &message_hash, EC_FLAG_ECDSA, &signature);

    // Verify the signature
    try ecSigVerify(&pubkey, &message_hash, EC_FLAG_ECDSA, &signature);

    // Verification with wrong message should fail
    var wrong_hash: [EC_MESSAGE_HASH_LEN]u8 = undefined;
    try sha256("Wrong message", &wrong_hash);

    const verify_result = ecSigVerify(&pubkey, &wrong_hash, EC_FLAG_ECDSA, &signature);
    try std.testing.expect(std.meta.isError(verify_result));
}

test "hash functions" {
    try init(0);
    defer cleanup(0) catch {};

    const data = "test data";

    // Test SHA256
    var sha256_result: [SHA256_LEN]u8 = undefined;
    try sha256(data, &sha256_result);

    // Test SHA256d (double SHA256)
    var sha256d_result: [SHA256_LEN]u8 = undefined;
    try sha256d(data, &sha256d_result);

    // They should be different
    try std.testing.expect(!std.mem.eql(u8, &sha256_result, &sha256d_result));

    // Test SHA512
    var sha512_result: [SHA512_LEN]u8 = undefined;
    try sha512(data, &sha512_result);

    // Test Hash160
    var hash160_result: [HASH160_LEN]u8 = undefined;
    try hash160(data, &hash160_result);

    // All should be non-zero
    try std.testing.expect(!std.mem.eql(u8, &sha256_result, &[_]u8{0} ** SHA256_LEN));
    try std.testing.expect(!std.mem.eql(u8, &sha512_result, &[_]u8{0} ** SHA512_LEN));
    try std.testing.expect(!std.mem.eql(u8, &hash160_result, &[_]u8{0} ** HASH160_LEN));
}

test "HMAC functions" {
    try init(0);
    defer cleanup(0) catch {};

    const key = "secret key";
    const data = "message to authenticate";

    // Test HMAC-SHA256
    var hmac256_result: [HMAC_SHA256_LEN]u8 = undefined;
    try hmacSha256(key, data, &hmac256_result);

    // Test HMAC-SHA512
    var hmac512_result: [HMAC_SHA512_LEN]u8 = undefined;
    try hmacSha512(key, data, &hmac512_result);

    // Results should be non-zero
    try std.testing.expect(!std.mem.eql(u8, &hmac256_result, &[_]u8{0} ** HMAC_SHA256_LEN));
    try std.testing.expect(!std.mem.eql(u8, &hmac512_result, &[_]u8{0} ** HMAC_SHA512_LEN));

    // Same key and data should produce same result
    var hmac256_result2: [HMAC_SHA256_LEN]u8 = undefined;
    try hmacSha256(key, data, &hmac256_result2);
    try std.testing.expectEqualSlices(u8, &hmac256_result, &hmac256_result2);
}

test "PBKDF2 key derivation" {
    try init(0);
    defer cleanup(0) catch {};

    const password = "password";
    const salt = "salt";
    const iterations = 100;

    // Test PBKDF2-HMAC-SHA256
    var derived_key: [32]u8 = undefined;
    try pbkdf2HmacSha256(password, salt, 0, iterations, &derived_key);

    // Result should be non-zero
    try std.testing.expect(!std.mem.eql(u8, &derived_key, &[_]u8{0} ** 32));

    // Same inputs should produce same output
    var derived_key2: [32]u8 = undefined;
    try pbkdf2HmacSha256(password, salt, 0, iterations, &derived_key2);
    try std.testing.expectEqualSlices(u8, &derived_key, &derived_key2);

    // Different password should produce different output
    var derived_key3: [32]u8 = undefined;
    try pbkdf2HmacSha256("different", salt, 0, iterations, &derived_key3);
    try std.testing.expect(!std.mem.eql(u8, &derived_key, &derived_key3));
}

test "transaction creation" {
    try init(0);
    defer cleanup(0) catch {};

    // Create a simple transaction
    const tx = try txInit(2, 0, 1, 1);
    defer txFree(tx);

    try std.testing.expectEqual(@as(u32, 2), tx.version);
    try std.testing.expectEqual(@as(u32, 0), tx.locktime);
    try std.testing.expectEqual(@as(usize, 0), tx.num_inputs);
    try std.testing.expectEqual(@as(usize, 0), tx.num_outputs);

    // Get txid
    var txid: [WALLY_TXHASH_LEN]u8 = undefined;
    try txGetTxid(tx, &txid);

    // Get wtxid
    var wtxid: [WALLY_TXHASH_LEN]u8 = undefined;
    try txGetWtxid(tx, &wtxid);

    // Both should be non-zero
    try std.testing.expect(!std.mem.eql(u8, &txid, &[_]u8{0} ** WALLY_TXHASH_LEN));
    try std.testing.expect(!std.mem.eql(u8, &wtxid, &[_]u8{0} ** WALLY_TXHASH_LEN));
}

test "PSBT creation" {
    try init(0);
    defer cleanup(0) catch {};

    // Create a PSBT
    const psbt = try psbtInitAlloc(0, 1, 1, 0);
    defer psbtFree(psbt);

    try std.testing.expectEqual(@as(u32, 0), psbt.version);
    try std.testing.expectEqual(@as(usize, 0), psbt.num_inputs);
    try std.testing.expectEqual(@as(usize, 0), psbt.num_outputs);
}
