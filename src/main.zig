const std = @import("std");
const wally = @import("libwally_core");

pub fn main() !void {
    std.debug.print("\n=== libwally-core Zig Wrapper Demo ===\n\n", .{});

    // Initialize the library
    try wally.init(0);
    defer wally.cleanup(0) catch {};

    // Get library version
    const version = try wally.getBuildVersion();
    std.debug.print("libwally-core version: 0x{X:0>6}\n\n", .{version});

    // Demo 1: Hash functions
    try demoHashing();

    // Demo 2: BIP39 mnemonic and seed generation
    try demoMnemonic();

    // Demo 3: BIP32 key derivation
    try demoKeyDerivation();

    // Demo 4: ECDSA operations
    try demoECDSA();

    std.debug.print("\n=== All demos completed successfully! ===\n", .{});
}

fn demoHashing() !void {
    std.debug.print("--- Hash Functions Demo ---\n", .{});

    const data = "Hello, Bitcoin!";

    // SHA256
    var sha256_hash: [wally.SHA256_LEN]u8 = undefined;
    try wally.sha256(data, &sha256_hash);
    std.debug.print("SHA256(\"{s}\") = ", .{data});
    printHex(&sha256_hash);
    std.debug.print("\n", .{});

    // SHA256d (double SHA256)
    var sha256d_hash: [wally.SHA256_LEN]u8 = undefined;
    try wally.sha256d(data, &sha256d_hash);
    std.debug.print("SHA256d(\"{s}\") = ", .{data});
    printHex(&sha256d_hash);
    std.debug.print("\n", .{});

    // Hash160 (RIPEMD160(SHA256))
    var hash160: [wally.HASH160_LEN]u8 = undefined;
    try wally.hash160(data, &hash160);
    std.debug.print("Hash160(\"{s}\") = ", .{data});
    printHex(&hash160);
    std.debug.print("\n\n", .{});
}

fn demoMnemonic() !void {
    std.debug.print("--- BIP39 Mnemonic Demo ---\n", .{});

    // Use a fixed entropy for reproducible demo
    // In production, use std.crypto.random.bytes() or a secure RNG
    const entropy = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };

    // Generate mnemonic
    var mnemonic_buf: [256]u8 = undefined;
    @memset(&mnemonic_buf, 0);
    try wally.bip39MnemonicFromBytes(&entropy, &mnemonic_buf);

    const mnemonic = std.mem.span(@as([*:0]u8, @ptrCast(&mnemonic_buf)));
    std.debug.print("Mnemonic: {s}\n", .{mnemonic});

    // Validate mnemonic
    try wally.bip39MnemonicValidate(@ptrCast(&mnemonic_buf));
    std.debug.print("Mnemonic validation: OK\n", .{});

    // Convert to seed
    var seed: [wally.BIP39_SEED_LEN_512]u8 = undefined;
    try wally.bip39MnemonicToSeed(
        @ptrCast(&mnemonic_buf),
        null, // no passphrase
        &seed,
    );
    std.debug.print("Seed (first 32 bytes): ", .{});
    printHex(seed[0..32]);
    std.debug.print("\n\n", .{});
}

fn demoKeyDerivation() !void {
    std.debug.print("--- BIP32 Key Derivation Demo ---\n", .{});

    // Use the same entropy as mnemonic demo
    const entropy = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };

    var mnemonic_buf: [256]u8 = undefined;
    @memset(&mnemonic_buf, 0);
    try wally.bip39MnemonicFromBytes(&entropy, &mnemonic_buf);

    var seed: [wally.BIP39_SEED_LEN_512]u8 = undefined;
    try wally.bip39MnemonicToSeed(@ptrCast(&mnemonic_buf), null, &seed);

    // Create master key
    const master_key = try wally.bip32KeyFromSeedAlloc(
        &seed,
        wally.BIP32_VER_MAIN_PRIVATE,
        wally.BIP32_FLAG_KEY_PRIVATE,
    );
    defer wally.bip32KeyFree(master_key);

    std.debug.print("Master key created\n", .{});
    std.debug.print("Master key depth: {}\n", .{master_key.depth});

    // Derive m/44'/0'/0'/0/0 (first Bitcoin receive address)
    // 44' = 0x8000002C (BIP44 purpose)
    // 0'  = 0x80000000 (Bitcoin mainnet)
    // 0'  = 0x80000000 (first account)
    // 0   = 0x00000000 (external/receive chain)
    // 0   = 0x00000000 (first address)
    const path = [_]u32{
        0x8000002C, // 44' (purpose)
        0x80000000, // 0'  (coin type - Bitcoin)
        0x80000000, // 0'  (account)
        0,          // 0   (external chain)
        0,          // 0   (address index)
    };

    var child_key: ?*wally.c.ext_key = null;
    try wally.bip32KeyFromParentPath(
        master_key,
        &path,
        wally.BIP32_FLAG_KEY_PRIVATE,
        &child_key,
    );
    defer wally.bip32KeyFree(child_key);

    std.debug.print("Derived path: m/44'/0'/0'/0/0\n", .{});
    std.debug.print("Child key depth: {}\n", .{child_key.?.depth});

    // Generate P2PKH address from child key
    var address_buf: [128]u8 = undefined;
    @memset(&address_buf, 0);
    try wally.bip32KeyToAddress(
        child_key.?,
        wally.BIP32_FLAG_KEY_PUBLIC,
        wally.WALLY_ADDRESS_VERSION_P2PKH_MAINNET,
        &address_buf,
        address_buf.len,
    );

    const address = std.mem.span(@as([*:0]u8, @ptrCast(&address_buf)));
    std.debug.print("Bitcoin address (P2PKH): {s}\n\n", .{address});
}

fn demoECDSA() !void {
    std.debug.print("--- ECDSA Signature Demo ---\n", .{});

    // Generate a private key (fixed for demo)
    const privkey = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };

    // Verify private key is valid
    try wally.ecPrivateKeyVerify(&privkey);
    std.debug.print("Private key: ", .{});
    printHex(&privkey);
    std.debug.print("\n", .{});

    // Derive public key
    var pubkey: [wally.EC_PUBLIC_KEY_LEN]u8 = undefined;
    try wally.ecPublicKeyFromPrivateKey(&privkey, &pubkey);
    std.debug.print("Public key: ", .{});
    printHex(&pubkey);
    std.debug.print("\n", .{});

    // Create a message hash to sign
    const message = "Message to sign";
    var message_hash: [wally.EC_MESSAGE_HASH_LEN]u8 = undefined;
    try wally.sha256(message, &message_hash);
    std.debug.print("Message: \"{s}\"\n", .{message});
    std.debug.print("Message hash: ", .{});
    printHex(&message_hash);
    std.debug.print("\n", .{});

    // Sign the message
    var signature: [wally.EC_SIGNATURE_LEN]u8 = undefined;
    try wally.ecSigFromBytes(
        &privkey,
        &message_hash,
        wally.EC_FLAG_ECDSA,
        &signature,
    );
    std.debug.print("Signature: ", .{});
    printHex(&signature);
    std.debug.print("\n", .{});

    // Verify the signature
    try wally.ecSigVerify(
        &pubkey,
        &message_hash,
        wally.EC_FLAG_ECDSA,
        &signature,
    );
    std.debug.print("Signature verification: OK\n", .{});

    // Test with wrong message (should fail)
    var wrong_hash: [wally.EC_MESSAGE_HASH_LEN]u8 = undefined;
    try wally.sha256("Wrong message", &wrong_hash);

    const verify_result = wally.ecSigVerify(
        &pubkey,
        &wrong_hash,
        wally.EC_FLAG_ECDSA,
        &signature,
    );

    if (verify_result) {
        std.debug.print("ERROR: Signature should have failed!\n", .{});
    } else |_| {
        std.debug.print("Wrong message verification: Failed (as expected)\n", .{});
    }

    std.debug.print("\n", .{});
}

fn printHex(bytes: []const u8) void {
    for (bytes) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
}

test "basic functionality" {
    try wally.init(0);
    defer wally.cleanup(0) catch {};

    // Test SHA256
    const data = "test";
    var hash: [wally.SHA256_LEN]u8 = undefined;
    try wally.sha256(data, &hash);

    // Hash should be non-zero
    var is_nonzero = false;
    for (hash) |b| {
        if (b != 0) {
            is_nonzero = true;
            break;
        }
    }
    try std.testing.expect(is_nonzero);
}
