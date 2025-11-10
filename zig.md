# libwally-core Zig Bindings

Thin Zig wrapper around [libwally-core](https://github.com/ElementsProject/libwally-core), a cross-platform cryptocurrency wallet library from Blockstream.

## Features

- **Complete API access**: All C functions exposed through the `c` namespace
- **Idiomatic error handling**: C error codes converted to Zig errors
- **Bitcoin & Elements/Liquid support**: Full support for both networks
- **Comprehensive functionality**:
  - BIP39 mnemonic phrases
  - BIP32 HD wallet key derivation
  - Address generation (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
  - Transaction construction and signing
  - PSBT (Partially Signed Bitcoin Transactions)
  - Cryptographic primitives (ECDSA, Schnorr/BIP340)
  - Script operations
  - Elements/Liquid confidential transactions

## Installation

### Using zig fetch (recommended)

Add this library as a dependency to your project using `zig fetch`:

```bash
# Replace with your fork URL or the upstream URL
zig fetch --save git+https://github.com/YOUR_USERNAME/libwally-core.git
```

This will:
1. Download the library
2. Add it to your `build.zig.zon` dependencies
3. Generate a content hash for the dependency

### Manual configuration

If you prefer to add the dependency manually, update your `build.zig.zon`:

```zig
.{
    .name = "my-bitcoin-app",
    .version = "0.1.0",
    .dependencies = .{
        .libwally_core = .{
            .url = "git+https://github.com/YOUR_USERNAME/libwally-core.git#COMMIT_HASH",
            .hash = "HASH_HERE", // Run `zig build` to compute this
        },
    },
}
```

### Add to your build.zig

In your `build.zig`, add the module as a dependency:

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Get the libwally_core dependency
    const libwally_dep = b.dependency("libwally_core", .{
        .target = target,
        .optimize = optimize,
    });
    const libwally_mod = libwally_dep.module("libwally_core");

    // Create your executable
    const exe = b.addExecutable(.{
        .name = "my-app",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "libwally_core", .module = libwally_mod },
            },
        }),
    });

    b.installArtifact(exe);
}
```

## Usage

### Import the library

```zig
const std = @import("std");
const wally = @import("libwally_core");
```

### Initialize the library

Always initialize the library before using any functions:

```zig
try wally.init(0);
defer wally.cleanup(0) catch {};
```

### Basic Examples

#### Generate a BIP39 mnemonic and derive keys

```zig
const std = @import("std");
const wally = @import("libwally_core");

pub fn main() !void {
    // Initialize library
    try wally.init(0);
    defer wally.cleanup(0) catch {};

    // Generate entropy for a 12-word mnemonic (128 bits)
    var entropy: [wally.BIP39_ENTROPY_LEN_128]u8 = undefined;
    std.crypto.random.bytes(&entropy);

    // Generate mnemonic from entropy
    var mnemonic_buf: [256]u8 = undefined;
    try wally.bip39MnemonicFromBytes(&entropy, &mnemonic_buf);

    const mnemonic = std.mem.span(@as([*:0]u8, @ptrCast(&mnemonic_buf)));
    std.debug.print("Mnemonic: {s}\n", .{mnemonic});

    // Convert mnemonic to seed
    var seed: [wally.BIP39_SEED_LEN_512]u8 = undefined;
    try wally.bip39MnemonicToSeed(
        @ptrCast(&mnemonic_buf),
        null, // no passphrase
        &seed,
    );

    // Create master key from seed
    const master_key = try wally.bip32KeyFromSeedAlloc(
        &seed,
        wally.BIP32_VER_MAIN_PRIVATE,
        wally.BIP32_FLAG_KEY_PRIVATE,
    );
    defer wally.bip32KeyFree(master_key);

    std.debug.print("Master key created successfully!\n", .{});
}
```

#### Derive child keys using BIP32 paths

```zig
// Derive m/44'/0'/0'/0/0 (first receive address)
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

// Generate address from child key
var address_buf: [128]u8 = undefined;
try wally.bip32KeyToAddress(
    child_key.?,
    wally.BIP32_FLAG_KEY_PUBLIC,
    wally.WALLY_ADDRESS_VERSION_P2PKH_MAINNET,
    &address_buf,
    address_buf.len,
);

const address = std.mem.span(@as([*:0]u8, @ptrCast(&address_buf)));
std.debug.print("Address: {s}\n", .{address});
```

#### Hash data with SHA256

```zig
const data = "Hello, Bitcoin!";
var hash: [wally.SHA256_LEN]u8 = undefined;
try wally.sha256(data, &hash);

// Convert to hex
var hex: [wally.SHA256_LEN * 2 + 1]u8 = undefined;
try wally.bytesToHex(&hash, hex[0 .. wally.SHA256_LEN * 2]);
hex[wally.SHA256_LEN * 2] = 0; // null terminate

std.debug.print("SHA256: {s}\n", .{hex[0 .. wally.SHA256_LEN * 2]});
```

#### Create and sign with ECDSA

```zig
// Generate a private key (in production, use secure random)
var privkey: [wally.EC_PRIVATE_KEY_LEN]u8 = undefined;
std.crypto.random.bytes(&privkey);

// Verify it's valid
try wally.ecPrivateKeyVerify(&privkey);

// Get public key
var pubkey: [wally.EC_PUBLIC_KEY_LEN]u8 = undefined;
try wally.ecPublicKeyFromPrivateKey(&privkey, &pubkey);

// Sign a message hash
var message_hash: [wally.EC_MESSAGE_HASH_LEN]u8 = undefined;
try wally.sha256("Sign this message", &message_hash);

var signature: [wally.EC_SIGNATURE_LEN]u8 = undefined;
try wally.ecSigFromBytes(
    &privkey,
    &message_hash,
    wally.EC_FLAG_ECDSA,
    &signature,
);

// Verify signature
try wally.ecSigVerify(
    &pubkey,
    &message_hash,
    wally.EC_FLAG_ECDSA,
    &signature,
);

std.debug.print("Signature verified successfully!\n", .{});
```

#### Create a Bitcoin transaction

```zig
// Create a new transaction
const tx = try wally.txInit(
    2,  // version
    0,  // locktime
    1,  // num inputs
    1,  // num outputs
);
defer wally.txFree(tx);

// Note: Adding inputs and outputs requires constructing
// wally_tx_input and wally_tx_output structs using the C API
// See the wally.c namespace for full transaction construction

// Get transaction ID
var txid: [wally.WALLY_TXHASH_LEN]u8 = undefined;
try wally.txGetTxid(tx, &txid);
```

### Advanced Usage: Direct C API Access

All C functions are available through the `wally.c` namespace:

```zig
// Access any C function directly
const result = wally.c.wally_some_function(...);
try wally.checkError(result);

// Access C types
var key: wally.c.ext_key = undefined;
var tx: *wally.c.wally_tx = undefined;
var psbt: *wally.c.wally_psbt = undefined;

// Access C constants
const network = wally.c.WALLY_NETWORK_BITCOIN_MAINNET;
```

This gives you complete access to the entire libwally-core C API, including:
- Elements/Liquid functions
- PSBT operations
- Descriptor parsing
- Anti-exfiltration protocols
- Coin selection algorithms
- All transaction and script operations

## Error Handling

The wrapper converts C error codes to Zig errors:

```zig
pub const WallyError = error{
    Error,           // WALLY_ERROR (-1)
    InvalidArgument, // WALLY_EINVAL (-2)
    OutOfMemory,     // WALLY_ENOMEM (-3)
};
```

All wrapped functions that can fail return `WallyError!T`. Use Zig's standard error handling:

```zig
const result = wally.someFunction(...) catch |err| {
    std.debug.print("Error: {}\n", .{err});
    return err;
};
```

## Memory Management

Functions that allocate memory (e.g., `bip32KeyFromSeedAlloc`) return pointers that **must** be freed:

```zig
const key = try wally.bip32KeyFromSeedAlloc(seed, version, flags);
defer wally.bip32KeyFree(key);
```

For sensitive data, use `wally.bzero()` to securely zero memory before freeing:

```zig
var privkey: [32]u8 = undefined;
// ... use privkey ...
wally.bzero(&privkey, privkey.len);
```

## Building from Source

To build the library locally:

```bash
# Clone with submodules (includes libsecp256k1)
git clone --recursive https://github.com/YOUR_USERNAME/libwally-core.git
cd libwally-core

# Build and run example
zig build run

# Run tests
zig build test
```

## API Documentation

This wrapper provides thin Zig bindings with idiomatic error handling. For detailed API documentation, refer to the upstream libwally-core documentation:

- [libwally-core Documentation](https://wally.readthedocs.io/)
- [C API Headers](./include/)
- [Example Usage](./src/main.zig)

## Supported Platforms

- Linux (x86_64, ARM64)
- macOS (x86_64, ARM64)
- Windows (x86_64)
- WebAssembly (WASI)
- Other platforms supported by Zig and libwally-core

## License

This Zig wrapper follows the same license as libwally-core. See [LICENSE](./LICENSE) for details.

## Contributing

Contributions are welcome! Please ensure:
- All C functions remain accessible via the `c` namespace
- Error handling is properly implemented
- Tests are added for new functionality
- Documentation is updated

## Troubleshooting

### Build errors about missing headers

Ensure git submodules are initialized:
```bash
git submodule update --init --recursive
```

### Link errors on macOS

Zig automatically handles C library linking. If you encounter issues, ensure you have Xcode Command Line Tools installed:
```bash
xcode-select --install
```

### Elements/Liquid support

This build includes full Elements/Liquid support by default. To disable it, modify `build.zig` and remove the `-DBUILD_ELEMENTS` flag.

## Resources

- [BIP32 - Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP39 - Mnemonic Code for Generating Deterministic Keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP340 - Schnorr Signatures](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [libwally-core Repository](https://github.com/ElementsProject/libwally-core)
