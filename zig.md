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

## Prerequisites

**You must build and install libwally-core before using this wrapper.**

### Building libwally-core

```bash
# Clone the repository (if you haven't already)
git clone --recursive https://github.com/ElementsProject/libwally-core.git
cd libwally-core

# Option 1: Autotools build
./tools/autogen.sh
./configure --enable-elements
make
sudo make install

# Option 2: CMake build
mkdir build && cd build
cmake .. -DBUILD_ELEMENTS=ON
make
sudo make install
```

This will install:
- Headers to `/usr/local/include/wally_*.h`
- Library to `/usr/local/lib/libwallycore.{a,so,dylib}`

### Custom Installation Path

If you installed to a custom location:

```bash
./configure --prefix=/custom/path --enable-elements
make && make install
```

Then use `-Dlibwally-path=/custom/path` when building with Zig.

## Installation

### Using zig fetch (recommended)

Add this library as a dependency to your project:

```bash
zig fetch --save git+https://github.com/YOUR_USERNAME/libwally-core.git
```

### Add to your build.zig

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Get the libwally_core dependency
    const libwally_dep = b.dependency("libwally_core", .{
        .target = target,
        .optimize = optimize,
        // Optional: specify custom libwally-core path
        // .@"libwally-path" = "/custom/path",
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

### Environment Setup

Make sure pkg-config can find libwally-core:

```bash
# Check if libwally-core is found
pkg-config --cflags --libs wallycore

# If not found, add to PKG_CONFIG_PATH
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
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
    var mnemonic_ptr: [*c]u8 = null;
    try wally.bip39MnemonicFromBytes(&entropy, &mnemonic_ptr);
    defer wally.free(mnemonic_ptr);

    const mnemonic = std.mem.span(@as([*:0]const u8, @ptrCast(mnemonic_ptr)));
    std.debug.print("Mnemonic: {s}\n", .{mnemonic});

    // Convert mnemonic to seed
    var seed: [wally.BIP39_SEED_LEN_512]u8 = undefined;
    try wally.bip39MnemonicToSeed(
        mnemonic_ptr,
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
// Derive m/44'/0'/0'/0/0 (first Bitcoin receive address)
const path = [_]u32{
    0x8000002C, // 44' (purpose)
    0x80000000, // 0'  (coin type - Bitcoin)
    0x80000000, // 0'  (account)
    0,          // 0   (external chain)
    0,          // 0   (address index)
};

var child_key: wally.c.ext_key = undefined;
try wally.bip32KeyFromParentPath(
    master_key,
    &path,
    wally.BIP32_FLAG_KEY_PRIVATE,
    &child_key,
);

// Generate address from child key
var address_buf: [128]u8 = undefined;
try wally.bip32KeyToAddress(
    &child_key,
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

Functions that allocate memory (e.g., `bip39MnemonicFromBytes`, `bip32KeyFromSeedAlloc`) return pointers that **must** be freed:

```zig
var mnemonic_ptr: [*c]u8 = null;
try wally.bip39MnemonicFromBytes(&entropy, &mnemonic_ptr);
defer wally.free(mnemonic_ptr);

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

To build and test this wrapper locally:

```bash
# Ensure libwally-core is installed first (see Prerequisites)

# Clone this repo
git clone https://github.com/YOUR_USERNAME/libwally-core.git
cd libwally-core

# Build and run example
zig build run

# Run tests (requires libwally-core installed)
zig build test

# Specify custom libwally-core path
zig build test -Dlibwally-path=/custom/path
```

## Dependencies

### Required:
- **libwally-core** (>= 1.5.0) - Must be built and installed separately
- **libsecp256k1-zkp** - Included with libwally-core build

### Runtime:
- Standard C library (libc)

### Build:
- Zig >= 0.15.1

## Troubleshooting

### "cannot find -lwallycore"

Make sure libwally-core is installed:
```bash
# Check if library exists
ls /usr/local/lib/libwallycore.*

# Add to library path if needed (Linux)
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# macOS
export DYLD_LIBRARY_PATH=/usr/local/lib:$DYLD_LIBRARY_PATH
```

### "wally_core.h file not found"

Specify the correct include path:
```bash
zig build -Dlibwally-path=/usr/local
```

### Tests fail to link

Ensure you've built libwally-core with all required features:
```bash
./configure --enable-elements
make clean && make && sudo make install
```

## API Documentation

This wrapper provides thin Zig bindings with idiomatic error handling. For detailed API documentation, refer to:

- [libwally-core Documentation](https://wally.readthedocs.io/)
- [C API Headers](https://github.com/ElementsProject/libwally-core/tree/master/include)
- [Example Usage](./src/main.zig)

## Supported Platforms

- Linux (x86_64, ARM64)
- macOS (x86_64, ARM64/Apple Silicon)
- Windows (x86_64) - with MinGW or MSVC
- Any platform supported by both Zig and libwally-core

## License

This Zig wrapper follows the same license as libwally-core. See [LICENSE](./LICENSE) for details.

## Contributing

Contributions are welcome! Please ensure:
- All C functions remain accessible via the `c` namespace
- Error handling is properly implemented
- Tests are added for new functionality
- Documentation is updated

## Resources

- [BIP32 - Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP39 - Mnemonic Code for Generating Deterministic Keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP340 - Schnorr Signatures](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [libwally-core Repository](https://github.com/ElementsProject/libwally-core)
