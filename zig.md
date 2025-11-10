# libwally-core Zig Bindings

Thin Zig wrapper around libwally-core - compiles libwally C code and links against user-provided secp256k1.

## What This Package Does

✅ **Compiles libwally-core C sources** - Builds from the C files in this repo
✅ **Provides Zig wrapper** - Idiomatic error handling and Zig-friendly API
❌ **Does NOT include secp256k1** - You must provide this dependency

## Prerequisites

**Install secp256k1-zkp before building:**

```bash
# Clone and build secp256k1-zkp
git clone https://github.com/BlockstreamResearch/secp256k1-zkp.git
cd secp256k1-zkp
./autogen.sh

# Configure with all required modules
./configure \
  --enable-module-ecdh \
  --enable-module-recovery \
  --enable-module-extrakeys \
  --enable-module-schnorrsig \
  --enable-module-generator \
  --enable-module-rangeproof \
  --enable-module-surjectionproof \
  --enable-module-whitelist

make && sudo make install
```

Installs to `/usr/local` by default. Use `-Dsecp256k1-path=/custom/path` if installed elsewhere.

## Installation

Add to your `build.zig.zon`:

```bash
zig fetch --save git+https://github.com/YOUR_USERNAME/libwally-core.git
```

In your `build.zig`:

```zig
const libwally_dep = b.dependency("libwally_core", .{
    .target = target,
    .optimize = optimize,
    // Optional: custom secp256k1 location
    // .@"secp256k1-path" = "/custom/path",
});
const libwally_mod = libwally_dep.module("libwally_core");
```

## Usage Example

```zig
const wally = @import("libwally_core");

pub fn main() !void {
    try wally.init(0);
    defer wally.cleanup(0) catch {};

    // Generate BIP39 mnemonic
    var entropy: [wally.BIP39_ENTROPY_LEN_128]u8 = undefined;
    std.crypto.random.bytes(&entropy);

    var mnemonic_ptr: [*c]u8 = null;
    try wally.bip39MnemonicFromBytes(&entropy, &mnemonic_ptr);
    defer wally.free(mnemonic_ptr);

    // Convert to seed
    var seed: [wally.BIP39_SEED_LEN_512]u8 = undefined;
    try wally.bip39MnemonicToSeed(mnemonic_ptr, null, &seed);

    // Derive keys
    const key = try wally.bip32KeyFromSeedAlloc(
        &seed,
        wally.BIP32_VER_MAIN_PRIVATE,
        wally.BIP32_FLAG_KEY_PRIVATE,
    );
    defer wally.bip32KeyFree(key);
}
```

See [src/main.zig](./src/main.zig) for complete examples.

## Architecture

| Component | Included | How |
|-----------|----------|-----|
| libwally C code | ✅ Yes | Compiled from src/*.c |
| CCAN utilities | ✅ Yes | Compiled from src/ccan |
| Zig wrapper | ✅ Yes | src/root.zig |
| secp256k1 | ❌ No | User provides via `-Dsecp256k1-path` |

## Building

```bash
# Ensure secp256k1 is installed
ls /usr/local/lib/libsecp256k1.*

# Build and run example
zig build run

# Run tests
zig build test

# Custom secp256k1 location
zig build -Dsecp256k1-path=/opt/homebrew
```

## Troubleshooting

### "cannot find -lsecp256k1"

```bash
# Check installation
ls /usr/local/lib/libsecp256k1.*

# Set library path (Linux)
export LD_LIBRARY_PATH=/usr/local/lib

# macOS
export DYLD_LIBRARY_PATH=/usr/local/lib
```

### "secp256k1.h not found"

```bash
# Specify path
zig build -Dsecp256k1-path=/usr/local
```

### Missing module errors

Rebuild secp256k1 with all modules enabled (see Prerequisites).

## Documentation

- [libwally-core Docs](https://wally.readthedocs.io/)
- [Example Code](./src/main.zig)
- [API Headers](./include/)

## License

Same license as libwally-core. See [LICENSE](./LICENSE).
