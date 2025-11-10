# Zig Wrapper for libwally-core

This repository contains **thin Zig bindings** for libwally-core. The wrapper does NOT build libwally-core from source - users must install it separately.

## Quick Start

### 1. Install libwally-core

You must first build and install the upstream libwally-core C library:

```bash
# Clone the upstream repository
cd /tmp
git clone --recursive https://github.com/ElementsProject/libwally-core.git
cd libwally-core

# Install autotools if needed (macOS)
brew install automake autoconf libtool

# Build and install
./tools/autogen.sh
./configure --enable-elements
make
sudo make install
```

This installs:
- Headers to `/usr/local/include/wally_*.h`
- Library to `/usr/local/lib/libwallycore.{a,dylib}`

### 2. Use the Zig wrapper

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .libwally_core = .{
        .url = "git+https://github.com/evmts/libwally-core.git#COMMIT",
        .hash = "HASH", // Run zig build to compute
    },
},
```

In your `build.zig`:

```zig
const libwally_dep = b.dependency("libwally_core", .{
    .target = target,
    .optimize = optimize,
});
const libwally_mod = libwally_dep.module("libwally_core");

// Add to your executable imports
.imports = &.{
    .{ .name = "libwally_core", .module = libwally_mod },
},
```

### 3. Use in your code

```zig
const wally = @import("libwally_core");

try wally.init(0);
defer wally.cleanup(0) catch {};

// Use wally functions...
```

## Architecture

- **Zig Wrapper Only**: This repo contains only Zig bindings, no C compilation
- **External Dependencies**: Users link against system-installed libwally-core
- **Full API Access**: All C functions available via `wally.c` namespace
- **Idiomatic Errors**: C error codes converted to Zig errors

## Documentation

See [zig.md](./zig.md) for complete usage documentation.

## Why This Approach?

1. **Cleaner separation**: Zig wrapper is separate from C library build
2. **User control**: Users control libwally-core version and build options
3. **No submodules**: No git submodule complexity
4. **Standard practice**: Matches how other language bindings work
5. **Smaller package**: Only Zig code, not entire C codebase
