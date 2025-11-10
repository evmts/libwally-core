const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // User must provide secp256k1 library path
    // Example: zig build -Dsecp256k1-path=/usr/local
    const secp256k1_path = b.option([]const u8, "secp256k1-path", "Path to secp256k1 installation") orelse "/usr/local";

    // Build libwally-core C library (without secp256k1 source)
    const libwally = b.addStaticLibrary(.{
        .name = "wally",
        .target = target,
        .optimize = optimize,
    });

    // Add all libwally C source files (NOT amalgamation, to avoid secp256k1 inclusion)
    const c_sources = [_][]const u8{
        "src/address.c",
        "src/aes.c",
        "src/anti_exfil.c",
        "src/base_58.c",
        "src/base_64.c",
        "src/bech32.c",
        "src/bip32.c",
        "src/bip38.c",
        "src/bip39.c",
        "src/bip85.c",
        "src/blech32.c",
        "src/coins.c",
        "src/descriptor.c",
        "src/ecdh.c",
        "src/elements.c",
        "src/hex_.c",
        "src/hmac.c",
        "src/internal.c",
        "src/map.c",
        "src/mnemonic.c",
        "src/pbkdf2.c",
        "src/psbt.c",
        "src/pullpush.c",
        "src/script.c",
        "src/scrypt.c",
        "src/sign.c",
        "src/symmetric.c",
        "src/transaction.c",
        "src/tx_io.c",
        "src/wif.c",
        "src/wordlist.c",
        // CCAN dependencies
        "src/ccan/ccan/crypto/ripemd160/ripemd160.c",
        "src/ccan/ccan/crypto/sha256/sha256.c",
        "src/ccan/ccan/crypto/sha512/sha512.c",
        "src/ccan/ccan/base64/base64.c",
        "src/ccan/ccan/str/hex/hex.c",
        // ctaes
        "src/ctaes/ctaes.c",
    };

    const c_flags = [_][]const u8{
        "-DBUILD_ELEMENTS",
        "-DUSE_ECMULT_STATIC_PRECOMPUTATION",
        "-DECMULT_WINDOW_SIZE=15",
        "-DWALLY_CORE_BUILD",
        "-DHAVE_CONFIG_H",
        "-std=c99",
        "-Wno-unused-function",
    };

    for (c_sources) |src| {
        libwally.addCSourceFile(.{
            .file = b.path(src),
            .flags = &c_flags,
        });
    }

    // Add include paths
    libwally.addIncludePath(b.path("."));
    libwally.addIncludePath(b.path("include"));
    libwally.addIncludePath(b.path("src"));
    libwally.addIncludePath(b.path("src/ccan"));

    // Link against user-provided secp256k1
    const secp256k1_include = b.pathJoin(&.{ secp256k1_path, "include" });
    const secp256k1_lib = b.pathJoin(&.{ secp256k1_path, "lib" });

    libwally.addIncludePath(.{ .cwd_relative = secp256k1_include });
    libwally.addLibraryPath(.{ .cwd_relative = secp256k1_lib });
    libwally.linkSystemLibrary("secp256k1");
    libwally.linkLibC();

    b.installArtifact(libwally);

    // Create the Zig wrapper module
    const mod = b.addModule("libwally_core", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    // Link the C library to the module
    mod.linkLibrary(libwally);

    // Add include paths to the module for C headers
    mod.addIncludePath(b.path("."));
    mod.addIncludePath(b.path("include"));
    mod.addIncludePath(b.path("src"));
    mod.addIncludePath(b.path("src/ccan"));
    mod.addIncludePath(.{ .cwd_relative = secp256k1_include });

    // Create an example executable
    const exe = b.addExecutable(.{
        .name = "libwally_core",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "libwally_core", .module = mod },
            },
        }),
    });

    b.installArtifact(exe);

    // Run step
    const run_step = b.step("run", "Run the example");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // Test infrastructure
    const lib_unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // Add same dependencies to tests
    lib_unit_tests.root_module.linkLibrary(libwally);
    lib_unit_tests.root_module.addIncludePath(b.path("."));
    lib_unit_tests.root_module.addIncludePath(b.path("include"));
    lib_unit_tests.root_module.addIncludePath(b.path("src"));
    lib_unit_tests.root_module.addIncludePath(b.path("src/ccan"));
    lib_unit_tests.root_module.addIncludePath(.{ .cwd_relative = secp256k1_include });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
