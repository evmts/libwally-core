const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Build the libwally-core C library as a static library
    const libwally = b.addLibrary(.{
        .name = "wally",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
        .linkage = .static,
    });

    // Use the amalgamation build (single combined.c file)
    libwally.addCSourceFile(.{
        .file = b.path("src/amalgamation/combined.c"),
        .flags = &.{
            "-DBUILD_ELEMENTS", // Enable Elements/Liquid support
            "-DUSE_ECMULT_STATIC_PRECOMPUTATION",
            "-DECMULT_WINDOW_SIZE=15",
            "-DWALLY_CORE_BUILD",
            "-std=c99",
            "-Wno-unused-function",
        },
    });

    // Add include directories
    libwally.addIncludePath(b.path("."));           // Root dir for secp256k1 includes
    libwally.addIncludePath(b.path("include"));
    libwally.addIncludePath(b.path("src"));
    libwally.addIncludePath(b.path("src/ccan"));
    libwally.addIncludePath(b.path("src/secp256k1"));
    libwally.addIncludePath(b.path("src/secp256k1/include"));

    // Link system libraries
    libwally.linkLibC();

    // Install the library
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
    mod.addIncludePath(b.path("src/secp256k1"));
    mod.addIncludePath(b.path("src/secp256k1/include"));

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
    const mod_tests = b.addTest(.{
        .root_module = mod,
    });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}
