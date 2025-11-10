const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Create the Zig wrapper module
    // Users must provide libwally-core via system linkage or build options
    const mod = b.addModule("libwally_core", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    // Link against system libwally-core
    // Users can override with: -Dlibwally-path=/custom/path
    const libwally_path = b.option([]const u8, "libwally-path", "Path to libwally-core installation") orelse "/usr/local";

    // Add include paths for C headers
    const include_path = b.pathJoin(&.{ libwally_path, "include" });
    mod.addIncludePath(.{ .cwd_relative = include_path });

    // Link the library
    mod.linkSystemLibrary("wallycore", .{});
    mod.linkLibC();

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
    lib_unit_tests.root_module.addIncludePath(.{ .cwd_relative = include_path });
    lib_unit_tests.root_module.linkSystemLibrary("wallycore", .{});
    lib_unit_tests.root_module.linkLibC();

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
