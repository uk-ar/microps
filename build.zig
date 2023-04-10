const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    //const lib = b.addStaticLibrary("microps", "test/test.zig");
    const lib = b.addStaticLibrary("microps", null);
    lib.linkSystemLibrary("c");
    lib.linkLibC();
    lib.addIncludePath("./");
    lib.addCSourceFile("util.c", &[_][]const u8{""});
    lib.setBuildMode(mode);

    lib.install();

    const main_tests = b.addTest("test/test.zig");
    main_tests.addIncludePath("./");
    main_tests.linkSystemLibrary("c");
    main_tests.linkLibrary(lib);
    //main_tests.linkSystemLibrary("microps");
    main_tests.linkLibC();
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}