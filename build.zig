const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("microps", null);
    lib.setBuildMode(mode);
    //lib.addCSourceFile("net.c", &[_][]const u8{"-std=c99"});
    lib.addCSourceFile("net.c", &[_][]const u8{""});
    lib.addCSourceFile("util.c", &[_][]const u8{""});
    lib.addCSourceFile("ip.c", &[_][]const u8{""});
    lib.addCSourceFile("udp.c", &[_][]const u8{""});
    lib.addCSourceFile("arp.c", &[_][]const u8{""});
    lib.addCSourceFile("ether.c", &[_][]const u8{""});
    lib.addCSourceFile("icmp.c", &[_][]const u8{""});
    lib.addCSourceFile("tcp.c", &[_][]const u8{""});
    lib.addCSourceFile("driver/dummy.c", &[_][]const u8{""});
    lib.addCSourceFile("driver/loopback.c", &[_][]const u8{""});
    lib.addIncludePath("./");
    lib.addCSourceFile("./platform/linux/intr.c", &[_][]const u8{""});
    lib.addCSourceFile("./platform/linux/sched.c", &[_][]const u8{""});
    lib.linkLibC(); //for stdio.h
    lib.addIncludePath("./platform/linux");
    lib.install();

    const main_tests = b.addTest("test/test.zig");
    main_tests.step.dependOn(&lib.step);
    main_tests.setBuildMode(mode);
    main_tests.linkLibrary(lib);
    main_tests.addIncludePath("./");

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}
