// zig test -freference-trace test.zig -lc -I ./
const std = @import("std");
const assert = std.debug.assert;
const c = @cImport({
    @cInclude("util.c");
    @cInclude("stdio.h");
    //@cInclude("net.c");
});
//const c = @cImport(@cInclude("util.c"));
const testing = std.testing;

test "integer overflow at compile time" {
    const x: u8 = 255;
    assert(x == 255);
    try testing.expectEqual(@as(i32, 1234), c.byteorder());
    try testing.expectEqual(@as(i32, 10), c.add(3, 7));
    _ = c.printf("Hello, C!\n");
}

test "step1" {
    //try testing.expectEqual(@as(i32, 1234), c.net_init());
    try testing.expectEqual(@as(i32, 10), c.add(3, 7));
    _ = c.printf("Hello, C!\n");
}
