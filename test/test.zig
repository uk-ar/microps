// zig test -freference-trace test.zig -lc -I ./
const std = @import("std");
const c = @cImport({
    @cInclude("util.h");
    @cInclude("net.h");
    @cInclude("tcp.h");
    @cInclude("driver/dummy.h");
    @cInclude("test/test.h");
});
const testing = std.testing;

test "basic add functionality" {
    //try testing.expect(add(3, 7) == 10);
    //try testing.expect(c.byteorder() == 1234);
    try testing.expectEqual(c.hton16(10),2560);
}

test "step1"{
    try testing.expect(c.net_init()!=-1);
    const dev = c.dummy_init();
    try testing.expect(dev!=null);
    try testing.expect(c.net_run() != -1);
    try testing.expect(c.net_device_output(dev, 0x800, &c.test_data, c.test_data.len, null) != -1);
    //assert transmitted value at dummy_transmit
    try testing.expect(c.net_device_output(dev, 0x800, &c.test_data, c.test_data.len, null) != -1);
    c.net_shutdown();
}

test "step2" {
    //try testing.expectEqual(@as(i32, 1234), c.net_init());
    //try testing.expectEqual(@as(i32, 10), c.add(3, 7));
    _ = c.printf("Hello, C!\n");
}
