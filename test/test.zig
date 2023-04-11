// zig test -freference-trace test.zig -lc -I ./
const std = @import("std");
const c = @cImport({
    @cInclude("util.h");
    @cInclude("net.h");
    @cInclude("tcp.h");
    @cInclude("driver/dummy.h");
    @cInclude("test/test.h");
    @cInclude("platform/linux/platform.h");
    @cInclude("signal.h");
});
const testing = std.testing;

test "basic add functionality" {
    //try testing.expect(add(3, 7) == 10);
    //try testing.expect(c.byteorder() == 1234);
    try testing.expectEqual(c.hton16(10), 2560);
}
pub fn dummy_transmit(dev: [*c]c.struct_net_device, d_type: u16, _: [*c]const u8, len: usize, _: ?*const anyopaque) callconv(.C) c_int {
    //debugf("dev=%s,type=0x%04x,len=%zu", dev->name, type, len);
    //debugdump(data, len);
    std.debug.print("dev={s},type=0x{x},len={}\n", .{ dev.*.name, d_type, len });
    _ = c.intr_raise_irq(DUMMY_IRQ());
    return 0;
}
pub var dummy_ops: c.struct_net_device_ops = c.struct_net_device_ops{
    .open = null,
    .close = null,
    .transmit = &dummy_transmit,
};
pub fn dummy_isr(irq: c_uint, _: ?*anyopaque) callconv(.C) c_int {
    //_ = lprintf(stderr, @as(c_int, 'D'), "driver/dummy.c", @as(c_int, 29), "dummy_isr", "irq=%u,dev=%s", irq, @ptrCast([*c]u8, @alignCast(@import("std").meta.alignment([*c]u8), &@ptrCast([*c]struct_net_device, @alignCast(@import("std").meta.alignment([*c]struct_net_device), id)).*.name)));
    //debugf("irq=%u,dev=%s", irq, ((struct net_device *)id)->name);
    std.debug.print("irq={}\n", .{irq});//, 
    //@ptrCast(*const c.struct_net_device, @alignCast(@alignOf(c.struct_net_device),id).*) });
    return 0;
}
//const DUMMY_IRQ = c.SIGRTMIN+1;//ng
pub fn DUMMY_IRQ() c_uint {
    return @intCast(c_uint,c.__libc_current_sigrtmin() + 1);
}
pub export fn dummy_init() [*c]c.struct_net_device {
    var dev: [*c]c.struct_net_device = undefined;
    dev = c.net_device_alloc();
    if (!(dev != null)) {
        //_ = lprintf(stderr, @as(c_int, 'E'), "driver/dummy.c", @as(c_int, 43), "dummy_init", "net_device_alloc() failure");
        return null;
    }
    dev.*.type = c.NET_DEVICE_TYPE_DUMMY;
    dev.*.mtu = 65535;
    dev.*.hlen = 0;
    dev.*.alen = 0;
    dev.*.ops = &dummy_ops;
    if (c.net_device_register(dev) == -1) {
        std.debug.print("net_device_register() failure",.{});
        //_ = lprintf(stderr, @as(c_int, 'E'), "driver/dummy.c", @as(c_int, 53), "dummy_init", "net_device_register() failure");
        return null;
    }
    _ = c.intr_request_irq(DUMMY_IRQ(), dummy_isr, c.INTR_IRQ_SHARED, &dev.*.name, dev);
    //_ = lprintf(stderr, @as(c_int, 'D'), "driver/dummy.c", @as(c_int, 58), "dummy_init", "initialized,dev=%s", @ptrCast([*c]u8, @alignCast(@import("std").meta.alignment([*c]u8), &dev.*.name)));
    return dev;
}
test "step1" {
    try testing.expect(c.net_init() != -1);
    const dev = dummy_init();
    try testing.expect(dev != null);
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
