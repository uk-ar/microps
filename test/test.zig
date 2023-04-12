// zig test -freference-trace test.zig -lc -I ./
const std = @import("std");
const mem = @import("std").mem;
const c = @cImport({
    @cInclude("util.h");
    @cInclude("net.h");
    @cInclude("tcp.h");
    @cInclude("driver/dummy.h"); //step1
    @cInclude("driver/loopback.h"); //step2
    @cInclude("test/test.h");
    @cInclude("platform/linux/platform.h");
    @cInclude("signal.h");
    //@cInclude("string.h");
});
const testing = std.testing;

test "basic add functionality" {
    //try testing.expect(add(3, 7) == 10);
    //try testing.expect(c.byteorder() == 1234);
    try testing.expectEqual(c.hton16(10), 2560);
}
const Last = struct {
    var dev: [*c]c.struct_net_device = null;
    var data: [*c]const u8 = "";
    var d_type: u16 = 0;
    var d_len: usize = 0;
};

pub fn dummy_transmit(dev: [*c]c.struct_net_device, d_type: u16, data: [*c]const u8, len: usize, _: ?*const anyopaque) callconv(.C) c_int {
    //debugf("dev=%s,type=0x%04x,len=%zu", dev->name, type, len);
    //debugdump(data, len);
    std.debug.print("dev={s},type=0x{x},len={}\n", .{ dev.*.name, d_type, len });
    c.hexdump(c.stderr, data, len);
    //Last{  .data = data, .d_type = d_type, .d_len = len,.dev = dev };
    Last.data = data;
    Last.d_type = d_type;
    Last.d_len = len;
    Last.dev = dev;
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
    std.debug.print("irq={}\n", .{irq}); //,
    //@ptrCast(*const c.struct_net_device, @alignCast(@alignOf(c.struct_net_device),id).*) });
    return 0;
}
//const DUMMY_IRQ = c.SIGRTMIN+1;//ng
//inline
pub fn DUMMY_IRQ() c_uint {
    return @intCast(c_uint, c.__libc_current_sigrtmin() + 1);
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
        std.debug.print("net_device_register() failure", .{});
        //_ = lprintf(stderr, @as(c_int, 'E'), "driver/dummy.c", @as(c_int, 53), "dummy_init", "net_device_register() failure");
        return null;
    }
    _ = c.intr_request_irq(DUMMY_IRQ(), dummy_isr, c.INTR_IRQ_SHARED, &dev.*.name, dev);
    //_ = lprintf(stderr, @as(c_int, 'D'), "driver/dummy.c", @as(c_int, 58), "dummy_init", "initialized,dev=%s", @ptrCast([*c]u8, @alignCast(@import("std").meta.alignment([*c]u8), &dev.*.name)));
    return dev;
}
test "step2" {
    try testing.expect(c.net_init() != -1);
    const dev = dummy_init();
    try testing.expect(dev != null);
    try testing.expect(c.net_run() != -1);

    try testing.expect(c.net_device_output(dev, 0x800, &c.test_data, c.test_data.len, null) != -1);
    try testing.expect(mem.eql(u8, Last.dev.*.name[0..4 :0], "net0"));
    try testing.expectEqual(Last.d_type, 0x800);
    try testing.expectEqual(Last.d_len, 48);
    try testing.expect(mem.eql(u8, Last.data[28..38], "1234567890"));
    std.time.sleep(1);

    try testing.expect(c.net_device_output(dev, 0x800, &c.test_data, c.test_data.len, null) != -1);
    try testing.expect(mem.eql(u8, Last.dev.*.name[0..4 :0], "net0"));
    try testing.expectEqual(Last.d_type, 0x800);
    try testing.expectEqual(Last.d_len, 48);
    try testing.expect(mem.eql(u8, Last.data[28..38], "1234567890"));
    c.net_shutdown();
    c.ip_shutdown();
}
//comptime {
//    _ = @import("test2.zig");
// And all other files
//}

test "step3" {
    try testing.expect(c.net_init() != -1);
    const dev = c.loopback_init();
    try testing.expect(dev != null);
    try testing.expect(c.net_run() != -1);

    try testing.expect(c.net_device_output(dev, 0x800, &c.test_data, c.test_data.len, null) != -1);
    //try testing.expect(mem.eql(u8, Last.dev.*.name[0..4 :0], "net0"));
    //try testing.expectEqual(Last.d_type, 0x800);
    //try testing.expectEqual(Last.d_len, 48);
    //try testing.expect(mem.eql(u8, Last.data[28..38], "1234567890"));
    //TODO: assert ループバックデバイスがハードウェア割り込みにより net_input_handler を呼び出すこと
    std.time.sleep(1);

    try testing.expect(c.net_device_output(dev, 0x800, &c.test_data, c.test_data.len, null) != -1);
    //try testing.expect(mem.eql(u8, Last.dev.*.name[0..4 :0], "net0"));
    //try testing.expectEqual(Last.d_type, 0x800);
    //try testing.expectEqual(Last.d_len, 48);
    //try testing.expect(mem.eql(u8, Last.data[28..38], "1234567890"));
    c.net_shutdown();

    //_ = c.printf("Hello, C!\n");
}

test "step4" {
    try testing.expect(c.net_init() != -1);
    const dev = c.loopback_init();
    try testing.expect(dev != null);
    try testing.expect(c.net_run() != -1);

    try testing.expect(c.net_device_output(dev, c.NET_PROTOCOL_TYPE_IP, &c.test_data, c.test_data.len, null) != -1);
    //try testing.expect(mem.eql(u8, Last.dev.*.name[0..4 :0], "net0"));
    //try testing.expectEqual(Last.d_type, 0x800);
    //try testing.expectEqual(Last.d_len, 48);
    //try testing.expect(mem.eql(u8, Last.data[28..38], "1234567890"));
    //TODO: assert net_input_handler がメッセージをIPキューに積むこと
    std.time.sleep(1);

    try testing.expect(c.net_device_output(dev, c.NET_PROTOCOL_TYPE_IP, &c.test_data, c.test_data.len, null) != -1);
    //try testing.expect(mem.eql(u8, Last.dev.*.name[0..4 :0], "net0"));
    //try testing.expectEqual(Last.d_type, 0x800);
    //try testing.expectEqual(Last.d_len, 48);
    //try testing.expect(mem.eql(u8, Last.data[28..38], "1234567890"));
    c.net_shutdown();

    //_ = c.printf("Hello, C!\n");
}

test "step5" {
    try testing.expect(c.net_init() != -1);
    const dev = c.loopback_init();
    try testing.expect(dev != null);
    try testing.expect(c.net_run() != -1);

    try testing.expect(c.net_device_output(dev, c.NET_PROTOCOL_TYPE_IP, &c.test_data, c.test_data.len, null) != -1);
    //try testing.expect(mem.eql(u8, Last.dev.*.name[0..4 :0], "net0"));
    //try testing.expectEqual(Last.d_type, 0x800);
    //try testing.expectEqual(Last.d_len, 48);
    //try testing.expect(mem.eql(u8, Last.data[28..38], "1234567890"));
    //TODO: assert net_input_handler がメッセージをIPキューに積むこと(ネットワークドライバー内のtop half)
    //TODO: assert ソフト割り込みで ip_inputが呼ばれること(ネットワークドライバー内のbottom half)
    std.time.sleep(1);

    try testing.expect(c.net_device_output(dev, c.NET_PROTOCOL_TYPE_IP, &c.test_data, c.test_data.len, null) != -1);
    //try testing.expect(mem.eql(u8, Last.dev.*.name[0..4 :0], "net0"));
    //try testing.expectEqual(Last.d_type, 0x800);
    //try testing.expectEqual(Last.d_len, 48);
    //try testing.expect(mem.eql(u8, Last.data[28..38], "1234567890"));
    c.net_shutdown();

    //_ = c.printf("Hello, C!\n");
}

test "step6" {
    try testing.expect(c.net_init() != -1);
    const dev = c.loopback_init();
    try testing.expect(dev != null);
    try testing.expect(c.net_run() != -1);

    try testing.expect(c.net_device_output(dev, c.NET_PROTOCOL_TYPE_IP, &c.test_data, c.test_data.len, null) != -1);
    //try testing.expect(mem.eql(u8, Last.dev.*.name[0..4 :0], "net0"));
    //try testing.expectEqual(Last.d_type, 0x800);
    //try testing.expectEqual(Last.d_len, 48);
    //try testing.expect(mem.eql(u8, Last.data[28..38], "1234567890"));
    //TODO: assert ソフト割り込みで ip_inputが呼ばれること(ネットワークドライバー内のbottom half)
    //TODO: ip_inputで受信したデータが以下 v:4 hl:5 tos:0x00 total:48 id:128 offset 0x0000 
    //      ttl:255 protocol:1 sum 0xbd4a src 127.0.0.1 dst:127.0.0.1
    std.time.sleep(1);

    try testing.expect(c.net_device_output(dev, c.NET_PROTOCOL_TYPE_IP, &c.test_data, c.test_data.len, null) != -1);
    //try testing.expect(mem.eql(u8, Last.dev.*.name[0..4 :0], "net0"));
    //try testing.expectEqual(Last.d_type, 0x800);
    //try testing.expectEqual(Last.d_len, 48);
    //try testing.expect(mem.eql(u8, Last.data[28..38], "1234567890"));
    c.net_shutdown();

    //_ = c.printf("Hello, C!\n");
}
