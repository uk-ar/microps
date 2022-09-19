#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"

#include "driver/loopback.h"
#include "test.h"

static volatile sig_atomic_t terminate;

static void on_signal(int s)
{
    (void)s;
    terminate = 1;
}

static int setup(void)
{
    struct net_device *dev;
    signal(SIGINT, on_signal);
    // init protocol stack
    if (net_init() == -1)
    {
        errorf("net_init() failure");
        return -1;
    }
    dev = loopback_init();
    if (!dev)
    {
        errorf("loopback_init() failure");
        return -1;
    }
    struct ip_iface *iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if (!iface)
    {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1)
    {
        errorf("ip_iface_register() failure");
        return -1;
    }
    if (net_run() == -1)
    {
        errorf("net_run() failure");
        return -1;
    }
    return 0;
}
void cleanup()
{
    // stop protocol stack
    net_shutdown();
}
int main(int argc, char *argv[])
{
    if (setup() == -1)
    {
        errorf("setup() failure");
        return -1;
    }
    ip_addr_t src, dst;
    size_t offset = IP_HDR_SIZE_MIN + ICMP_HDR_SIZE;
    ip_addr_pton(LOOPBACK_IP_ADDR, &src);
    dst = src;
    uint16_t id = getpid() % UINT16_MAX;
    uint16_t seq = 0;
    (icmp_output(ICMP_TYPE_ECHO, 0, hton32(id << 16 | seq++), test_data + offset, sizeof(test_data) - offset, src, dst) == -1);
    sleep(10);
    /*while (!terminate)
    { // until signal raise
        if (icmp_output(ICMP_TYPE_ECHO, 0, hton32(id << 16 | seq++), test_data + offset, sizeof(test_data) - offset, src, dst) == -1)
        {
            errorf("ip_output() failure");
            break;
        }
        sleep(1);
    }*/
    cleanup();
    return 0;
}