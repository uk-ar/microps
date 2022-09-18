#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"
#include "ip.h"

#include "driver/loopback.h"
#include "test.h"

static volatile sig_atomic_t terminate;

static void on_signal(int s)
{
    (void)s;
    terminate = 1;
}

int main(int argc, char *argv[])
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
    while (!terminate)
    { // until signal raise
        if (net_device_output(dev, NET_PROTOCOL_TYPE_IP, test_data, sizeof(test_data), NULL) == -1)
        {
            errorf("net_device_output() failure");
            break;
        }
        sleep(1);
    }
    // stop protocol stack
    net_shutdown();
    return 0;
}