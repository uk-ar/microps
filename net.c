#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "arp.h"

struct net_protocol
{
    struct net_protocol *next;
    net_protocol type;
    struct queue_head queue; // each protocol has its own queue
    void (*handler)(const uint8_t *data, size_t len, struct net_device *dev);
};

struct net_protocol_queue_entry
{
    struct net_device *dev;
    size_t len;
    uint8_t data[]; // flex
};

/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */
static struct net_device *devices;
static struct net_protocol *protocols;

struct net_device *net_device_alloc(void)
{
    struct net_device *dev = memory_alloc(sizeof(struct net_device));
    if (!dev)
    {
        errorf("memory_alloc() failure");
        return NULL;
    }
    return dev;
}

/* NOT: must not be call after net_run() */
int net_device_register(struct net_device *dev)
{
    static unsigned int index = 0;
    dev->index = index++;
    snprintf(dev->name, sizeof(dev->name), "net%d", dev->index);
    dev->next = devices;
    devices = dev;
    infof("registered, dev=%s,type=0x%04x", dev->name, dev->type);
    return 0;
}

static int net_device_open(struct net_device *dev)
{
    if (NET_DEVICE_IS_UP(dev))
    {
        errorf("already opened,dev=%s", dev->name);
        return -1;
    }
    if (dev->ops->open)
    {
        if (dev->ops->open(dev) == -1)
        {
            errorf("open failure,dev=%s", dev->name);
            return -1;
        }
    }
    dev->flags |= NET_DEVICE_FLAG_UP;
    infof("dev=%s,state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

static int net_device_close(struct net_device *dev)
{
    if (!NET_DEVICE_IS_UP(dev))
    {
        errorf("not opened,dev=%s", dev->name);
        return -1;
    }
    if (dev->ops->close)
    {
        if (dev->ops->close(dev) == -1)
        {
            errorf("close failure,dev=%s", dev->name);
            return -1;
        }
    }
    dev->flags &= ~NET_DEVICE_FLAG_UP;
    infof("dev=%s,state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

/* NOTE: must not be call after net_run() */
int net_device_add_iface(struct net_device *dev, struct net_iface *iface)
{
    // TODO: use net_device_get_iface
    if (net_device_get_iface(dev, iface->family))
    {
        errorf("[limitation] device cannot handle the same family iface");
        return -1;
    }
    iface->dev = dev;
    iface->next = dev->ifaces;
    dev->ifaces = iface;
    return 0;
}

struct net_iface *net_device_get_iface(struct net_device *dev, int family)
{
    for (struct net_iface *iface = dev->ifaces; iface; iface = iface->next)
    {
        if (iface->family == family)
            return iface;
    }
    return NULL;
}

int net_device_output(struct net_device *dev, uint16_t proto_type, const uint8_t *data, size_t len, const void *dst)
{
    if (!NET_DEVICE_IS_UP(dev))
    {
        errorf("not opened,dev=%s", dev->name);
        return -1;
    }
    if (len > dev->mtu)
    {
        errorf("too long,dev=%s,mtu=%u,len=%zu", dev->name, dev->mtu, len);
        return -1;
    }
    debugf("dev=%s,proto_type=0x%04x,len=%zu", dev->name, proto_type, len);
    debugdump(data, len);
    if (dev->ops->transmit(dev, proto_type, data, len, dst) == -1)
    {
        errorf("device transmit failure,dev=%s,len=%zu", dev->name, len);
        return -1;
    }
    return 0;
}

/* NOT: must not be call after net_run() */
int net_protocol_register(uint16_t proto_type,
                          void (*handler)(const uint8_t *data, size_t len, struct net_device *dev))
{
    for (struct net_protocol *proto = protocols; proto; proto = proto->next)
    {
        if (proto->type == proto_type)
        {
            errorf("already registered,proto_type=0x%04x", proto_type);
            return -1;
        }
    }
    struct net_protocol *protocol = memory_alloc(sizeof(struct net_protocol));
    if (!protocol)
    {
        errorf("memory_alloc() failure");
        return -1;
    }
    protocol->handler = handler;
    protocol->type = proto_type;
    queue_init(&protocol->queue);
    protocol->next = protocols;
    protocols = protocol;
    infof("protocol registered,proto_type=0x%04x", proto_type);
    return 0;
}

int net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{
    debugf("dev=%s,type=0x%04x,len=%zu", dev->name, type, len);
    debugdump(data, len);
    for (struct net_protocol *proto = protocols; proto; proto = proto->next)
    {
        if (type != proto->type)
            continue;
        struct net_protocol_queue_entry *entry = memory_alloc(sizeof(struct net_protocol_queue_entry) + len);
        if (!entry)
        {
            errorf("memory_alloc() failure");
            return -1;
        }
        entry->len = len;
        entry->dev = dev;
        memcpy(entry->data, data, len);
        if (!queue_push(&proto->queue, entry))
        {
            errorf("queue_push failure");
            return -1;
        }
        intr_raise_irq(INTR_IRQ_SOFTIRQ);
        debugf("queue pushed (num:%u),dev=%s,type=0x%04x,len=%zu", proto->queue.num, dev->name, type, len);
        debugdump(entry->data, len);
        return 0;
    }
    /* unsupported */
    return 0;
}

int net_softirq_handler(void)
{
    for (struct net_protocol *proto = protocols; proto; proto = proto->next)
    {
        while (proto->queue.num)
        {
            struct net_protocol_queue_entry *entry = queue_pop(&proto->queue);
            if (proto->handler)
                proto->handler(entry->data, entry->len, entry->dev);
            debugf("queue poped (num:%u),dev=%s,type=0x%04x,len=%zu", proto->queue.num, entry->dev->name, proto->type, entry->len);
            debugdump(entry->data, entry->len);
            memory_free(entry);
        }
    }
    return 0;
}

int net_run(void)
{
    struct net_device *dev;

    if (intr_run() == -1)
    {
        errorf("intr_run() failure");
        return -1;
    }
    debugf("open all devices...");
    for (dev = devices; dev; dev = dev->next)
    {
        net_device_open(dev);
    }
    debugf("running ..");
    return 0;
}

void net_shutdown(void)
{
    struct net_device *dev;

    debugf("close all devices...");
    for (dev = devices; dev; dev = dev->next)
    {
        net_device_close(dev);
    }
    intr_shutdown();
    debugf("shutting down");
}
// 1. net_init
// 2. net_run
// 3. net_shutdown
int net_init(void)
{
    if (intr_init() == -1)
    {
        errorf("intr_init() failure");
        return -1;
    }
    if (arp_init() == -1)
    {
        errorf("arp_init() failure");
        return -1;
    }
    if (ip_init() == -1)
    {
        errorf("ip_init() failure");
        return -1;
    }
    if (icmp_init() == -1)
    {
        errorf("icmp_init() failure");
        return -1;
    }
    infof("initialized");
    return 0;
}