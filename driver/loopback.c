#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"

#define LOOPBACK_MTU UINT16_MAX
#define LOOPBACK_QUEUE_LIMIT 16
#define LOOPBACK_IRQ (INTR_IRQ_BASE + 1)

#define PRIV(x) ((struct loopback *)x->priv)

struct loopback
{
    int irq;
    mutex_t mutex;
    struct queue_head queue;
};

struct loopback_queue_entry
{
    uint16_t type;
    size_t len;
    uint8_t data[]; /* flexible array member */
};

static int loopback_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    // add_queue
    // struct loopback *loopback = PRIV(dev);//shared resource
    mutex_lock(&PRIV(dev)->mutex);
    if (PRIV(dev)->queue.num==LOOPBACK_QUEUE_LIMIT)
    {
        mutex_unlock(&PRIV(dev)->mutex);
        errorf("mutex_lock() failure");
        return -1;
    }
    struct loopback_queue_entry *entry = memory_alloc(sizeof(struct loopback_queue_entry) + len);
    if (!entry)
    {
        mutex_unlock(&PRIV(dev)->mutex);
        errorf("memory_alloc() failure");
        return -1;
    }
    entry->len = len;
    entry->type = type;
    memcpy(entry->data, data, len);

    queue_push(&(PRIV(dev)->queue), entry);    
    mutex_unlock(&(PRIV(dev)->mutex)); // timing
    int num = PRIV(dev)->queue.num;
    debugf("queue pushed(num=%u),dev=%s,type=0x%04x,len=%zu",num, dev->name, type, len);
    debugdump(entry->data, entry->len);

    intr_raise_irq(LOOPBACK_IRQ);

    return 0;
}

static int loopback_isr(unsigned int irq, void *id)
{
    struct net_device *dev = (struct net_device *)id;
    mutex_lock(&PRIV(dev)->mutex);
    while (PRIV(dev)->queue.num){
        struct loopback_queue_entry *entry = queue_pop(&(PRIV(dev)->queue));
        debugf("queue poped(num:%u),irq=%u,dev=%s", PRIV(dev)->queue.num, irq, dev->name);
        debugdump(entry->data, entry->len);
        net_input_handler(entry->type, entry->data, entry->len, dev);
        memory_free(entry);
    }
    mutex_unlock(&PRIV(dev)->mutex);
    return 0;
}

static struct net_device_ops loopback_ops = {
    .transmit = loopback_transmit,
};

struct net_device *loopback_init(void)
{
    struct loopback *loopback = memory_alloc(sizeof(struct loopback));
    if (!loopback)
    {
        errorf("memory_alloc() failure");
        return NULL;
    }
    loopback->irq = LOOPBACK_IRQ;
    queue_init(&(loopback->queue));
    mutex_init(&(loopback->mutex));//always return 0

    struct net_device *dev;
    dev = net_device_alloc();
    if (!dev)
    {
        errorf("net_device_alloc() failure");
        return NULL;
    }
    dev->type = NET_DEVICE_TYPE_LOOPBACK;
    dev->mtu = LOOPBACK_MTU;
    dev->hlen = 0;
    dev->alen = 0;
    dev->flags |= NET_DEVICE_FLAG_LOOPBACK;
    dev->ops = &loopback_ops;
    dev->priv = loopback;
    if (net_device_register(dev) == -1)
    {
        errorf("net_device_register() failure");
        return NULL;
    }
    intr_request_irq(LOOPBACK_IRQ, loopback_isr, INTR_IRQ_SHARED, dev->name, dev);
    debugf("initialized,dev=%s", dev->name);
    return dev;
}
