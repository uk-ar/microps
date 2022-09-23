#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "platform.h"

#include "util.h"
#include "ip.h"
#include "udp.h"

#define UDP_PCB_SIZE 16

#define UDP_PCB_STATE_FREE 0
#define UDP_PCB_STATE_OPEN 1
#define UDP_PCB_STATE_CLOSING 2

struct pseudo_hdr
{
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

struct udp_hdr
{
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t sum;
};

struct udp_pcb
{
    int state;
    struct ip_endpoint local;
    struct queue_head queue; /* recieve queue */
};

struct udp_queue_entry
{
    struct ip_endpoint foreign;
    uint16_t len;
    uint8_t data[];
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct udp_pcb pcbs[UDP_PCB_SIZE];

static void
udp_dump(const uint8_t *data, size_t len)
{
    struct udp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct udp_hdr *)data;
    fprintf(stderr, "    src:%u\n", ntoh16(hdr->src));
    fprintf(stderr, "    dst:%u\n", ntoh16(hdr->dst));
    fprintf(stderr, "    len:%u\n", ntoh16(hdr->len));
    fprintf(stderr, "    sum:0x%04x\n", ntoh16(hdr->sum));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/*
    UDP Protocol Control Block(PCB)
    NOTE: UDP PCB functions must be called after mutex locked
*/

static struct udp_pcb *udp_pcb_alloc(void)
{
    struct udp_pcb *pcb;
    for (pcb = pcbs; pcb<tailof(pcbs); pcb++)
    {
        if (pcb->state == UDP_PCB_STATE_FREE)
        {
            pcb->state = UDP_PCB_STATE_OPEN;
            return pcb;
        }
    }
    return NULL;
}

static void udp_pcb_release(struct udp_pcb *pcb)
{
    pcb->state = UDP_PCB_STATE_FREE;
    pcb->local.addr = IP_ADDR_ANY;
    pcb->local.port = 0;

    struct query_entry *entry;
    while (1)
    {
        /* Discard the entries in the queue */
        entry = queue_pop(&pcb->queue);
        if (!entry)
            break;
        memory_free(entry);
    }
}

static struct udp_pcb *udp_pcb_select(ip_addr_t addr, uint16_t port)
{
    struct udp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        if (pcb->state == UDP_PCB_STATE_OPEN)
        {
            if ((pcb->local.addr == IP_ADDR_ANY || addr == IP_ADDR_ANY || pcb->local.addr == addr) &&
                pcb->local.port == port)
            {
                return pcb;
            }
        }
    }
    return NULL;
}

static struct udp_pcb *udp_pcb_get(int id)
{
    struct udp_pcb *pcb;
    if (id < 0 || id >= (int)countof(pcbs))
    {
        return NULL;
    }
    pcb = &pcbs[id];
    if (pcb->state != UDP_PCB_STATE_OPEN)
        return NULL;
    return pcb;
}

static int udp_pcb_id(struct udp_pcb *pcb)
{
    return indexof(pcbs, pcb);
}

static void udp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst,
                      struct ip_iface *iface)
{
    struct pseudo_hdr psuedo;
    uint16_t psum = 0;
    struct udp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    if (len < sizeof(*hdr))
    {
        errorf("too short");
        return;
    }
    hdr = (struct udp_hdr *)data;
    if (len != ntoh16(hdr->len))
    {
        errorf("lenght error: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
        return;
    }
    psuedo.src = src;
    psuedo.dst = dst;
    psuedo.zero = 0;
    psuedo.protocol = IP_PROTOCOL_UDP;
    psuedo.len = hton16(len);
    psum = ~cksum16((uint16_t *)&psuedo, sizeof(psuedo), 0);
    if (cksum16((uint16_t *)hdr, len, psum) != 0)
    {
        errorf("checksum error: sum=0x%04x,veryfy=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }
    debugf("%s:%d=>%s:%d, len=%zu (payload=%zu)",
           ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
           ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
           len, len - sizeof(*hdr));
    udp_dump(data, len);

    mutex_lock(&mutex); // protect pcb
    struct udp_pcb *pcb = udp_pcb_select(dst, hdr->dst);
    if (!pcb)
    {
        // port is not in use
        mutex_unlock(&mutex);
        return;
        // There is no application, using this port
    }

    struct udp_queue_entry *entry = memory_alloc(sizeof(*entry));
    if (!entry)
    {
        mutex_unlock(&mutex);
        return;
    }
    entry->foreign.addr = dst;
    entry->foreign.port = hdr->dst;
    entry->len = len;
    memcpy(entry->data, data, len);
    queue_push(&pcb->queue, entry);

    debugf("queue pushed: id=%d, num=%d", udp_pcb_id(pcb), pcb->queue.num);
    mutex_unlock(&mutex);
}

ssize_t udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, const uint8_t *data, size_t len)
{
    uint8_t buf[IP_PAYLOAD_SIZE_MAX];
    struct udp_hdr *hdr;
    struct pseudo_hdr psuedo;
    uint16_t total, psum = 0;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    if (len > IP_PAYLOAD_SIZE_MAX - sizeof(*hdr))
    {
        errorf("too long");
        return -1;
    }
    hdr = (struct udp_hdr *)buf;

    psuedo.src = src->addr;
    psuedo.dst = dst->addr;
    psuedo.zero = 0;
    psuedo.protocol = IP_PROTOCOL_UDP;
    psuedo.len = hton16(sizeof(*hdr) + len);
    psum = ~cksum16((uint16_t *)&psuedo, sizeof(psuedo), 0);

    hdr->dst = dst->port;
    hdr->src = src->port;
    hdr->len = hton16(sizeof(*hdr) + len); // udp len = hdr+data len
    total = sizeof(*hdr) + len;
    int offset = sizeof(*hdr);
    memcpy(buf + offset, data, len); // hdr+offset cause problem

    hdr->sum = 0;
    hdr->sum = cksum16((uint16_t *)hdr, total, psum);

    debugf("%s=>%s, len=%zu (payload=%zu)\n",
           ip_endpoint_ntop(src, ep1, sizeof(ep1)),
           ip_endpoint_ntop(dst, ep2, sizeof(ep2)),
           total, len);
    udp_dump((uint8_t *)hdr, total);
    ip_output(IP_PROTOCOL_UDP, buf, total, psuedo.src, psuedo.dst);
    return len;
}

int udp_init(void)
{
    ip_protocol_register(IP_PROTOCOL_UDP, udp_input);
    return 0;
}

/*
    UDP User Commands
*/

int udp_open(void)
{
    struct udp_pcb *pcb = udp_pcb_alloc();
    if (!pcb)
    {
        return -1;
    }
    return udp_pcb_id(pcb);
}
int udp_close(int id)
{
    struct udp_pcb *pcb = udp_pcb_get(id);
    if (pcb == NULL)
        return -1;
    udp_pcb_release(pcb);
    return 0;
}
int udp_bind(int id, struct ip_endpoint *local)
{
    struct udp_pcb *pcb, *exist;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    mutex_lock(&mutex);

    pcb = udp_pcb_get(id);
    if(!pcb){
        errorf("udp_pcb_get() failure");
        return -1;
    }
    exist = udp_pcb_select(local->addr, local->port);
    if(exist){
        // addr & port already used
        mutex_unlock(&mutex);
        return -1;
    }
    pcb->local = *local;

    debugf("bound, id=%d, local=%s", id, ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)));
    mutex_unlock(&mutex);
    return 0;
}
