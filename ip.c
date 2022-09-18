#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"

struct ip_hdr
{
    uint8_t vhl;    // version & IP header length
    uint8_t tos;    // type of service
    uint16_t total; // total length
    uint16_t id;
    uint16_t offset; // flag & offset?
    uint8_t ttl;
    uint8_t protocol;
    uint16_t sum; // checksum
    ip_addr_t src;
    ip_addr_t dst;
    uint8_t options[]; // flex
};

const ip_addr_t IP_ADDR_ANY = 0x00000000;       /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */

/* NOTE: if you want to add/delete the entries after net_run(),
you need to protect these lists with a mutex */
static struct ip_iface *ifaces;

int ip_addr_pton(const char *p, ip_addr_t *n)
{
    // convert ip from p string to n ip_addr_t
    char *sp, *ep;
    int idx;
    long ret;
    sp = (char *)p;
    for (idx = 0; idx < 4; idx++)
    {
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255)
        {
            return -1;
        }
        if (ep == sp)
        {
            return -1;
        }
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.'))
        {
            return -1;
        }
        ((uint8_t *)n)[idx] = ret;
        sp = ep + 1;
    }
    return 0;
}

char *ip_addr_ntop(ip_addr_t n, char *p, size_t size)
{
    // convert ip from n ip_addr to p string
    uint8_t *u8;

    u8 = (uint8_t *)&n;
    snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
    return p;
}

static void ip_dump(const uint8_t *data, size_t len)
{
    flockfile(stderr);
    struct ip_hdr *hdr = (struct ip_hdr *)data;
    uint8_t v = (hdr->vhl) >> 4;
    uint8_t hl = (hdr->vhl) & 0x0f; // 4byte unit
    char addr[IP_ADDR_STR_LEN];

    uint16_t hlen = hl << 2; // bit
    fprintf(stderr, " vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, v, hl, hlen);
    fprintf(stderr, " tos: 0x%02x\n", hdr->tos);
    uint16_t total = ntoh16(hdr->total);
    fprintf(stderr, " total: %u (payload: %u)\n", total, total - hlen);
    fprintf(stderr, " id: %u\n", ntoh16(hdr->id));
    uint16_t offset = ntoh16(hdr->offset);
    fprintf(stderr, " offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff);
    fprintf(stderr, " ttl: %u\n", hdr->ttl);
    fprintf(stderr, " protocol: %u\n", hdr->protocol);
    fprintf(stderr, " sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, " src: %s\n", ip_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, " dst: %s\n", ip_addr_ntop(hdr->dst, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

struct ip_iface *ip_iface_alloc(const char *unicast, const char *netmask)
{
    struct ip_iface *iface = memory_alloc(sizeof(struct ip_iface));
    if (!iface)
    {
        errorf("memory_alloc() failure");
        return NULL;
    }
    // up cast
    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IP;

    if (ip_addr_pton(unicast, &iface->unicast) == -1)
    {
        errorf("ip_addr_pton(unicast) failure");
        memory_free(iface);
        return NULL;
    }
    if (ip_addr_pton(netmask, &iface->netmask) == -1)
    {
        errorf("ip_add_pton(netmask) failure");
        memory_free(iface);
        return NULL;
    }
    iface->broadcast = (iface->unicast & iface->netmask) | ~(iface->netmask);
    return iface;
}

/* NOTE: must not call after net_run() */
int ip_iface_register(struct net_device *dev, struct ip_iface *iface)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];

    if (net_device_add_iface(dev, NET_IFACE(iface)) == -1)
    {
        errorf("net_device_add_iface() failure");
        return -1;
    }
    iface->next = ifaces;
    ifaces = iface;

    infof("registered: dev=%s, unicast=%s,netmask=%s,broadcast=%s", dev->name,
          ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
          ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)),
          ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3)));

    return 0;
    // dev->ifaces
}

// when recieve packet select if from dest address
struct ip_iface *ip_iface_select(ip_addr_t addr)
{
    for (struct ip_iface *iface = ifaces; iface; iface = iface->next)
    {
        if (iface->unicast == addr)
        {
            return iface;
        }
    }
    return NULL;
}

static void
ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    if (len < IP_HDR_SIZE_MIN)
    {
        errorf("too short");
        return;
    }
    struct ip_hdr *hdr = (struct ip_hdr *)data;
    uint8_t v = (hdr->vhl) >> 4;
    if (v != IP_VERSION_IPV4)
    {
        errorf("ip version mismatch");
        return;
    }
    uint8_t hl = (hdr->vhl) & 0x0f; // 4byte unit
    uint16_t hlen = hl << 2;        // byte
    uint16_t total = ntoh16(hdr->total);
    if (len < hlen || len < total)
    {
        errorf("too short");
        return;
    }
    uint16_t sum = cksum16((uint16_t *)hdr, hlen, 0);
    if (sum != 0)
    {
        errorf("checksum mismatch,exp:0x%04x,act:0x%04x,cnt=%u", hdr->sum, sum, hlen);
        return;
    }
    uint16_t offset = ntoh16(hdr->offset);
    if (offset & 0x2000 || offset & 0x1fff)
    {
        errorf("fragment does not support");
        return;
    }

    struct ip_iface *iface = (struct ip_iface *)
        net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (hdr->dst != iface->unicast && hdr->dst != IP_ADDR_BROADCAST &&
        hdr->dst != iface->broadcast)
        return;

    char addr[IP_ADDR_STR_LEN];
    debugf("dev=%s,iface=%s,protocol=%u,total=%zu", dev->name,
           ip_addr_ntop(iface->unicast, addr, sizeof(addr)), hdr->protocol, len, total);

    ip_dump(data, total);
}

int ip_init(void)
{
    if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input))
    {
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}