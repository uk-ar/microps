#ifndef ARP_H
#define ARP_H

#include <stdint.h>

#include "net.h"
#include "ip.h"

#define ARP_RESOLVER_ERROR -1
#define ARP_RESOLVER_INCOMPLETE 0
#define ARP_RESOLVER_FOUNT 1

extern int arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha);

extern int arp_init(void);

#endif