#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "util.h"
#include "ip.h"
#include "icmp.h"

#define ICMP_BUFSIZ IP_PAYLOAD_SIZE_MAX

struct icmp_hdr
{
    uint8_t type;
    uint8_t code;
    uint16_t sum;
    uint32_t values;
};

struct icmp_echo
{
    uint8_t type;
    uint8_t code;
    uint16_t sum;
    uint16_t id;
    uint16_t seq;
};

static char *icmp_type_ntoa(uint8_t type)
{
    switch (type)
    {
    case ICMP_TYPE_ECHOREPLY:
        return "EchoReply";
    case ICMP_TYPE_DEST_UNREACH:
        return "DesticationUnreachable";
    case ICMP_TYPE_SOURCE_QENCH:
        return "SourceQuench";
    case ICMP_TYPE_REDIRECT:
        return "Redirect";
    case ICMP_TYPE_ECHO:
        return "Echo";
    case ICMP_TYPE_TIME_EXCEEDED:
        return "TimeExceeded";
    case ICMP_TYPE_PARAM_PROBLEM:
        return "ParameterProblem";
    case ICMP_TYPE_TIMESTAMP:
        return "Timestamp";
    case ICMP_TYPE_TIMESTAMPREPLY:
        return "TimestampReply";
    case ICMP_TYPE_INFO_REQUEST:
        return "InformationRequest";
    case ICMP_TYPE_INFO_REPLY:
        return "InformationReply";
    }
    return "Unknown";
}

static void icmp_dump(const uint8_t *data, size_t len)
{
    flockfile(stderr);
    struct icmp_hdr *hdr = (struct icmp_hdr *)data;
    fprintf(stderr, " type: %u (%s)\n", hdr->type, icmp_type_ntoa(hdr->type));
    fprintf(stderr, " code: %u\n", hdr->code);
    fprintf(stderr, "  sum: 0x%04x\n", ntoh16(hdr->sum));
    struct icmp_echo *echo;
    switch (hdr->type)
    {
    case ICMP_TYPE_ECHO:
    case ICMP_TYPE_ECHOREPLY:
        echo = (struct icmp_echo *)hdr;
        fprintf(stderr, "  id: %u\n", ntoh16(echo->id));
        fprintf(stderr, " seq: %u\n", ntoh16(echo->seq));
        break;
    default:
        fprintf(stderr, " values: 0x%08x\n", ntoh32(hdr->values));
        break;
    }
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

void icmp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    if (len < ICMP_HDR_SIZE)
    {
        errorf("too short");
        return;
    }
    struct icmp_hdr *hdr = (struct icmp_hdr *)data;
    uint16_t sum = cksum16((uint16_t *)hdr, len, 0);
    if (sum != 0)
    {
        errorf("checksum mismatch,exp0x%04x,act:0x%04x,cnt=%u", hdr->sum, sum, len);
        return;
    }
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    debugf("%s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)),
           ip_addr_ntop(dst, addr2, sizeof(addr2)), len);
    icmp_dump(data, len);
    switch (hdr->type)
    {
    case ICMP_TYPE_ECHO:
        icmp_output(ICMP_TYPE_ECHOREPLY, 0, hdr->values, (const uint8_t *)hdr + ICMP_HDR_SIZE, len, iface->unicast, src);
        break;
    default:
        break;
    }
}

int icmp_output(uint8_t type, uint8_t code, uint32_t values, const uint8_t *data, size_t len, ip_addr_t src,
                ip_addr_t dst)
{
    uint8_t buf[ICMP_BUFSIZ];
    struct icmp_hdr *hdr = (struct icmp_hdr *)buf;
    hdr->type = type;
    hdr->code = code;
    hdr->values = values;
    hdr->sum = 0;
    uint16_t sum = cksum16((uint16_t *)hdr, len, 0);
    hdr->sum = sum;
    memcpy(hdr + ICMP_HDR_SIZE, data, len);
    uint16_t msg_len = len + ICMP_HDR_SIZE; // total
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    debugf("%s=>%s, type=%u, code=%u, values=%u, sum=0x%04x, len=%zu",
           ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)),
           type, code, values, sum, msg_len);
    icmp_dump(buf, msg_len);
    return ip_output(IP_PROTOCOL_ICMP, buf, msg_len, src, dst);
}

int icmp_init(void)
{
    if (ip_protocol_register(IP_PROTOCOL_ICMP, icmp_input) == -1)
    {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    return 0;
}
