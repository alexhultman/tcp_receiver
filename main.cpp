#include <map>

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <time.h>

int send_fd;

struct TcpHeader : iphdr, tcphdr {
    unsigned char options[4];
};

struct socket_key {
    // these are kept in network order
    uint32_t saddr, daddr;
    uint16_t source, dest;
};

bool operator<(const struct socket_key &a, const struct socket_key &b) {
    return memcmp(&a, &b, sizeof(struct socket_key)) < 0;
}

struct socket_value {
    // these are kept in host order
    uint32_t seq, seq_ack;
    uint32_t initialSeq, initialSeqAck;
};

std::map<socket_key, socket_value> sockets;

static unsigned long getPseudoHeaderSum(u_int32_t saddr, u_int32_t daddr, u_int16_t tcpLength) {
    struct PseudoHeader {
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t tcp_length;
    } volatile pseudoHeader = {saddr, daddr, 0, IPPROTO_TCP, tcpLength};

    unsigned short *ptr = (unsigned short *) &pseudoHeader;
    unsigned long sum = 0;
    for (int i = 0; i < 6; i++) {
        sum += *ptr++;
    }
    return sum;
}

static unsigned short csum_continue(unsigned long sumStart, char *p,int nbytes)
{
    unsigned short *ptr = (unsigned short *) p;

    long sum;
    unsigned short oddbyte;
    short answer;

    sum=sumStart;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

void send_packet(int syn, int ack, uint32_t seq, uint32_t ack_seq, struct socket_key key) {
    TcpHeader packet = {};

    packet.syn = syn;
    packet.ack = ack;

    packet.seq = htonl(seq);
    packet.ack_seq = htonl(ack_seq);


    packet.ihl = 5;
    packet.ttl = 255;

    packet.dest = key.source;
    packet.source = key.dest;

    packet.daddr = key.saddr;
    packet.saddr = key.daddr;

    packet.version = 4;
    packet.protocol = IPPROTO_TCP;

    packet.doff = 6;// needs to be 6 for options?
    packet.window = htons(1024);

    // window scale 512kb / 2
    packet.options[0] = 3;
    packet.options[1] = 3;
    packet.options[2] = 5; // shift
    packet.options[3] = 0;

    // should we check tcp checksum for correctness before parsing it or does the linux kernel do that?

    // ip checksum is set, but not TCP checksum
    packet.tcphdr::check = csum_continue(getPseudoHeaderSum(packet.saddr, packet.daddr, htons(sizeof(struct TcpHeader) + 0 - sizeof(struct iphdr)))
                                , ((char *) &packet) + sizeof(struct iphdr), sizeof(struct TcpHeader) + 0 - sizeof(struct iphdr));

    // sendto
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = packet.daddr;
    addr.sin_port = packet.dest;
    int sent = sendto(send_fd, &packet, sizeof(packet), 0, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));

    //printf("Sent: %d\n", sent);
}

int main() {
    // init
    int read_fd;

    read_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (read_fd == -1) {
        printf("Cannot open raw socket!\n");
        return -1;
    }

    send_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    char *buf = (char *) malloc(65000);

    // mainloop
    while (true) {
        int length = recv(read_fd, buf, 65000, 0);

        volatile struct iphdr *ipHeader = (volatile struct iphdr *) buf;

        if (ipHeader->version != 4) {
            continue;
        }

        volatile TcpHeader *tcpHeader = (volatile TcpHeader *) buf;

        if (ntohs(tcpHeader->dest) == 4000) {

            struct socket_value s;
            struct socket_key key = {tcpHeader->saddr, tcpHeader->daddr, tcpHeader->source, tcpHeader->dest};
            auto it = sockets.find(key);
            if (it != sockets.end()) {
                s = it->second;
            } else {

                // if we get a package for a socket we do not have, ignore it
                if (!tcpHeader->syn) {
                    continue;
                }

                // seq, seq_ack
                s = {rand(), ntohl(tcpHeader->seq)};
                s.initialSeq = s.seq;
                s.initialSeqAck = s.seq_ack;
            }

            if (tcpHeader->syn) {
                //printf("It is a syn!\n");
                send_packet(1, 1, s.initialSeq, s.initialSeqAck + 1, key);
            }

            if (tcpHeader->ack) {
                //printf("It is ack!\n");

                uint32_t seq = ntohl(tcpHeader->ack_seq);
                uint32_t seq_ack = ntohl(tcpHeader->seq);

                // ack whatever is the highest ack we get, don't care for correctness just yet

                // whenever this ack holds data, print the latency
                int tcpdatalen = ntohs(tcpHeader->tot_len) - (tcpHeader->doff * 4) - (tcpHeader->ihl * 4);
                if (tcpdatalen) {
                    //printf("Got data with length: %d\n", tcpdatalen);

                    if (tcpdatalen == 8) {
                        time_t now = time(0);

                        time_t then;
                        memcpy(&then, ((char *) tcpHeader) + tcpHeader->ihl * 4 + tcpHeader->doff * 4, 8);

                        int latency = now - then;

                        if (latency > 2) {
                            printf("Latency: %d\n", latency);
                        }

                    } else {
                        printf("Got data with length: %d\n", tcpdatalen);
                    }

                }

                // if it holds data, we ack the ack with whatever seq it has, even duplicates, and display the latency of the data

                send_packet(0, 1, seq, seq_ack + tcpdatalen, key);
            }

            sockets[key] = s;
        }
    }
}