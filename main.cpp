#include <map>

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>

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
  // if we have not got our first ACK yet, we just accept any ack as the tip
  bool init = false;
};

std::map<socket_key, socket_value> sockets;

static unsigned long getPseudoHeaderSum(u_int32_t saddr, u_int32_t daddr,
                                        u_int16_t tcpLength) {
  struct PseudoHeader {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
  } volatile pseudoHeader = {saddr, daddr, 0, IPPROTO_TCP, tcpLength};

  unsigned short *ptr = (unsigned short *)&pseudoHeader;
  unsigned long sum = 0;
  for (int i = 0; i < 6; i++) {
    sum += *ptr++;
  }
  return sum;
}

static unsigned short csum_continue(unsigned long sumStart, char *p,
                                    int nbytes) {
  unsigned short *ptr = (unsigned short *)p;

  long sum;
  unsigned short oddbyte;
  short answer;

  sum = sumStart;
  while (nbytes > 1) {
    sum += *ptr++;
    nbytes -= 2;
  }
  if (nbytes == 1) {
    oddbyte = 0;
    *((u_char *)&oddbyte) = *(u_char *)ptr;
    sum += oddbyte;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum = sum + (sum >> 16);
  answer = (short)~sum;

  return (answer);
}

uint16_t ip_checksum(const void *buf, size_t hdr_len) {
  unsigned long sum = 0;
  const uint16_t *ip1;

  ip1 = (const uint16_t *)buf;
  while (hdr_len > 1) {
    sum += *ip1++;
    if (sum & 0x80000000)
      sum = (sum & 0xFFFF) + (sum >> 16);
    hdr_len -= 2;
  }

  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return (~sum);
}

void send_packet(int syn, int ack, uint32_t seq, uint32_t ack_seq,
                 struct socket_key key) {
  TcpHeader packet = {};

  // ip layer
  packet.iphdr::ihl = 5;
  packet.iphdr::ttl = 255;
  packet.iphdr::tot_len = htons(44); // we always send 44 bytes, or 46?
  packet.iphdr::daddr = key.saddr;
  packet.iphdr::saddr = key.daddr;
  packet.iphdr::version = 4;
  packet.iphdr::protocol = IPPROTO_TCP;
  packet.iphdr::frag_off = htons(0x4000);
  packet.iphdr::id = rand();
  // compute the header checksum here
  packet.iphdr::check = ip_checksum(&packet, 20);

  // tcp layer
  packet.syn = syn;
  packet.ack = ack;

  packet.seq = htonl(seq);
  packet.ack_seq = htonl(ack_seq);

  packet.dest = key.source;
  packet.source = key.dest;

  packet.doff = 6; // needs to be 6 for options?
  packet.window = htons(1024);

  // window scale 512kb / 2
  packet.options[0] = 3;
  packet.options[1] = 3;
  packet.options[2] = 5; // shift
  packet.options[3] = 0;

  // should we check tcp checksum for correctness before parsing it or does the
  // linux kernel do that?

  // ip checksum is set, but not TCP checksum
  packet.tcphdr::check =
      csum_continue(getPseudoHeaderSum(packet.saddr, packet.daddr,
                                       htons(sizeof(struct TcpHeader) + 0 -
                                             sizeof(struct iphdr))),
                    ((char *)&packet) + sizeof(struct iphdr),
                    sizeof(struct TcpHeader) + 0 - sizeof(struct iphdr));

  // sendto (raw socket)
  /*struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = packet.daddr;
  addr.sin_port = packet.dest;
  int sent = sendto(send_fd, &packet, sizeof(packet), 0, (struct sockaddr *)
  &addr, sizeof(struct sockaddr_in));*/

  // sendto (packet)
  struct sockaddr_ll addr = {};
  addr.sll_family = AF_PACKET;
  addr.sll_protocol = htons(ETH_P_IP);
  addr.sll_halen = 6;

  // this is my own ehternet card address (raspberry)
  /*addr.sll_addr[0] = 0xdc;
  addr.sll_addr[1] = 0xa6;
  addr.sll_addr[2] = 0x32;
  addr.sll_addr[3] = 0x77;
  addr.sll_addr[4] = 0xe1;
  addr.sll_addr[5] = 0x32;

  // this is my gateway (tp-link)
  addr.sll_addr[0] = 0xb0;
  addr.sll_addr[1] = 0x4e;
  addr.sll_addr[2] = 0x26;
  addr.sll_addr[3] = 0xb0;
  addr.sll_addr[4] = 0x8f;
  addr.sll_addr[5] = 0x76;*/

  // this is my laptop (wifi)
  addr.sll_addr[0] = 0xdc;
  addr.sll_addr[1] = 0x85;
  addr.sll_addr[2] = 0xde;
  addr.sll_addr[3] = 0x3b;
  addr.sll_addr[4] = 0x8c;
  addr.sll_addr[5] = 0x89;

  // this is my laptop (lan)
  addr.sll_addr[0] = 0x50;
  addr.sll_addr[1] = 0x46;
  addr.sll_addr[2] = 0x5d;
  addr.sll_addr[3] = 0x2e;
  addr.sll_addr[4] = 0x10;
  addr.sll_addr[5] = 0xc0;

  addr.sll_ifindex = 2;
  int sent = sendto(send_fd, &packet,
                    /*sizeof(packet)*/ 44 /*sizeof is wrong due to padding*/, 0,
                    (struct sockaddr *)&addr, sizeof(struct sockaddr_ll));

  // printf("Sent: %d\n", sent);
}

int main() {
  // init
  int read_fd;

  if (read_fd == -1) {
    printf("Cannot open raw socket!\n");
    return -1;
  }

  // we want packet sockets for this benchmarking bound to one specific
  // interface
  read_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));

  // bind only to ethernet interface! (2 on raspberry)
  struct sockaddr_ll addr = {};

  addr.sll_family = AF_PACKET;
  addr.sll_protocol = htons(ETH_P_IP);
  addr.sll_ifindex = 2;

  int e = bind(read_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_ll));
  printf("Bind to ethernet: %d\n", e);

  int optval = 0;
  socklen_t socklen = 4;
  int err = getsockopt(read_fd, SOL_SOCKET, SO_RCVBUF, &optval, &socklen);
  printf("Original RX buffer size: %d\n", optval);

  err = getsockopt(send_fd, SOL_SOCKET, SO_SNDBUF, &optval, &socklen);
  printf("Original TX buffer size: %d\n", optval);

  int bufsize = 1024 * 1024 * 50; // 50mb receive buffer biatch!
  err = setsockopt(read_fd, SOL_SOCKET, SO_RCVBUFFORCE, &bufsize,
                   sizeof(bufsize));

  err = setsockopt(send_fd, SOL_SOCKET, SO_SNDBUFFORCE, &bufsize,
                   sizeof(bufsize));

  err = getsockopt(read_fd, SOL_SOCKET, SO_RCVBUF, &optval, &socklen);
  printf("socket RX new buffer size = %d\n", optval);

  err = getsockopt(send_fd, SOL_SOCKET, SO_SNDBUF, &optval, &socklen);
  printf("New TX buffer size: %d\n", optval);

  send_fd = read_fd; // socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  char *buf = (char *)malloc(65000);

  // mainloop
  while (true) {
    int length = recv(read_fd, buf, 65000, 0);

    volatile struct iphdr *ipHeader = (volatile struct iphdr *)buf;

    if (ipHeader->version != 4 || ipHeader->protocol != 6) {
      continue;
    }

    volatile TcpHeader *tcpHeader = (volatile TcpHeader *)buf;

    if (ntohs(tcpHeader->dest) == 4000) {

      struct socket_value s;
      struct socket_key key = {tcpHeader->saddr, tcpHeader->daddr,
                               tcpHeader->source, tcpHeader->dest};
      auto it = sockets.find(key);
      if (it != sockets.end()) {
        s = it->second;
      } else {
        // only syn packets are acceptable at this point
        if (!tcpHeader->syn) {
          continue;
        }

        // seq, seq_ack
        s = {rand(), ntohl(tcpHeader->seq)};
        s.initialSeq = s.seq;
        s.initialSeqAck = s.seq_ack;
      }

      // handle first, or duplicate SYN
      if (tcpHeader->syn) {
        send_packet(1, 1, s.initialSeq, s.initialSeqAck + 1, key);
      }

      // on first ACK, we just accept it and set our seq, seq_ack
      if (tcpHeader->ack) {
        uint32_t packet_seq = ntohl(tcpHeader->seq);
        uint32_t packet_seq_ack = ntohl(tcpHeader->ack_seq);

        // first ACK determines where we are
        if (!s.init) {
          // OUR seq is now THEIR seq_ack
          // OUR seq_ack is now their seq
          s.seq = packet_seq_ack;
          s.seq_ack = packet_seq;
          s.init = true;
        }

        // REPORT OUT OF SEQUENCE PACKETS AS A BIG FAILURE (SHOULD NEVER HAPPEN, EVER)
        if (s.seq_ack < packet_seq) {
          printf("ERROR: GOT PACKET OUT OF SEQUENCE!\n");
          continue;
        }

        // whenever this ack holds data, print the latency
        int tcpdatalen = ntohs(tcpHeader->tot_len) - (tcpHeader->doff * 4) -
                         (tcpHeader->ihl * 4);

        if (tcpdatalen) {
          // printf("Got data with length: %d\n", tcpdatalen);

          // this packet is new and not out of sequence or dup
          if (s.seq_ack == packet_seq) {
            //printf("Got ACK in sequence with length: %d\n", tcpdatalen);

            if (tcpdatalen == 8) {
              time_t now = time(0);

              time_t then;
              memcpy(&then,
                     ((char *)tcpHeader) + tcpHeader->ihl * 4 +
                         tcpHeader->doff * 4,
                     8);

              int latency = now - then;

              static int max_latency = -1;

              if (latency > max_latency) {
                printf("New max latency: %d\n", latency);
                max_latency = latency;
              }

            } else {
              printf("Got data with length: %d\n", tcpdatalen);
            }

            // make sure this socket knows how far it has acked
            s.seq_ack = packet_seq + tcpdatalen;
          }

          // if it holds data, we ack the ack with whatever seq it has, even
          // duplicates, (and display the latency of the data)
          send_packet(0, 1, packet_seq_ack, packet_seq + tcpdatalen, key);
        }
      }

      sockets[key] = s;
    } else {
      // printf("Got shit package of length: %d\n", length);
    }
  }
}
