#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>

/* Ethernet header */
struct ethheader {
	u_char ether_dhost[6]; /* destination host address */
	u_char ether_shost[6]; /* source host address */
	u_short ether_type; /* protocol type (2byte) */
};

/* IP header */
struct ipheader {
	unsigned char iph_ihl:4, /* IP header length */
		      iph_ver:4; /* IP version */
	unsigned char iph_ToS; /* IP Type of Service */
	unsigned short int iph_len; /* IP packet length (data+header) */
	unsigned short int iph_ident; /* Identification */
	unsigned short int iph_flag:3, /* Fragmentation flags */
		           iph_offset:13; /* Flags offset */
	unsigned char iph_ttl; /* Time to Live */
	unsigned char iph_protocol; /* Protocol type */
	unsigned short int iph_chksum; /* IP datagram checksum */
	struct in_addr iph_sip; /* Source IP address */
	struct in_addr iph_dip; /* Destination IP address */
};

/* TCP header */
struct tcpheader {
	u_short tcp_sport; /* TCP source port */
	u_short tcp_dport; /* TCP destination port */
	u_int tcp_seq; /* TCP sequence number */
	u_int tcp_ack; /* TCP acknowledgement number */
	u_char tcp_offset; /* TCP data offset */
	u_char tcp_flags; /* TCP Fragmentation flags */
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_CWR 0x80
#define TH_FLAGS	(TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short tcp_win;
	u_short tcp_sum;
	u_short tcp_urp;
};

/* Packet Capture */
void packet_capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	struct ethheader *eth = (struct ethheader *)packet;
	struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
	struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);

	/* Ethernet print */
	printf("Source Ethernet Address: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
	printf("Destination Ethernet Address: %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));

	/* IP print */
	printf("Source IP Address: %s\n", inet_ntoa(ip->iph_sip));
	printf("Destination IP Address: %s\n", inet_ntoa(ip->iph_dip));

	/* TCP Port print */
	printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
	printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));
};      

int main(){
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];

	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

	pcap_loop(handle, 0, packet_capture, NULL);

	pcap_close(handle);

	return 0;
};

