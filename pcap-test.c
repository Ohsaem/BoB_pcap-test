#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

void print_mac(u_int8_t *m) {
        printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
} 

void print_ip(struct in_addr addr) {
        printf("%s", inet_ntoa(addr));
}

void print_tcp_port(u_int16_t port) {
        printf("%u", ntohs(port));
}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

		struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;
		print_mac(eth_hdr->ether_shost);
		printf("\n");
		print_mac(eth_hdr->ether_dhost);
		printf("\n");

		struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
                print_ip(ip_hdr->ip_src);
                printf("\n");
    		print_ip(ip_hdr->ip_dst);
    		printf("\n");

		if (ip_hdr->ip_p == IPPROTO_TCP) {
        		struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));
        		print_tcp_port(tcp_hdr->th_sport);
        		printf("\n");
        		print_tcp_port(tcp_hdr->th_dport);
        		printf("\n");

			int payloadOffset = sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + (tcp_hdr->th_off * 4);  		
			int payloadLength = header->caplen - payloadOffset;
        		int maxPayloadLength = payloadLength > 10 ? 10 : payloadLength;
        		printf("Payload (Data): ");
        		for (int i = 0; i < maxPayloadLength; i++) {
            			printf("%02x ", packet[payloadOffset + i]);
        		}
        		printf("\n");
    		}
	}

	pcap_close(pcap);
}
