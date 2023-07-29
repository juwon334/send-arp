#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

void getMAC(char *iface, unsigned char *mac) {
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
}
void getIP(char *iface, char *ip) {
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	strcpy(ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

int main(int argc, char* argv[]) {

	int i = 2;
	if(argc % 2 != 0){
		fprintf(stderr,"Please give me more ip\n");
		exit(1);
	}
	unsigned char mac[ETHER_ADDR_LEN];
	getMAC(argv[1], mac);
	char macStr[18];
	sprintf(macStr, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	printf("MAC: %s\n", macStr);

	char ip[20];
	getIP(argv[1], ip);
	printf("IP: %s\n", ip);

	while(1){
		if(i>=argc)
                        break;
		char* dev = argv[1];
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
		if (handle == nullptr) {
			fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
			return -1;
		}
		char Smac[18];
		EthArpPacket packet;
		packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
		packet.eth_.smac_ = Mac(macStr);
		packet.eth_.type_ = htons(EthHdr::Arp);
		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(macStr);
		packet.arp_.sip_ = htonl(Ip(ip));
		packet.arp_.tmac_ = Mac("00-00-00-00-00-00");
		packet.arp_.tip_ = htonl(Ip(argv[i]));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		while (true) {
			struct pcap_pkthdr* header;
			const u_char* reply_packet;
			int result = pcap_next_ex(handle, &header, &reply_packet);
			if (result != 1) {
				continue;
			}

			EthArpPacket* reply = (EthArpPacket*)reply_packet;

			if (ntohs(reply->eth_.type_) == EthHdr::Arp && ntohs(reply->arp_.op_) == ArpHdr::Reply &&
					reply->arp_.sip_ == packet.arp_.tip_ && reply->arp_.tip_ == packet.arp_.sip_) {
				strcpy(Smac,std::string(reply->arp_.smac_).c_str());

				printf("Found target MAC address: %s\n", std::string(reply->arp_.smac_).c_str());
				break;
			}
		}

		EthArpPacket rppacket;
		rppacket.eth_.dmac_ = Mac(Smac);
		rppacket.eth_.smac_ = Mac(macStr);
		rppacket.eth_.type_ = htons(EthHdr::Arp);
		rppacket.arp_.hrd_ = htons(ArpHdr::ETHER);
		rppacket.arp_.pro_ = htons(EthHdr::Ip4);
		rppacket.arp_.hln_ = Mac::SIZE;
		rppacket.arp_.pln_ = Ip::SIZE;
		rppacket.arp_.op_ = htons(ArpHdr::Reply);
		rppacket.arp_.smac_ = Mac(macStr);
		rppacket.arp_.sip_ = htonl(Ip(argv[i+1]));
		rppacket.arp_.tmac_ = Mac(Smac);
		rppacket.arp_.tip_ = htonl(Ip(argv[i]));

		int rpres = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&rppacket), sizeof(EthArpPacket));

		i+=2;
		pcap_close(handle);
	}
}
