#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define IP_ETHERTYPE 0x0800
#define ETHERNET_LENGTH 14
#define IP_DEFAULT_SIZE 20
#define TCP_PROTOCOL 6
#define WEIGHT 4

void usage(void) {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
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

typedef struct _ethernet_header{
    uint8_t dstAddr[6]; //MAC Destination Address
    uint8_t srcAddr[6]; //MAC Source Address
    uint16_t etherType; //Ehernet Type
    
}ETHERNET_HEADER;

typedef struct _ipv4_header{
    //unsigned char version;//(4)
    //unsigned char IHL;//Internet Header Length(5)
    uint8_t version_IHL;
    uint8_t TOS;
    uint16_t totalLength;
    uint16_t identification;
    uint16_t flag_fragmentOffset;
    uint8_t TTL;
    uint8_t protocol; //TCP\ub77c\uba74 6
    uint16_t headerChecksum;
    uint32_t srcAddr; //source IP address
    uint32_t dstAddr; //destination IP address
    
    
}IPv4_HEADER;

typedef struct _tcp_header{
    uint16_t srcPort;//source port
    uint16_t dstPort;//destination port
    uint32_t seqNumber;//sequence number
    uint32_t ackNumber;//Acknowledgement number
    uint16_t dataOffset_reserved_flags;//Data Offset
    
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPointer;
}TCP_HEADER;

//typedef struct _headers{
//    ETHERNET_HEADER ethernetHeader;
///    IPv4_HEADER ipv4Header;
//    TCP_HEADER tcpHeader;
//     
//}HEADERS;

void setEthr_Struct(ETHERNET_HEADER * h, const u_char * p){
    
    memcpy(h,p,sizeof(u_char)*ETHERNET_LENGTH);
//    printf("p[0]: 0x%hhx\n",p[0]);
//    printf("ETHERNET[0]: 0x%hhx\n",h->dstAddr[0]);
}

void printEthrAddr(ETHERNET_HEADER *h){
    printf("----------------------------------\n");
    printf("----------------------------------\n");
    printf("Ethernet Header\n");
    printf("src mac: ");
    printf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",h->srcAddr[0],h->srcAddr[1],h->srcAddr[2],h->srcAddr[3],h->srcAddr[4],h->srcAddr[5]);
    printf("dst mac: ");
    printf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",h->dstAddr[0],h->dstAddr[1],h->dstAddr[2],h->dstAddr[3],h->dstAddr[4],h->dstAddr[5]);
}

bool isIP(ETHERNET_HEADER*h){
    //printf("h value : %x, IP value : %x\n", h->etherType, IP_ETHERTYPE);
    return (ntohs(h->etherType)==IP_ETHERTYPE);
}

void setIP_Struct(IPv4_HEADER *h, const u_char *p){
    memcpy(h, &p[ETHERNET_LENGTH], sizeof(u_char)*IP_DEFAULT_SIZE);
    
}


void printIP_Struct(IPv4_HEADER *h){
    printf("----------------------------------\n");
    printf("IP Header\n");
    struct sockaddr_in addr;
    printf("src ip: ");
    addr.sin_addr.s_addr=h->srcAddr;
    printf("%s\n",inet_ntoa(addr.sin_addr));
    
    printf("dst ip: ");
    addr.sin_addr.s_addr=h->dstAddr;
    printf("%s\n",inet_ntoa(addr.sin_addr));
    
    
}

bool isTCP(IPv4_HEADER *h){
    return (h->protocol==TCP_PROTOCOL);
}

uint32_t calc_tcp_start_index(uint32_t ip_header_size){
    
    return ETHERNET_LENGTH+ip_header_size;
}
void setTCP_Struct(TCP_HEADER *h, const u_char *p, uint32_t tcp_start_index){
    //printf("p[index]: %hhx\n",p[index]);
   
    //printf("set tcp header size: %x",size);
    memcpy(h,&p[tcp_start_index],sizeof(TCP_HEADER));
}

void printTCP_Struct(TCP_HEADER *h){
    printf("----------------------------------\n");
    printf("TCP Header\n");
    
    printf("src port: ");
    printf("%hu\n",ntohs(h->srcPort));
    printf("dst port: ");
    printf("%hu\n",ntohs(h->dstPort));
    

    
}

//uint32_t calc_data_size(IPv4_HEADER *h1, uint32_t ip_header_size, uint32_t tcp_header_size){
//    return ntohs(h1->totalLength)-ETHERNET_LENGTH-ip_header_size-tcp_header_size;
//}

//uint32_t calc_data_start_index(uint32_t ip_header_size, uint32_t tcp_header_size){
//    return ETHERNET_LENGTH+ip_header_size+tcp_header_size;
//}

void printData(const u_char *p, uint32_t datasize, uint32_t data_start_index){
    printf("----------------------------------\n");
    printf("Payload(Data)\n");
    if(datasize>10){
        datasize=10;
    }
    for(int i=0;i<datasize;i++){
        printf("0x%02hhx ",p[data_start_index+i]);
    }
    printf("\n");
//    printf("----------------------------------\n");
//    printf("----------------------------------\n");
//    printf("\n\n");
    
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
       	 
        	ETHERNET_HEADER ethrH;
        	setEthr_Struct(&ethrH, packet);
//		printf("ehtr check2:%hhx\n",ethrH.dstAddr[0]);
        	if(!isIP)continue;
//        	printf("ehtr check3:%hhx\n",ethrH.dstAddr[0]);
        	IPv4_HEADER ipH;
        	setIP_Struct(&ipH, packet);
//		printf("ehtr check4:%hhx\n",ethrH.dstAddr[0]);
        	if(!isTCP(&ipH))continue;
       		TCP_HEADER tcpH;

   
		//printf("strlen(packet): %lu\n",strlen(packet));
	

//		printf("ipH.version_IHL: 0x%hhx\n",ipH.version_IHL);
		

		uint32_t ip_header_size=WEIGHT*(ipH.version_IHL&0x0F);
//		printf("ip_header_size %u\n", ip_header_size);

        	uint32_t tcp_header_size=WEIGHT*(packet[ETHERNET_LENGTH+ip_header_size+12]>>4);
		//printf("packet[ETHERNET_LENGTH+ip_header_size+12]: 0x%x\n",packet[ETHERNET_LENGTH+ip_header_size+12]>>4);
//		printf("tcp_header_size: %u\n",tcp_header_size);
        	
		uint32_t tcp_start_index=calc_tcp_start_index(ip_header_size);
  //      	printf("tcp_start_index: %u\n", tcp_start_index);
 //             printf("ehtr check5:%hhx\n",ethrH.dstAddr[0]);

        	setTCP_Struct(&tcpH, packet, tcp_start_index);
		//printf("ipH.totalleng: %u\n",ntohs(ipH.totalLength));
//		printf("ehtr check6:%hhx\n",ethrH.dstAddr[0]);
		uint32_t total_packet_len=ntohs(ipH.totalLength);
//        	printf("total_packet_len: %u\n",ntohs(ipH.totalLength));

		uint32_t data_len=total_packet_len-ip_header_size-tcp_header_size;//calc_data_size(&ipH, ip_header_size,tcp_header_size);
//       		printf("data_len: %u\n",data_len);
      		
		uint32_t data_start_index=ETHERNET_LENGTH+ip_header_size+tcp_header_size;//calc_data_start_index(ip_header_size,tcp_header_size);
//        	printf("data_start_index: %u\n",data_start_index);

//		printf("ehtr check7:%hhx\n",ethrH.dstAddr[0]);
    printEthrAddr(&ethrH);
    printIP_Struct(&ipH);
    printTCP_Struct(&tcpH);
		if(data_len>0) printData(packet, data_len, data_start_index);

  		printf("----------------------------------\n");
     printf("----------------------------------\n");
    	printf("\n\n");      

        
        	//printf("%u bytes captured\n", header->caplen);
	}
    
    
    
    
    
    
    
    

	pcap_close(pcap);
  
  
}
