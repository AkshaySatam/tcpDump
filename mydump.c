#include <stdio.h>
#include <pcap.h>
#include <ctype.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <string.h>
#include <time.h>
//#include <netinet/ip_icmp.h>
//#include <net/if_arp.h>
/* ARP Header, (assuming Ethernet+IPv4)            */ 
#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 

struct my_icmphdr{
	u_char icmp_type;
	u_char icmp_code;
	u_short icmp_cksum;
};
typedef struct my_arphdr { 
	u_int16_t htype;    /* Hardware Type           */ 
	u_int16_t ptype;    /* Protocol Type           */ 
	u_char hlen;        /* Hardware Address Length */ 
	u_char plen;        /* Protocol Address Length */ 
	u_int16_t oper;     /* Operation Code          */ 
	u_char sha[6];      /* Sender hardware address */ 
	u_char spa[4];      /* Sender IP address       */ 
	u_char tha[6];      /* Target hardware address */ 
	u_char tpa[4];      /* Target IP address       */ 
}arphdr_t; 


struct sniff_tcp {
	u_short th_sport;               /* source port */
	u_short th_dport;               /* destination port */
	tcp_seq th_seq;                 /* sequence number */
	tcp_seq th_ack;                 /* acknowledgement number */
	u_char  th_offx2;               /* data offset, rsvd */
	#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
	#define TH_FIN  0x01
	#define TH_SYN  0x02
	#define TH_RST  0x04
	#define TH_PUSH 0x08
	#define TH_ACK  0x10
	#define TH_URG  0x20
	#define TH_ECE  0x40
	#define TH_CWR  0x80
	#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;                 /* window */
	u_short th_sum;                 /* checksum */
	u_short th_urp;                 /* urgent pointer */
};
struct UDP_hdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};

void *timestamp_string(struct timeval ts)
{
	static char timestamp_string_buf[256];
	time_t t = ts.tv_sec;
	struct tm* info;
	info = localtime (&t);
	char timeBuf[90];
	strftime (timeBuf, 90, "%F %T", localtime(&t));
	printf("%s", timeBuf);
//	printf("%s",strftime(info));
	return 0;
}


void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

void processPacket(u_char * arg,const struct pcap_pkthdr* pkthdr, const u_char * packet){
	int i =0;
	struct ether_header *eptr;
	char sourceIp[INET_ADDRSTRLEN];
	char destIp[INET_ADDRSTRLEN];
	const struct ip * ipHeader;
	const struct sniff_tcp* tcpHeader;
	const struct UDP_hdr* udpHeader;
	const struct my_icmphdr* icmpHeader;
	u_short sourcePort;
	u_short destPort;
	u_char *ptr;
	int size_ip;
	int payloadLength=0;
	u_char *payloadPtr;
	char payLoadStr [5000];
	char* p=payLoadStr;
	//UDP header structs
	char* stringFilter= (char*) arg;
	char* isStrPresent;
	//ARP info
	arphdr_t *arpheader = NULL;

//	printf("String Filter: %s\n",(const char *)arg);

	if(packet == NULL)
	{
		printf("Couldnt get packet\n");
		exit(1);
	}
		for(i=0;i<pkthdr->len;i++){
		if(isprint(packet[i]) && packet[i]!='\n'){
	//		printf("%c",packet[i]);
			*p++ = packet[i];	
		}else{
	//		printf(".");
		}
		if((i%16 == 0 && i!=0)||(i==pkthdr -> len-1)){
	//		printf("\n");

		}
	}
	*p='\0';
	//printf("Payload String:\n");
	//p = payLoadStr;
	/*while(*p){
	  printf("%c ",*p++);
	  }*/
	if(stringFilter!=NULL){
		isStrPresent = strstr(payLoadStr,stringFilter);}
	else {
		isStrPresent="Present";
	}
	if(isStrPresent!= NULL){

		timestamp_string (pkthdr->ts);
		eptr = (struct ether_header *) packet;
		
		
		if (ntohs (eptr->ether_type) == ETHERTYPE_IP){

			ptr = eptr->ether_shost;
			i = ETHER_ADDR_LEN;
			//printf(" Source Address:  ");
			do{
				printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
			}while(--i>0);
			
			printf(" -> "); 
			ptr = eptr->ether_dhost;
			i = ETHER_ADDR_LEN;
			//printf(" Destination Address:  ");
			do{
				printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
			}while(--i>0);

		
			printf(" type %x ",ntohs(eptr->ether_type));
			printf("len %d ",pkthdr->len);
			ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
			inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

			
			switch(ipHeader->ip_p) {
				case IPPROTO_TCP:
					//printf("TCP ");
					tcpHeader = (struct sniff_tcp*)(packet + sizeof(struct ether_header) +  sizeof(struct ip));
					sourcePort = ntohs(tcpHeader->th_sport);
					destPort = ntohs(tcpHeader->th_sport);
					printf("%s:%d ",sourceIp,sourcePort);
					printf(" -> "); 
					printf("%s:%d ",destIp,destPort);
			//		printf("%d ",sourcePort);
			//		printf("%d ",destPort);
					printf("TCP \n");
					payloadPtr = (u_char*)(packet + sizeof(struct ether_header) +  sizeof(struct ip)+sizeof(struct sniff_tcp));
					payloadLength = ntohs(ipHeader->ip_len) - (sizeof(struct ip)+sizeof(struct sniff_tcp));
					print_payload(payloadPtr, payloadLength);
					break;
				case IPPROTO_UDP:
					udpHeader = (struct UDP_hdr*) (packet + sizeof(struct ether_header) +  sizeof(struct ip));
					sourcePort = ntohs(udpHeader->uh_sport);
					destPort = ntohs(udpHeader->uh_dport);
					printf("%s:%d ",sourceIp,sourcePort);
					printf(" -> "); 
					printf("%s:%d ",destIp,destPort);
					//printf("%d ",sourcePort);
					//printf("%d ",destPort);
					payloadPtr = (u_char*)(packet + sizeof(struct ether_header) +  sizeof(struct ip)+sizeof(struct UDP_hdr));
					payloadLength = ntohs(ipHeader->ip_len) - (sizeof(struct ip)+sizeof(struct UDP_hdr));
					printf("UDP\n");
					print_payload(payloadPtr, payloadLength);
					break;
				case IPPROTO_ICMP:
					//printf("   Protocol: ICMP\n");
					printf("%s ",sourceIp);
					printf(" -> "); 
					printf("%s ",destIp);
					icmpHeader = (struct my_icmphdr*) (packet + sizeof(struct ether_header) +  sizeof(struct ip));
					payloadPtr = (u_char*)(packet + sizeof(struct ether_header) +  sizeof(struct ip)+sizeof(struct my_icmphdr));
					payloadLength = ntohs(ipHeader->ip_len) - (sizeof(struct ip)+sizeof(struct my_icmphdr));
					print_payload(payloadPtr, payloadLength);
					break;
				default:
					printf("Other Protocol \n");
					printf("%s ",sourceIp);
					printf(" -> "); 
					printf("%s ",destIp);
					break;
			}
		}	
		else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
		{
			printf("type hex:%x ",ntohs(eptr->ether_type));
			arpheader = (struct my_arphdr *)(packet+14); /* Point to the ARP header */ 
			/* If is Ethernet and IPv4, print packet contents */ 
			if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800){ 
//				printf("Sender MAC: "); 

				for(i=0; i<6;i++)
					printf("%02X:", arpheader->sha[i]); 

				printf(" -> "); 

//				printf("\nTarget MAC: "); 

				for(i=0; i<6;i++)
					printf("%02X:", arpheader->tha[i]); 

//				printf("\nSender IP: "); 

				for(i=0; i<4;i++)
					printf("%d.", arpheader->spa[i]);
				printf(" -> "); 
//				printf("\nTarget IP: "); 

				for(i=0; i<4; i++)
					printf("%d.", arpheader->tpa[i]); 

				printf("\n"); 
			} 
		}else {
			printf("Ethernet type %x not IP", ntohs(eptr->ether_type));
			exit(1);
		}
			
	}
}

int main(int argc, char *argv[])
{
	
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	const char *fileName;
	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[50];
	//char* filter_exp = "port 1900";	/* The filter expression */
	bpf_u_int32 mask;		/* The netmask of our sniffing device */
	bpf_u_int32 net;		/* The IP of our sniffing device */
	pcap_t *handle;
	int count=0;
	int readFromFile = 0;
	const char* stringFilter=NULL;
	int j=0;	
	dev = pcap_lookupdev(errbuf);
	for(int i=1;i<argc;i++){
		if(strcmp("-i",argv[i])==0){
			i++;
			dev = argv[i];
//			printf("Device set to : %s \n",dev);
		}else 
			if(strcmp("-r",argv[i])==0){
				i++;
				fileName = argv[i];
				readFromFile=1;	
//				printf("Read From file : %d \n",readFromFile);
//				printf("fileName : %s\n",fileName);
			}else 
				if(strcmp("-s",argv[i])==0){
					i++;
					stringFilter = argv[i];
//					printf("String filter: %s\n", stringFilter);	
				}else {
					int k =0;
					if(j!=0){
						*(filter_exp+j)= ' ';
						j++;
					}
//					printf("Received exp: %s \n",(argv[i]+k));
//					printf("First char of received exp: %c \n",*(argv[i]+k));
					while(*(argv[i]+k)!='\0'){
						*(filter_exp+j)= *(argv[i]+k);
						j++;k++;
//						printf("Expression: %s\n",filter_exp);	
					}
				}
	}
	if(readFromFile){
		handle = pcap_open_offline(fileName, errbuf);
	}else{
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
		printf("Device: %s\n", dev);

		handle = pcap_open_live(dev, 65535, 1, 10000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}
		else{
			printf("Opened the device\n");	
		}
		
	}
	// provide filters if anys
	
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Can't get netmask for device %s\n", dev);
			net = 0;
			mask = 0;
		}
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
	// capture packets
	pcap_loop(handle,-1,processPacket,(u_char *) stringFilter);

	return(0);
}
