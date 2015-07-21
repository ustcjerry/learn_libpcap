#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>

/* tcpdump header (ether.h) defines ETHER_HDRLEN) */
#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

u_int16_t handle_ethernet
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet);
u_char* handle_IP
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet);

typedef	uint32_t	tcp_seq;

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr {
	uint16_t	th_sport;		/* source port */
	uint16_t	th_dport;		/* destination port */
	tcp_seq		th_seq;			/* sequence number */
	tcp_seq		th_ack;			/* acknowledgement number */
	uint8_t		th_offx2;		/* data offset, rsvd */
	uint8_t		th_flags;
	uint16_t	th_win;			/* window */
	uint16_t	th_sum;			/* checksum */
	uint16_t	th_urp;			/* urgent pointer */
} UNALIGNED;

/*
 * Structure of an internet header, naked of options.
 *
 * Stolen from tcpdump source (thanks tcpdump people)
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
struct my_ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
    struct in_addr ip_src,ip_dst;      /* source and dest address */
};

/* looking at ethernet headers */
void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*packet)
{
    u_int16_t type = handle_ethernet(args,pkthdr,packet);

    if(type == ETHERTYPE_IP)
    {/* handle IP packet */
        handle_IP(args,pkthdr,packet);
    }else if(type == ETHERTYPE_ARP)
    {/* handle arp packet */
    }else if(type == ETHERTYPE_REVARP)
    {/* handle reverse arp packet */
    }
}

u_char* handle_IP(u_char *args, const struct pcap_pkthdr * pkthdr, const u_char *packet)
{
    const struct my_ip* ip;
    const struct tcphdr *tp;
    u_int length = pkthdr->len;
    u_int hlen,off,version;
    int i;
    const u_char *cp;
    int len;
    uint16_t	th_sport;		/* source port */
    uint16_t	th_dport;		/* destination port */

    struct tm *ltime;
    char timestr[16];

    /* jump pass the ethernet header */
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));

    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0 )/* aka no 1's in first 13 bits */
    {
	if(ip->ip_p== IPPROTO_TCP){

            tp = (struct tcphdr*)(packet + sizeof(struct ether_header)+sizeof(struct my_ip));
            th_sport=ntohs(tp->th_sport);
            th_dport=ntohs(tp->th_dport);

            ltime=localtime(&pkthdr->ts.tv_sec);
            strftime( timestr, sizeof (timestr), "%H:%M:%S", ltime);
            printf("%s.%.6d \n", timestr, (int)pkthdr->ts.tv_usec);

            printf("tcp ");
            fprintf(stdout,"%s:", inet_ntoa(ip->ip_src));
            fprintf(stdout,"%d-->%s:%d\n", th_sport, inet_ntoa(ip->ip_dst), th_dport);

//          下面这行输出的目的地址和源地址一样，不知道什么bug
//          fprintf(stdout,"%s:%d-->%s:%d\n", inet_ntoa(ip->ip_src), th_sport, inet_ntoa(ip->ip_dst), th_dport);
	}
    }
    return NULL;
}

/* handle ethernet packets, much of this code gleaned from
 * print-ether.c from tcpdump source
 */
u_int16_t handle_ethernet
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    u_int caplen = pkthdr->caplen;
    u_int length = pkthdr->len;
    struct ether_header *eptr;  /* net/ethernet.h */
    u_short ether_type;

    if (caplen < ETHER_HDRLEN)
    {
        fprintf(stdout,"Packet length less than ethernet header length\n");
        return -1;
    }

    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);

    /* Lets print SOURCE DEST TYPE LENGTH */
//  fprintf(stdout,"ETH: ");
//  fprintf(stdout,"%s "
//         ,ether_ntoa((struct ether_addr*)eptr->ether_shost));
//  fprintf(stdout,"%s "
//         ,ether_ntoa((struct ether_addr*)eptr->ether_dhost));

    /* check to see if we have an ip packet */
    if (ether_type == ETHERTYPE_IP)
    {
      //  fprintf(stdout,"(IP)");
    }else  if (ether_type == ETHERTYPE_ARP)
    {
        fprintf(stdout,"(ARP)");
    }else  if (eptr->ether_type == ETHERTYPE_REVARP)
    {
        fprintf(stdout,"(RARP)");
    }else {
        fprintf(stdout,"(?)");
    }
   // fprintf(stdout," %d\n",length);

    return ether_type;
}


int main(int argc,char **argv)
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;      /* hold compiled program     */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */
    u_char* args = NULL;

    /* Options must be passed in as a string because I am lazy */
    if(argc < 2){
        fprintf(stdout,"Usage: %s numpackets \"options\"\n",argv[0]);
        return 0;
    }

    /* grab a device to peak into... */
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    { printf("%s\n",errbuf); exit(1); }

    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(dev,&netp,&maskp,errbuf);

    /* open device for reading. NOTE: defaulting to
     * promiscuous mode*/
    descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }


    if(argc > 2)
    {
        /* Lets try and compile the program.. non-optimized */
        if(pcap_compile(descr,&fp,argv[2],0,netp) == -1)
        { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

        /* set the compiled program as the filter */
        if(pcap_setfilter(descr,&fp) == -1)
        { fprintf(stderr,"Error setting filter\n"); exit(1); }
    }

    /* ... and loop */
    pcap_loop(descr,atoi(argv[1]),my_callback,args);

    fprintf(stdout,"\nfinished\n");
    return 0;
}
