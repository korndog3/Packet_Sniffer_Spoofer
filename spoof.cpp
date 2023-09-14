#include "common.h"

int main()
{
    char buffer[PACKET_LEN];
    memset(buffer, 0, PACKET_LEN);

    ipheader *ip = (ipheader *)buffer;
    udpheader *udp = (udpheader *)(buffer + sizeof(ipheader));

    // add data
    char *data = (char *)udp + sizeof(udpheader);
    int data_len = strlen(CLIENT_IP);
    strncpy(data, CLIENT_IP, data_len);

    // create udp header
    // TODO
    udp->udp_sport = htons(CLIENT_PORT);
    udp->udp_dport = htons(SERVER_PORT);
    udp->udp_ulen = htons(sizeof(udpheader) + data_len);
    udp->udp_sum = 0; 

    // create ip header
    // TODO
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 255;
    ip->iph_protocol = IPPROTO_UDP;
    ip->iph_sourceip.s_addr = inet_addr(SPOOF_IP);
    ip->iph_destip.s_addr = inet_addr(SERVER_IP);
    ip->iph_ident = htons(0);
    ip->iph_flag = 0;
    ip->iph_offset = 0;
    ip->iph_chksum = 0;
    ip->iph_len = htons(sizeof(ipheader) + sizeof(udpheader) + data_len);

    //calc udp chksum
    pseudo_tcp p_tcp;
    p_tcp.saddr = inet_addr(SPOOF_IP);
    p_tcp.daddr = inet_addr(SERVER_IP);
    p_tcp.mbz = 0;
    p_tcp.ptcl = IPPROTO_UDP;
    p_tcp.tcpl = htons(sizeof(udpheader) + data_len);
    memcpy(&p_tcp.tcp, udp, sizeof(udpheader) + data_len);
    p_tcp.tcp.tcp_sum = 0;
    unsigned short *ptr = (unsigned short *)&p_tcp;
    int nbytes = sizeof(pseudo_tcp);
    unsigned int sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
        sum += *(unsigned char *)ptr;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    udp->udp_sum = ~sum;

    
    // send packet
    send_raw_ip_packet(ip);

    return 0;
}