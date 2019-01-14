/*
* THIS FILE IS FOR IP TEST
*/
// system support
#include "sysInclude.h"

extern void ip_DiscardPkt(char* pBuffer,int type);

extern void ip_SendtoLower(char*pBuffer,int length);

extern void ip_SendtoUp(char *pBuffer,int length);

extern unsigned int getIpv4Address();

// implemented by students

//checksum function
unsigned short checksum(unsigned short *buffer, int len) {
	unsigned long cksum = 0;
	while (len > 1) {
		cksum += *buffer++;
		len -= sizeof(unsigned short);
	}
	if (len) {
		cksum += *(unsigned char *)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (unsigned short)(~cksum);
}

int stud_ip_recv(char *pBuffer,unsigned short length)
{
	//Version
	if ((pBuffer[0] & 0xf0) != 0x40) {
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_VERSION_ERROR);
		return 1;
	}

	//IHL
	if ((pBuffer[0] & 0x0f) != 0x05) {
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_HEADLEN_ERROR);
		return 1;
	}

	//TTL
	if (pBuffer[8] == 0x00) {
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_TTL_ERROR);
		return 1;
	}

	//dst IP
	unsigned int address = getIpv4Address();
	unsigned int *intAddress = (unsigned int *)(pBuffer + 16);
	if (address != ntohl(*intAddress)) {
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_DESTINATION_ERROR);
		return 1;
	}

	//checksum
	unsigned short cksum = checksum((unsigned short *)pBuffer, 20);
	if (cksum != 0) {
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_CHECKSUM_ERROR);
		return 1;
	}

	ip_SendtoUp(pBuffer, length);
	return 0;
}

int stud_ip_Upsend(char *pBuffer,unsigned short len,unsigned int srcAddr,
				   unsigned int dstAddr,byte protocol,byte ttl)
{
	byte *frame = new byte[20 + len];
	memset(frame, 0, 20);
	frame[0] = 0x45;//version=4
	unsigned short int *length = (unsigned short int *)(frame + 2); 
	*length = htons(20 + len);
	frame[8] = ttl;
	frame[9] = protocol;
	unsigned int *srcIP = (unsigned int *)(frame + 12);
	*srcIP = ntohl(srcAddr);
	unsigned int *dstIP = (unsigned int *)(frame + 16);
	*dstIP = ntohl(dstAddr);
	short int *cksumAddr = (short int *)(frame + 10);
	*cksumAddr = checksum((unsigned short *)frame, 20);
	for (int i = 0; i<len; i++) {
		frame[i + 20] = pBuffer[i];
	}
	ip_SendtoLower(frame, 20 + len);
	return 0;
}





