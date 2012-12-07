#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

/*-------------------------------------------------------------------------*/

#define __PING_COUNT	4
#define __PING_TIMEOUT	2
#define __PING_WAIT		1
#define __PING_DATA		56

/*-------------------------------------------------------------------------*/

static int exit_code = 1;

/*-------------------------------------------------------------------------*/

uint16_t in_cksum(const uint16_t *addr, size_t len)
{
	int nleft = len;
	const uint16_t *w = addr;
	uint16_t answer;
	uint32_t sum = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += htons(*(u_char *)w << 8);

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

/*-------------------------------------------------------------------------*/

int pingv4_pkt_init(struct icmphdr* icmphdr, size_t len, uint16_t id, uint16_t seq)
{
	if(sizeof(*icmphdr) > len)
		return(-1);

	/* setup ICMP packet */
	memset(icmphdr, 0, sizeof(*icmphdr));
	icmphdr->type = ICMP_ECHO;
	icmphdr->code = ICMP_REDIR_NET;
	icmphdr->un.echo.id = htons(id);
	icmphdr->un.echo.sequence = htons(seq);
	icmphdr->checksum = in_cksum((uint16_t*)icmphdr, len);

	return(0);
}

/*-------------------------------------------------------------------------*/

int pingv4_pkt_check(struct icmphdr* icmphdr, size_t len, uint16_t id, uint16_t seq)
{
	uint16_t checksum;

	if(sizeof(*icmphdr) > len)
		return(0);

	/* check checksum without checksum */
	checksum = icmphdr->checksum;
	icmphdr->checksum = 0;

	return((icmphdr->type == ICMP_ECHOREPLY) &&
		(icmphdr->un.echo.id == htons(id)) &&
		(icmphdr->un.echo.sequence == htons(seq)) &&
		(checksum == (icmphdr->checksum = in_cksum((uint16_t*)icmphdr, len)))
	);
}

/*-------------------------------------------------------------------------*/

int main(int narg, char** argv)
{
	uint8_t buf[sizeof(struct iphdr) + sizeof(struct icmphdr) + __PING_DATA];
	struct iphdr* iphdr = (struct iphdr*)buf;
	struct sockaddr_in sendaddr;
	struct sockaddr_in recvaddr;
	struct timeval tv1, tv2;
	socklen_t recvaddr_len;
	struct icmphdr* icmphdr;
	int iphdr_len;
	int sockfd;
	int res;
	int seq;

	if(narg != 2) {
		printf("Usage: %s HOST\n", argv[0]);
		return(exit_code);
	}

	/* configure target address */
	memset(&sendaddr, 0, sizeof(sendaddr));
	sendaddr.sin_family = AF_INET;

	/* target address validation */
	if(!inet_aton(argv[1], &sendaddr.sin_addr)) {
		struct hostent* host = gethostbyname(argv[1]);

		if(!host) {
			printf("%s: unknown host %s\n", argv[0], argv[1]);

			return(exit_code);
		}

		sendaddr.sin_addr = *((struct in_addr*)host->h_addr);
	}

	/* create raw socket for ICMP */
	if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
		perror("socket()");
		return(exit_code);
	}

	if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &(struct timeval){__PING_TIMEOUT, 0}, sizeof(struct timeval)) == -1) {
		perror("setsockopt(SO_RCVTIMEO)");
		return(exit_code);
	}

	if(setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &(struct timeval){0, 0}, sizeof(struct timeval)) == -1) {
		perror("setsockopt(SO_SNDTIMEO)");
		return(exit_code);
	}

	for(seq = 0; seq < __PING_COUNT; ++ seq) {
		if(seq)
			/* wait between ping */
			sleep(__PING_WAIT);

		icmphdr = (struct icmphdr*)buf;

		/* init icmp packet */
		pingv4_pkt_init(icmphdr, sizeof(*icmphdr) + __PING_DATA, getpid(), seq);

		if(gettimeofday(&tv1, NULL)) {
			perror("gettimeofday()");
			goto error;
		}

		if(sendto(sockfd, icmphdr, sizeof(*icmphdr) + __PING_DATA, 0, (struct sockaddr *)&sendaddr, sizeof(sendaddr)) == -1) {
			perror("sendto()");
			goto error;
		}

try_recvfrom:
		recvaddr_len = sizeof(recvaddr);

		/* receive packet */
		if((res = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&recvaddr, &recvaddr_len)) == -1) {
			if(errno == EAGAIN) {
				printf("%s: icmp_req=%d timeout after %d seconds\n", argv[1], seq, __PING_TIMEOUT);
				continue;
			}

			perror("recvfrom()");
			goto error;
		}

		if(gettimeofday(&tv2, NULL)) {
			perror("gettimeofday()");
			goto error;
		}

		/* getting icmp header */
		iphdr_len = iphdr->ihl << 2;
		icmphdr = (struct icmphdr*)(buf + iphdr_len);

		/* check packet owner */
		if(!pingv4_pkt_check(icmphdr, res - iphdr_len, getpid(), seq))
			goto try_recvfrom;

		/* print packet info */
		printf("%d bytes from %s (%s): icmp_req=%d ttl=%d time=%zd ms\n",
			htons(iphdr->tot_len) - iphdr_len,
			argv[1],
			inet_ntoa(recvaddr.sin_addr),
			ntohs(icmphdr->un.echo.sequence),
			iphdr->ttl,
			(tv2.tv_sec - tv1.tv_sec) * 1000 +
			(tv2.tv_usec - tv1.tv_usec) / 1000
		);
	}

	exit_code = 0;

error:
	close(sockfd);

	return(exit_code);
}
