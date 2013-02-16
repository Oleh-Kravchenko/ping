/*
 * ping -- just another ping util.
 * Copyright (C) 2012  Oleh Kravchenko <oleg@kaa.org.ua>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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

/* implementation of RFC1071 Computing the Internet Checksum */
uint16_t inet_checksum(const void* data, size_t count)
{
	const uint16_t* addr = data;

	/* compute Internet Checksum for "count" bytes
	 * beginning at location "addr".
	 */
	register long sum = 0;

	while(count > 1) {
		/* this is the inner loop */
		sum += *addr ++;
		count -= 2;
	}

	/* add left-over byte, if any */
	if(count > 0)
		sum += *(const uint8_t*)addr;

	/* fold 32-bit sum to 16 bits */
	while(sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return(~sum);
}

/*-------------------------------------------------------------------------*/

int pingv4_pkt_init(void* buf, size_t len, uint16_t id, uint16_t seq)
{
	struct icmphdr* icmphdr = buf;

	if(len < sizeof(struct icmphdr))
		return(-1);

	/* setup ICMP packet */
	memset(icmphdr, 0, sizeof(*icmphdr));
	icmphdr->type = ICMP_ECHO;
	icmphdr->code = ICMP_REDIR_NET;
	icmphdr->un.echo.id = htons(id);
	icmphdr->un.echo.sequence = htons(seq);
	icmphdr->checksum = inet_checksum(buf, len);

	return(0);
}

/*-------------------------------------------------------------------------*/

int pingv4_pkt_check(void* buf, size_t len, uint16_t id, uint16_t seq)
{
	struct icmphdr* icmphdr = buf;
	uint16_t checksum;

	if(len < sizeof(struct icmphdr))
		return(0);

	/* check checksum without checksum */
	checksum = icmphdr->checksum;
	icmphdr->checksum = 0;

	return((icmphdr->type == ICMP_ECHOREPLY) &&
		(icmphdr->un.echo.id == htons(id)) &&
		(icmphdr->un.echo.sequence == htons(seq)) &&
		(checksum == (icmphdr->checksum = inet_checksum(buf, len)))
	);
}

/*-------------------------------------------------------------------------*/

int main(int narg, char** argv)
{
	uint8_t buf[sizeof(struct iphdr) + sizeof(struct icmphdr) + __PING_DATA];
	struct iphdr* iphdr = (struct iphdr*)buf;
	struct sockaddr_in sendaddr, recvaddr;
	int iphdr_len, sockfd, res, seq;
	struct timeval tv1, tv2;
	socklen_t recvaddr_len;
	struct icmphdr* icmphdr;
	time_t delay;

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
			/* wait between send ping */
			sleep(__PING_WAIT);

		icmphdr = (struct icmphdr*)buf;

		/* init icmp packet */
		pingv4_pkt_init(icmphdr, sizeof(buf) - sizeof(struct iphdr), getpid(), seq);

		if(gettimeofday(&tv1, NULL)) {
			perror("gettimeofday()");
			goto error;
		}

		if(sendto(sockfd, icmphdr, sizeof(buf) - sizeof(struct iphdr), 0, (struct sockaddr*)&sendaddr, sizeof(sendaddr)) == -1) {
			perror("sendto()");
			goto error;
		}

try_recvfrom:
		recvaddr_len = sizeof(recvaddr);

		/* receive packet */
		if((res = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&recvaddr, &recvaddr_len)) == -1) {
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

		/* calculate delay between send and receive */
		delay = (tv2.tv_sec - tv1.tv_sec) * 1000000 + (tv2.tv_usec - tv1.tv_usec);

		/* print packet info */
		printf("%d bytes from %s (%s): icmp_req=%d ttl=%d time=%zd.%03zd ms\n",
			ntohs(iphdr->tot_len) - iphdr_len,
			argv[1],
			inet_ntoa(recvaddr.sin_addr),
			ntohs(icmphdr->un.echo.sequence),
			iphdr->ttl, delay / 1000, delay % 1000
		);
	}

	exit_code = 0;

error:
	close(sockfd);

	return(exit_code);
}
