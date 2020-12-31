/* SPDX-License-Identifier: ISC */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <endian.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include "ssdp.h"
#include "http.h"
#include "util.h"
#include "version.h"

static const struct sockaddr_in ssdp_addr = {
	.sin_family = AF_INET,
#if BYTE_ORDER == LITTLE_ENDIAN
	.sin_port = 0x6c07,             /* 1900 */
	.sin_addr.s_addr = 0xfaffffef,  /* 239.255.255.250 */
#else
	.sin_port = 0x076c              /* 1900 */
	.sin_addr.s_addr = 0xeffffffa,  /* 239.255.255.250 */
#endif
};

static void
sendf(int sock, const struct sockaddr *addr, socklen_t addr_len, const char *fmt, ...)
{
	va_list ap;
	char buf[4096];
	int len;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (len < 0 || len >= sizeof(buf)) {
		fprintf(stderr, "response is too large\n");
		return;
	}
	if (sendto(sock, buf, len, 0, addr, addr_len) < 0) {
		perror("sendto");
		return;
	}
}

int
ssdp_open(const struct ssdp_device *ssdp)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(1900),
		.sin_addr = {.s_addr = INADDR_ANY},
	};
	struct ip_mreq mreq = {
		.imr_multiaddr = ssdp_addr.sin_addr,
		.imr_interface = {.s_addr = INADDR_ANY},
	};
	int sock, opt;
	size_t i;

#if 0
	char soap_addr_str[INET_ADDRSTRLEN];
	socklen_t soap_addr_len;
	soap_addr_len = sizeof(soap_addr);
	if (getsockname(soap_sock, (struct sockaddr *)&soap_addr, &soap_addr_len) != 0) {
		perror("getsockname");
		return -1;
	}
	if (!inet_ntop(soap_addr.sin_family, &soap_addr.sin_addr, soap_addr_str, sizeof(soap_addr_str))) {
		perror("inet_ntop");
		return -1 ;
	}
	ret = snprintf(location, sizeof(location), "http://%s:%d/MediaServer.xml", soap_addr_str, ntohs(soap_addr.sin_port));
	if (ret < 0 || ret >= sizeof(location)) {
		fprintf(stderr, "server location is too long\n");
		return -1;
	}
#endif
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		return -1;
	}
	opt = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
		perror("setsockopt SO_REUSEADDR");
		return -1;
	}
	opt = 2;
	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &opt, sizeof(opt)) != 0) {
		perror("setsockopt IP_MULTICAST_TTL");
		return -1;
	}
	if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) != 0) {
		perror("setsockopt IP_ADDR_MEMBERSHIP");
		return -1;
	}
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		perror("bind");
		return -1;
	}
	for (i = 0; i < ssdp->targets_len; ++i) {
		sendf(sock, (const struct sockaddr *)&ssdp_addr, sizeof(ssdp_addr),
			"NOTIFY * HTTP/1.1\r\n"
			"HOST: 239.255.255.250:1900\r\n"
			"CACHE-CONTROL: max-age=1800\r\n"
			"LOCATION: %s\r\n"
			"NT: %s\r\n"
			"NTS: ssdp:alive\r\n"
			"USN: %s\r\n"
			"\r\n",
			ssdp->location, ssdp->targets[i].nt, ssdp->targets[i].usn);
	}

	return sock;
}

void
ssdp_event(int sock, const struct ssdp_device *ssdp)
{
	char buf[4096], *pos, *end, *crlf, *st;
	struct http_header hdr;
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	ssize_t len;
	long mx;
	size_t i;

	len = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &addrlen);
	if (len < 0) {
		perror("recv");
		exit(1);
	}
	if (len == sizeof(buf)) {
		fprintf(stderr, "packet is too large\n");
		return;
	}
	pos = buf;
	end = buf + len;
	if (len < 21 || memcmp(pos, "M-SEARCH * HTTP/1.1\r\n", 21) != 0)
		return;
	pos += 21;
	mx = 0;
	st = NULL;
	for (;;) {
		crlf = memchr(pos, '\n', end - pos);
		if (!crlf || http_header(pos, crlf - pos + 1, &hdr) != 0)
			goto invalid;
		if (!hdr.name)
			break;
		if (strcasecmp(hdr.name, "MX") == 0) {
			errno = 0;
			mx = strtol(hdr.value, &pos, 10);
			if (*pos || errno || mx < 1 || mx > 5)
				goto invalid;
		} else if (strcasecmp(hdr.name, "ST") == 0) {
			st = hdr.value;
		}
		pos = crlf + 1;
	}
	if (!mx || !st)
		goto invalid;

	for (i = 0; i < ssdp->targets_len; ++i) {
		if (strcmp(ssdp->targets[i].nt, st) == 0 || strcmp(st, "ssdp:all") == 0) {
			fprintf(stderr, "[SSDP] search response %s\n", ssdp->targets[i].nt);
			sendf(sock, (struct sockaddr *)&addr, sizeof(addr),
				"HTTP/1.1 200 OK\r\n"
				"CACHE-CONTROL: max-age=1800\r\n"
				"EXT:\r\n"
				"LOCATION: %s\r\n"
				"SERVER: %s UPnP/1.0 upnp-av/" VERSION "\r\n"
				"ST: %s\r\n"
				"USN: %s\r\n"
				"\r\n",
				ssdp->location, ssdp->system, ssdp->targets[i].nt, ssdp->targets[i].usn);
		}
	}
	return;

invalid:
	fprintf(stderr, "invalid M-SEARCH message received\n");
}

void
ssdp_close(int sock, const struct ssdp_device *ssdp)
{
	size_t i;

	for (i = 0; i < ssdp->targets_len; ++i) {
		sendf(sock, (struct sockaddr *)&ssdp_addr, sizeof(ssdp_addr),
			"NOTIFY * HTTP/1.1\r\n"
			"HOST: 239.255.255.250:1900\r\n"
			"NT: %s\r\n"
			"NTS: ssdp:byebye\r\n"
			"USN: %s\r\n"
			"\r\n",
			ssdp->targets[i].nt, ssdp->targets[i].usn);
	}
	close(sock);
}

void
ssdp_target_init(struct ssdp_target *target, const char *uuid, const char *nt)
{
	if (nt) {
		strcpy(target->nt, nt);
		sprintf(target->usn, "uuid:%s::%s", uuid, nt);
	} else {
		sprintf(target->nt, "uuid:%s", uuid);
		sprintf(target->usn, "uuid:%s", uuid);
	}
}
