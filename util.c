/* SPDX-License-Identifier: ISC */
#include <string.h>
#include "util.h"

static inline int
url_unreserved(int c)
{
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') ||
	       c == '-' || c == '.' || c == '_' || c  == '~' || c == '/' || c == '\0';
}

char *
url_escape(char *dst, size_t len, const char *src)
{
	char *end;
	int c;

	for (end = dst + len; dst < end; ++src) {
		c = (unsigned char)*src;
		if (url_unreserved(c)) {
			*dst++ = c;
			if (c == '\0')
				break;
		} else {
			static const char hex[] = "0123456789abcdef";
			if (end - dst < 3)
				return NULL;
			*dst++ = '%';
			*dst++ = hex[c >> 4];
			*dst++ = hex[c & 0xf];
		}
	}
	return dst;
}

static int
hex_value(int c)
{
	if ('0' <= c && c <= '9')
		return c - '0';
	if ('a' <= c && c <= 'f')
		return 10 + (c - 'a');
	if ('A' <= c && c <= 'F')
		return 10 + (c - 'A');
	return -1;
}

char *
url_unescape(char *dst, size_t len, const char *src)
{
	char *end;
	int c1, c2;

	for (end = dst + len; dst < end; ++src, ++dst) {
		if (*src == '%') {
			c1 = hex_value(*++src);
			c2 = hex_value(*++src);
			if (c1 == -1 || c2 == -1)
				return NULL;
			*dst = c1 << 4 | c2;
		} else if ((*dst = *src) == '\0') {
			break;
		}
	}
	return dst;
}

char *
xml_escape(char *dst, size_t len, const char *src, int dbl)
{
	char *end = dst + len;
	const char *esc;
	size_t esc_len;

	for (;;) {
		switch (*src) {
		case '<':  esc = "&lt;";   esc_len = 4; break;
		case '>':  esc = "&gt;";   esc_len = 4; break;
		case '&':  esc = "&amp;";  esc_len = 5; break;
		case '"':  esc = "&quot;"; esc_len = 6; break;
		case '\'': esc = "&apos;"; esc_len = 6; break;
		default:   esc = NULL;
		}
		if (esc) {
			if (esc[0] == '&' && dbl) {
				if (end - dst < 4 + esc_len)
					return NULL;
				memcpy(dst, "&amp;", 5);
				dst += 5;
				++esc;
				--esc_len;
			} else if (end - dst < esc_len) {
				return NULL;
			}
			memcpy(dst, esc, esc_len);
			dst += esc_len;
		} else if ((*dst++ = *src) == '\0') {
			break;
		}
		++src;
	}
	return dst;
}
