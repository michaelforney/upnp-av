/* SPDX-License-Identifier: ISC */
#define LEN(a) (sizeof(a) / sizeof(*(a)))

char *url_escape(char *, size_t, const char *);
char *url_unescape(char *, size_t, const char *);
char *xml_escape(char *, size_t, const char *, int);
