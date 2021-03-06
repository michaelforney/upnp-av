/* SPDX-License-Identifier: ISC */
/* http://git.codemadness.org/xmlparser/file/README.html */
#ifndef _XML_H_
#define _XML_H_

#include <stdio.h>

typedef struct xmlparser {
	/* handlers */
	void (*xmlattr)(struct xmlparser *, const char *, size_t,
	      const char *, size_t, const char *, size_t);
	void (*xmlattrend)(struct xmlparser *, const char *, size_t,
	      const char *, size_t);
	void (*xmlattrstart)(struct xmlparser *, const char *, size_t,
	      const char *, size_t);
	void (*xmlattrentity)(struct xmlparser *, const char *, size_t,
	      const char *, size_t, const char *, size_t);
	void (*xmlcdatastart)(struct xmlparser *);
	void (*xmlcdata)(struct xmlparser *, const char *, size_t);
	void (*xmlcdataend)(struct xmlparser *);
	void (*xmlcommentstart)(struct xmlparser *);
	void (*xmlcomment)(struct xmlparser *, const char *, size_t);
	void (*xmlcommentend)(struct xmlparser *);
	void (*xmldata)(struct xmlparser *, const char *, size_t);
	void (*xmldataend)(struct xmlparser *);
	void (*xmldataentity)(struct xmlparser *, const char *, size_t);
	void (*xmldatastart)(struct xmlparser *);
	void (*xmltagend)(struct xmlparser *, const char *, size_t, int);
	void (*xmltagstart)(struct xmlparser *, const char *, size_t);
	void (*xmltagstartparsed)(struct xmlparser *, const char *,
	      size_t, int);

#ifndef GETNEXT
	#define GETNEXT() (x)->getnext(x)
	int (*getnext)(struct xmlparser *);
#endif

	/* current tag */
	char tag[1024];
	size_t taglen;
	/* current tag is in short form ? <tag /> */
	int isshorttag;
	/* current attribute name */
	char name[1024];
	/* data buffer used for tag data, cdata and attribute data */
	char data[BUFSIZ];
} XMLParser;

int xml_entitytostr(const char *, char *, size_t);
void xml_parse(XMLParser *);
#endif
