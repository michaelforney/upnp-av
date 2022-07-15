/* SPDX-License-Identifier: ISC */
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "xml.h"
#include "ssdp.h"
#include "http.h"
#include "util.h"

struct xmlns {
	char prefix[8];
	enum {
		NS_NONE,
		NS_SOAP,
		NS_CONTENTDIRECTORY,
		NS_CONNECTIONMANAGER,
		NS_UNKNOWN = -1,
	} id;
};

struct xmltag {
	int ns;
	enum {
		TAG_NONE,

		TAG_ENVELOPE,
		TAG_BODY,
	
		TAG_BROWSE,
		TAG_OBJECTID,
		TAG_BROWSEFLAG,
		TAG_FILTER,
		TAG_STARTINGINDEX,
		TAG_REQUESTEDCOUNT,
		TAG_SORTCRITERIA,
		TAG_GETSORTCAPABILITIES,
		TAG_GETSEARCHCAPABILITIES,
	} id;
	const char *str;
};

struct filetype {
	char ext[8];
	const char *mime;
	const char *upnp;
};

struct client {
	struct xmlparser xml;
	FILE *in, *out, *body;
	size_t content_length;

	struct xmlns ns[16];
	size_t ns_len;
	struct {
		const struct xmltag *tag;
		unsigned ns_len;
	} tags[8];
	size_t tags_len;
	int tag;

	int fault;

	/* invoked action */
	int action;
	/* action arguments */
	union {
		struct {
			char object_id[PATH_MAX];
			enum {
				BROWSE_METADATA,
				BROWSE_DIRECT_CHILDREN,
			} browse_flag;
			char *filter;
			size_t starting_index;
			size_t requested_count;
			char *sort_criteria;
		} browse;
	} u;
};

static char *argv0;
static int sigfd[2];
static const char *url_prefix;
static const char soap_prefix[] =
	"<s:Envelope xmlns:s=\"https://schemas.xmlsoap.org/soap/envelope/\""
	" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
	"<s:Body>";
static const char soap_suffix[] =
	"</s:Body>"
	"</s:Envelope>";
static const struct filetype filetypes[] = {
	{"", "application/octet-stream", "object.item"},
	// audio
	{"flac", "audio/flac", "object.item.audioItem"},
	{"mp3", "audio/mpeg", "object.item.audioItem"},
	{"ogg", "audio/ogg", "object.item.audioItem"},
	{"opus", "audio/opus", "object.item.audioItem"},
	{"wav", "audio/wav", "object.item.audioItem"},
	//video
	{"mp4", "video/mp4", "object.item.videoItem"},
	{"mkv", "video/x-matroska", "object.item.videoItem"},
	{"mov", "video/quicktime", "object.item.videoItem"},
	{"webm", "video/webm", "object.item.videoItem"},
	//image
	{"jpg", "image/jpeg", "object.item.imageItem"},
	{"png", "image/png", "object.item.imageItem"},
};
static char mediaserver_xml[] = {
#include "MediaServer.inc"
};
static const char contentdirectory_xml[] = {
#include "ContentDirectory.inc"
};
static const struct {
	const char *uri;
	const char *data;
	size_t size;
} static_files[] = {
	{"/MediaServer.xml", mediaserver_xml, sizeof(mediaserver_xml)},
	{"/ContentDirectory.xml", contentdirectory_xml, sizeof(contentdirectory_xml)},
};

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-l host] [-p port] [-C root] uuid urlprefix\n", argv0);
	exit(1);
}

static void
handle_signal(int sig)
{
	write(sigfd[1], &sig, sizeof(sig));
}

static void
soap_fault(struct client *c, int code, const char *fmt, ...)
{
	static const char fault_prefix[] =
		"<s:Fault>"
		"<faultcode>s:Client</faultcode>"
		"<faultstring>UPnPError</faultstring>"
		"<detail>"
		"<UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">";
	static const char fault_suffix[] =
		"</UPnPError>"
		"</detail>"
		"</s:Fault>";
	va_list ap;
		
	c->fault = 1;
	fwrite(soap_prefix, 1, sizeof(soap_prefix) - 1, c->body);
	fwrite(fault_prefix, 1, sizeof(fault_prefix) - 1, c->body);
	fprintf(c->body, "<errorCode>%d</errorCode><errorDescription>", code);
	va_start(ap, fmt);
	vfprintf(c->body, fmt, ap);
	va_end(ap);
	fputs("</errorDescription>", c->body);
	fwrite(fault_suffix, 1, sizeof(fault_suffix) - 1, c->body);
	fwrite(soap_suffix, 1, sizeof(soap_suffix) - 1, c->body);

	va_start(ap, fmt);
	fprintf(stderr, "[SOAP] fault: ");
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

static void
xmlattr(struct xmlparser *xml, const char *t, size_t tl, const char *a, size_t al, const char *v, size_t vl)
{
	struct client *c = (void *)xml;
	struct xmlns *ns;

	if (strncmp(a, "xmlns:", 6) == 0) {
		if (c->ns_len == LEN(c->ns)) {
			soap_fault(c, 501, "too many XML namespaces");
			return;
		}
		ns = &c->ns[c->ns_len++];
		if (!memccpy(ns->prefix, a + 6, '\0', sizeof(ns->prefix))) {
			soap_fault(c, 501, "namespace ID is too long\n");
			return;
		}
		if (strcmp(v, "http://schemas.xmlsoap.org/soap/envelope/") == 0)
			ns->id = NS_SOAP;
		else if (strcmp(v, "urn:schemas-upnp-org:service:ContentDirectory:1") == 0)
			ns->id = NS_CONTENTDIRECTORY;
		else if (strcmp(v, "urn:schemas-upnp-org:service:ConnectionManager:1") == 0)
			ns->id = NS_CONNECTIONMANAGER;
		else
			ns->id = NS_UNKNOWN;
	}
}

static const struct xmltag *
xmltag(struct client *c, const char *str)
{
	static const struct xmltag tags[] = {
		{NS_NONE, TAG_OBJECTID, "ObjectID"},
		{NS_NONE, TAG_BROWSEFLAG, "BrowseFlag"},
		{NS_NONE, TAG_FILTER, "Filter"},
		{NS_NONE, TAG_STARTINGINDEX, "StartingIndex"},
		{NS_NONE, TAG_REQUESTEDCOUNT, "RequestedCount"},
		{NS_NONE, TAG_SORTCRITERIA, "SortCriteria"},
		{NS_SOAP, TAG_ENVELOPE, "Envelope"},
		{NS_SOAP, TAG_BODY, "Body"},
		{NS_CONTENTDIRECTORY, TAG_BROWSE, "Browse"},
		{NS_CONTENTDIRECTORY, TAG_GETSORTCAPABILITIES, "GetSortCapabilities"},
		{NS_CONTENTDIRECTORY, TAG_GETSEARCHCAPABILITIES, "GetSearchCapabilities"},
	};
	const struct xmltag *t;
	const char *sep;
	int ns;
	size_t i;

	sep = strchr(str, ':');
	if (sep) {
		ns = NS_UNKNOWN;
		for (i = c->ns_len; i > 0;) {
			--i;
			if (strncmp(str, c->ns[i].prefix, strlen(c->ns[i].prefix)) == 0) {
				ns = c->ns[i].id;
				break;
			}
		}
		str = sep + 1;
	} else {
		ns = NS_NONE;
	}
	for (t = tags; t < tags + LEN(tags); ++t) {
		if (t->ns == ns && strcmp(t->str, str) == 0)
			return t;
	}
	return NULL;
}

static void
xmldata(struct xmlparser *xml, const char *d, size_t dl)
{
	struct client *c = (void *)xml;
	char *end;

	switch (c->tag) {
	case TAG_OBJECTID:
		if (dl + 1 > sizeof(c->u.browse.object_id)) {
			soap_fault(c, 603, "%s", strerror(errno));
			return;
		}
		memcpy(c->u.browse.object_id, d, dl + 1);
		break;
	case TAG_BROWSEFLAG:
		if (strcmp(d, "BrowseMetadata") == 0)
			c->u.browse.browse_flag = BROWSE_METADATA;
		else if (strcmp(d, "BrowseDirectChildren") == 0)
			c->u.browse.browse_flag = BROWSE_DIRECT_CHILDREN;
		else
			soap_fault(c, 600, "invalid BrowseFlag");
		break;
	case TAG_FILTER:
		break;
	case TAG_STARTINGINDEX:
		errno = 0;
		c->u.browse.starting_index = strtol(d, &end, 0);
		if (*end || errno)
			soap_fault(c, 600, "invalid StartingIndex");
		break;
	case TAG_REQUESTEDCOUNT:
		errno = 0;
		c->u.browse.requested_count = strtol(d, &end, 0);
		if (*end || errno)
			soap_fault(c, 600, "invalid RequestedCount");
		break;
	}
}

static void
xmltagend(struct xmlparser *xml, const char *t, size_t tl, int isshort)
{
	struct client *c = (void *)xml;
	const struct xmltag *tag;

	if (strcmp(t, "?xml") == 0)
		return;
	tag = xmltag(c, t);
	if (!tag || tag->id != c->tag) {
		soap_fault(c, 501, "unexpected XML closing tag");
		return;
	}
	assert(c->tags_len > 0);
	c->tag = --c->tags_len > 0 ? c->tags[c->tags_len - 1].tag->id : TAG_NONE;
}


static void
xmltagstartparsed(struct xmlparser *xml, const char *t, size_t tl, int isshort)
{
	struct client *c = (void *)xml;
	const struct xmltag *tag;

	if (strcmp(t, "?xml") == 0)
		return;
	if (c->tags_len == LEN(c->tags)) {
		soap_fault(c, 501, "XML tags nested too deep");
		return;
	}
	tag = xmltag(c, t);
	if (!tag) {
		soap_fault(c, 501, "unexpected XML tag '%s'", t);
		return;
	}
	switch (c->tag) {
	case TAG_NONE:
		if (tag->id != TAG_ENVELOPE) {
			soap_fault(c, 501, "expected SOAP Envelope");
			return;
		}
		break;
	case TAG_ENVELOPE:
		if (tag->id != TAG_BODY) {
			soap_fault(c, 501, "expected SOAP Body");
			return;
		}
		break;
	case TAG_BODY:
		switch (tag->id) {
		/* ContentDirectory */
		case TAG_BROWSE:
		case TAG_GETSORTCAPABILITIES:
		case TAG_GETSEARCHCAPABILITIES:
			if (c->action) {
				soap_fault(c, 501, "SOAP Body contains multiple tags");
				return;
			}
			c->action = tag->id;
			break;
		default:
			soap_fault(c, 401, "invalid action '%s'", tag->str);
			return;
		}
		break;
	case TAG_BROWSE:
		switch (tag->id) {
		case TAG_OBJECTID:
		case TAG_BROWSEFLAG:
		case TAG_FILTER:
		case TAG_STARTINGINDEX:
		case TAG_REQUESTEDCOUNT:
		case TAG_SORTCRITERIA:
			break;
		default:
			soap_fault(c, 402, "invalid Browse argument '%s'", t);
			return;
		}
		break;
	default:
		assert(0);
	}
	c->tags[c->tags_len].tag = tag;
	c->tags[c->tags_len].ns_len = c->ns_len;
	++c->tags_len;
	c->tag = tag->id;
}

static int
getnext(struct xmlparser *xml)
{
	struct client *c = (void *)xml;

	if (c->content_length == 0 || c->fault)
		return EOF;
	--c->content_length;
	return fgetc(c->in);
}

/* ContentDirectory */
static void
write_object(struct client *c, const char *path, const char *title, const char *id, const char *parent_id, int parent_id_len)
{
	struct stat st;
	const char *ext;
	size_t i;
	const struct filetype *type;
	char xml_title[NAME_MAX], date[16] = "";
	struct tm tm;

	if (stat(path, &st) != 0)
		return;
	if (!xml_escape(xml_title, sizeof(xml_title), title, 1))
		return;
	if (localtime_r(&st.st_mtime, &tm))
		strftime(date, sizeof(date), "%Y-%m-%d", &tm);
	if (S_ISDIR(st.st_mode)) {
		fprintf(c->body,
			"&lt;container id=&quot;%s&quot; parentID=&quot;%.*s&quot; restricted=&quot;true&quot;&gt;"
			"&lt;dc:title&gt;%s&lt;/dc:title&gt;"
			"&lt;dc:date&gt;%s&lt;/dc:date&gt;"
			"&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;"
			"&lt;/container&gt;",
			id, parent_id_len, parent_id, xml_title, date);
	} else {
		type = &filetypes[0];
		for (ext = path + strlen(path); ext > path; --ext) {
			if (ext[-1] == '.') {
				for (i = 1; i < LEN(filetypes); ++i) {
					if (strcmp(filetypes[i].ext, ext) == 0) {
						type = &filetypes[i];
						break;
					}
				}
				break;
			}
		}
		fprintf(c->body,
			"&lt;item id=&quot;%s&quot; parentID=&quot;%.*s&quot; restricted=&quot;true&quot;&gt;"
			"&lt;dc:title&gt;%s&lt;/dc:title&gt;"
			"&lt;dc:date&gt;%s&lt;/dc:date&gt;"
			"&lt;upnp:class&gt;%s&lt;/upnp:class&gt;"
			"&lt;res protocolInfo=&quot;http-get:*:%s:*&quot; size=&quot;%ju&quot;&gt;%s%s&lt;/res&gt;"
			"&lt;/item&gt;",
			id, parent_id_len, parent_id, xml_title, date,
			type->upnp, type->mime, (uintmax_t)st.st_size, url_prefix, id);
	}
}

static void
browse(struct client *c, const char *id, size_t starting_index, size_t requested_count)
{
	static const char prefix[] =
		"<u:BrowseResponse xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\">"
		"<Result>"
		"&lt;DIDL-Lite xmlns:dc=&quot;http://purl.org/dc/elements/1.1/&quot;"
		" xmlns:upnp=&quot;urn:schemas-upnp-org:metadata-1-0/upnp/&quot;"
		" xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&quot;&gt;";
	static const char suffix[] =
		"&lt;/DIDL-Lite&gt;"
		"</Result>";
	char path[PATH_MAX], id_buf[PATH_MAX], *title, *path_end, *parent_id_end, *id_end;
	const char *parent_id;
	int parent_id_len;
	DIR *dir;
	struct dirent *d;
	size_t total_matches, number_returned;

	fwrite(soap_prefix, 1, sizeof(soap_prefix) - 1, c->body);

	if (strcmp(id, "0") == 0) {
		strcpy(path, ".");
		path_end = path;
	} else {
		path_end = url_unescape(path, sizeof(path), id);
	}
	fprintf(stderr, "[SOAP] Browse(\"%s\", %zu, %zu)\n", id, starting_index, requested_count);
	fwrite(prefix, 1, sizeof(prefix) - 1, c->body);
	number_returned = 0;
	total_matches = 0;
	switch (c->u.browse.browse_flag) {
	case BROWSE_METADATA:
		for (title = path_end; title > path; --title) {
			if (title[-1] == '/')
				break;
		}
		parent_id_end = strrchr(id, '/');
		if (parent_id_end) {
			parent_id = id;
			if (parent_id_end - id > INT_MAX)
				return;
			parent_id_len = parent_id_end - id;
		} else if (strcmp(id, "0") == 0) {
			parent_id = "-1";
			parent_id_len = 2;
		} else {
			parent_id = "0";
			parent_id_len = 1;
		}
		write_object(c, path, title, id, parent_id, parent_id_len);
		++number_returned;
		++total_matches;
		break;
	case BROWSE_DIRECT_CHILDREN:
		parent_id = id;
		if (strcmp(id, "0") == 0) {
			id_end = id_buf;
			parent_id_len = 1;
		} else {
			id_end = memccpy(id_buf, id, '\0', sizeof(id_buf));
			if (!id_end)
				return;
			id_end[-1] = '/';
			parent_id_len = id_end - id_buf - 1;
		}
		dir = opendir(path);
		if (!dir)
			return;
		if (path_end != path)
			*path_end++ = '/';
		while ((d = readdir(dir))) {
			if (d->d_name[0] == '.' && (!d->d_name[1] || (d->d_name[1] == '.' && !d->d_name[2])))
				continue;
			++total_matches;
			if (starting_index > 0) {
				--starting_index;
				continue;
			}
			if (requested_count > 0 && number_returned == requested_count)
				continue;
			if (!memccpy(path_end, d->d_name, '\0', sizeof(path) - (path_end - path)))
				return;
			if (!url_escape(id_end, sizeof(id_buf) - (id_end - id_buf), d->d_name))
				return;
			write_object(c, path, d->d_name, id_buf, parent_id, parent_id_len);
			++number_returned;
		}
		closedir(dir);
		break;
	}
	fwrite(suffix, 1, sizeof(suffix) - 1, c->body);
	fprintf(c->body,
		"<NumberReturned>%zu</NumberReturned>"
		"<TotalMatches>%zu</TotalMatches>"
		"<UpdateID>1</UpdateID>"
		"</u:BrowseResponse>",
		number_returned, total_matches);
	fwrite(soap_suffix, 1, sizeof(soap_suffix) - 1, c->body);
}

static void
get_sort_capabilities(struct client *c)
{
	static const char response[] =
		"<u:GetSortCapabilitiesResponse xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\">"
		"<SortCaps></SortCaps>"
		"</u:GetSortCapabilitiesResponse>";
	fprintf(stderr, "[SOAP] GetSortCapabilities()\n");
	fwrite(soap_prefix, 1, sizeof(soap_prefix) - 1, c->body);
	fwrite(response, 1, sizeof(response) - 1, c->body);
	fwrite(soap_suffix, 1, sizeof(soap_suffix) - 1, c->body);
}

static void
get_search_capabilities(struct client *c)
{
	static const char response[] =
		"<u:GetSearchCapabilitiesResponse xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\">"
		"<SearchCaps></SearchCaps>"
		"</u:GetSearchCapabilitiesResponse>";
	fprintf(stderr, "[SOAP] GetSearchCapabilities()\n");
	fwrite(soap_prefix, 1, sizeof(soap_prefix) - 1, c->body);
	fwrite(response, 1, sizeof(response) - 1, c->body);
	fwrite(soap_suffix, 1, sizeof(soap_suffix) - 1, c->body);
}

static void
skip_data(FILE *fp, size_t len)
{
	char buf[8192];
	size_t blk, ret;

	fprintf(stderr, "skipping %zu\n", len);
	while (len > 0) {
		blk = len < sizeof(buf) ? len : sizeof(buf);
		ret = fread(buf, 1, blk, fp);
		if (ret != blk)
			break;
		len -= ret;
	}
}

static void
process_request(struct client *c, char **buf, size_t *cap)
{
	char *body, *end;
	struct http_request req;
	struct http_header hdr;
	size_t body_len, i;
	ssize_t len;
	int close;
	char uri[PATH_MAX];

	memset(&c->u, 0, sizeof(c->u));
	c->content_length = 0;
	c->ns_len = 0;
	c->tags_len = 0;
	c->tag = TAG_NONE;
	c->action = TAG_NONE;
	c->fault = 0;

	len = getline(buf, cap, c->in);
	if (len < 0) {
		if (ferror(c->in))
			perror("getline");
		goto fail;
	}
	if (http_request(*buf, len, &req) != 0) {
		http_error(c->out, 400, "Bad Request", NULL, 0);
		return;
	}
	if (!memccpy(uri, req.uri, '\0', sizeof(uri)))
		uri[0] = '\0';
	fprintf(stderr, "[HTTP] requested URI %s\n", req.uri);
	close = 0;
	for (;;) {
		len = getline(buf, cap, c->in);
		if (len < 0) {
			if (ferror(c->in))
				perror("getline");
			goto fail;
		}
		if (http_header(*buf, len, &hdr) != 0) {
			http_error(c->out, 400, "Bad Request", NULL, 0);
			return;
		}
		if (!hdr.name)
			break;
		if (strcasecmp(hdr.name, "Content-Length") == 0) {
			errno = 0;
			c->content_length = strtol(hdr.value, &end, 10);
			if (*end || errno) {
				http_error(c->out, 400, "Bad Request", NULL, 0);
				return;
			}
		} else if (strcasecmp(hdr.name, "Connection") == 0) {
			if (strcasecmp(hdr.value, "close") == 0)
				close = 1;
			else if (strcasecmp(hdr.value, "keep-alive") == 0)
				close = 0;
		}
	}
	if (strcmp(uri, "/control") == 0) {
		if (req.method != HTTP_POST) {
			http_error(c->out, 405, "Method Not Allowed", (const char *[]){"Allow:POST"}, 1);
			goto done;
		}
		c->body = open_memstream(&body, &body_len);
		if (!c->body) {
			perror("open_memstream");
			http_error(c->out, 500, "Internal Server Error", NULL, 0);
			goto done;
		}
		xml_parse(&c->xml);
		if (c->fault) {
			skip_data(c->in, c->content_length);

			fflush(c->body);
			fprintf(c->out, "HTTP/1.1 500 Internal Server Error\r\nContent-Type:text/xml;charset=utf-8\r\nContent-Length:%zu\r\n\r\n", body_len);
			fwrite(body, 1, body_len, c->out);
			goto done;
		}
		switch (c->action) {
		/* ContentDirectory */
		case TAG_BROWSE:
			browse(c, c->u.browse.object_id, c->u.browse.starting_index, c->u.browse.requested_count);
			break;
		case TAG_GETSORTCAPABILITIES:
			get_sort_capabilities(c);
			break;
		case TAG_GETSEARCHCAPABILITIES:
			get_search_capabilities(c);
			break;
		default:
			printf("unknown action %d\n", c->action);
		}
		fflush(c->body);
		if (ferror(c->body)) {
			fprintf(stderr, "error writing body\n");
		}
		fprintf(c->out, "HTTP/1.1 200 OK\r\nContent-Type:text/xml;charset=utf-8\r\nContent-Length:%zu\r\n\r\n", body_len);
		fwrite(body, 1, body_len, c->out);
	} else {
		for (i = 0; i < LEN(static_files); ++i) {
			if (strcmp(uri, static_files[i].uri) == 0)
				break;
		}
		if (i == LEN(static_files)) {
			http_error(c->out, 404, "Not Found", NULL, 0);
			goto done;
		}
		if (req.method != HTTP_GET) {
			http_error(c->out, 405, "Method Not Allowed", (const char *[]){"Allow:GET"}, 1);
			goto done;
		}
		fprintf(c->out, "HTTP/1.1 200 OK\r\nContent-Type:text/xml;charset=utf-8\r\nContent-Length:%zu\r\n\r\n", static_files[i].size);
		fwrite(static_files[i].data, 1, static_files[i].size, c->out);
	}
done:
	fflush(c->out);
	if (ferror(c->out) || close) {
fail:
		fclose(c->in);
		c->in = NULL;
	}
}

static void *
client_main(void *arg)
{
	struct client c = {
		.xml = {
			.xmlattr = xmlattr,
			.xmldata = xmldata,
			.xmltagend = xmltagend,
			.xmltagstartparsed = xmltagstartparsed,
			.getnext = getnext,
		},
		c.in = arg,
	};
	int fdout;
	char *buf = NULL;
	size_t cap = 0;

	fdout = dup(fileno(c.in));
	if (fdout < 0) {
		perror("dup");
		fclose(c.in);
		return NULL;
	}
	c.out = fdopen(fdout, "w");
	if (!c.out) {
		perror("fdopen");
		fclose(c.in);
		close(fdout);
		return NULL;
	}
	while (c.in)
		process_request(&c, &buf, &cap);
	free(buf);
	fclose(c.out);
	return NULL;
}

static int
soap_open(const char *host, int port)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr = {.s_addr = INADDR_ANY},
		.sin_port = htons(port),
	};
	int sock, opt;

	if (host && inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
		fprintf(stderr, "invalid IPv4 address '%s'\n", host);
		return -1;
	}
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return -1;
	}
	opt = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
		perror("setsockopt SO_REUSEADDR");
		return -1;
	}
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		perror("bind");
		return -1;
	}
	if (listen(sock, 0) != 0) {
		perror("listen");
		return -1;
	}

	return sock;
}

static void
soap_close(int sock)
{
	close(sock);
}

static void
soap_event(int sock)
{
	int fd, err;
	FILE *in;
	pthread_t thread;
	pthread_attr_t attr;

	fd = accept(sock, NULL, 0);
	if (fd < 0) {
		perror("accept");
		return;
	}
	in = fdopen(fd, "r");
	if (!in) {
		perror("fdopen");
		close(fd);
		return;
	}
	err = pthread_attr_init(&attr);
	if (err) {
		fprintf(stderr, "pthread_attr_init: %s\n", strerror(err));
		fclose(in);
		return;
	}
	err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (err) {
		fprintf(stderr, "pthread_attr_setdetachstate: %s\n", strerror(err));
		fclose(in);
		return;
	}
	err = pthread_create(&thread, &attr, client_main, in);
	if (err) {
		fprintf(stderr, "pthread_create: %s\n", strerror(err));
		fclose(in);
		return;
	}
}

static int
valid_uuid(const char *uuid)
{
	const char *ref = "00000000-0000-0000-0000-000000000000";

	for (; *ref; ++ref, ++uuid) {
		if (*ref == '-') {
			if (*uuid != '-')
				return 0;
		} else if (!isxdigit(*uuid)) {
			return 0;
		}
	}
	return *uuid == '\0';
}

int
main(int argc, char *argv[])
{
	const char *host = NULL, *uuid;
	struct sockaddr_in addr;
	socklen_t addr_len;
	char addr_str[INET_ADDRSTRLEN], *pos;
	struct utsname uts;
	struct pollfd pfd[3];
	struct ssdp_target targets[4];
	struct ssdp_device ssdp = {
		.targets = targets,
		.targets_len = LEN(targets),
	};
	int opt, sig, ret, port = 0;

	argv0 = argc ? argv[0] : "upnp-mediaserver";
	while ((opt = getopt(argc, argv, "C:l:p:")) != -1) {
		switch (opt) {
		case 'C':
			if (chdir(optarg) != 0) {
				fprintf(stderr, "chdir %s: %s\n", optarg, strerror(errno));
				return 1;
			}
			break;
		case 'l':
			host = optarg;
			break;
		case 'p':
			port = strtol(optarg, NULL, 10);
			break;
		case '?':
			usage();
			break;
		}
	}
	argv += optind;
	argc -= optind;
	if (argc != 2 || !valid_uuid(argv[0]))
		usage();
	uuid = argv[0];
	url_prefix = argv[1];

	/* replace UUID in MediaServer XML description */
	pos = memmem(mediaserver_xml, sizeof(mediaserver_xml), "uuid:", 5);
	assert(pos);
	memcpy(pos + 5, uuid, 36);

	if (pipe(sigfd) != 0) {
		perror("pipe");
		return 1;
	}
	if (signal(SIGINT, handle_signal) != 0) {
		perror("signal SIGINT");
		return 1;
	}
	if (signal(SIGTERM, handle_signal) != 0) {
		perror("signal SIGTERM");
		return 1;
	}
	ssdp_target_init(&targets[0], uuid, "upnp:rootdevice");
	ssdp_target_init(&targets[1], uuid, NULL);
	ssdp_target_init(&targets[2], uuid, "urn:schemas-upnp-org:device:MediaServer:1");
	ssdp_target_init(&targets[3], uuid, "urn:schemas-upnp-org:service:ContentDirectory:1");

	pfd[0].fd = sigfd[0];
	pfd[0].events = POLLIN;

	/* start SOAP */
	pfd[1].fd = soap_open(host, port);
	if (pfd[1].fd < 0)
		return 1;
	pfd[1].events = POLLIN;

	/* initialize SSDP device fields */
	addr_len = sizeof(addr);
	if (getsockname(pfd[1].fd, (struct sockaddr *)&addr, &addr_len) != 0) {
		perror("getsockname");
		return 1;
	}
	if (!inet_ntop(addr.sin_family, &addr.sin_addr, addr_str, sizeof(addr_str))) {
		perror("inet_ntop");
		return 1;
	}
	ret = snprintf(ssdp.location, sizeof(ssdp.location), "http://%s:%d/MediaServer.xml", addr_str, (int)ntohs(addr.sin_port));
	if (ret < 0 || ret >= sizeof(ssdp.location)) {
		fprintf(stderr, "server location is too long\n");
		return 1;
	}
	if (uname(&uts) != 0) {
		perror("uname");
		return 1;
	}
	ret = snprintf(ssdp.system, sizeof(ssdp.system), "%s/%s", uts.sysname, uts.release);
	if (ret < 0 || ret >= sizeof(ssdp.system)) {
		fprintf(stderr, "system name is too long\n");
		return 1;
	}

	/* start SSDP */
	pfd[2].fd = ssdp_open(&ssdp);
	if (pfd[2].fd < 0)
		return 1;
	pfd[2].events = POLLIN;

	fprintf(stderr, "[HTTP] listening on http://%s:%d\n", addr_str, (int)ntohs(addr.sin_port));

	for (;;) {
		while (poll(pfd, LEN(pfd), -1) < 0 && errno == EINTR)
			;
		if (pfd[0].revents & POLLIN && read(sigfd[0], &sig, sizeof(sig)) == sizeof(sig)) {
			switch (sig) {
			case SIGINT:
			case SIGTERM:
				goto quit;
			}
		}
		if (pfd[1].revents & POLLIN)
			soap_event(pfd[1].fd);
		if (pfd[2].revents & POLLIN)
			ssdp_event(pfd[2].fd, &ssdp);
	}

quit:
	ssdp_close(pfd[2].fd, &ssdp);
	soap_close(pfd[1].fd);
	_exit(0);
}
