## upnp-av

upnp-av is a server implementing a minimal [UPnP MediaServer] device.
It presents the contents of a local directory as a [UPnP
ContentDirectory], enabling other devices on the network (such as
smart TVs) to browse the media files it contains. The files themselves
are then streamed by some other HTTP server which is configured
separately.

### Building

upnp-av is written in POSIX C99, and also requires `memmem`. It can
be built using

```
make
```

### Configuring an HTTP server

`upnp-mediaserver` implements directory navigation through the UPnP
ContentDirectory service. The transfer of the files is handled
through a standard HTTP server, serving that same directory at some
location.

One TV I tested with required a special DLNA header in order to
support pause and seeking: `contentFeatures.dlna.org: DLNA.ORG_OP=01`.
This allows the player to use the HTTP/1.1 `Range` header to fetch
certain fragments of the file. On nginx, this header can be added with

```
add_header contentFeatures.dlna.org DLNA.ORG_OP=01;
```

### Running

To run `upnp-mediaserver`, you must choose a UUID to identify the
server. This can be generated with `uuidgen` from util-linux.
Currently, you also need to explicitly specify the address to bind
to.

```
UUID=$(uuidgen)
upnp-mediaserver -l bind-address -C /path/to/media "$UUID" http://mediaserver/
```

Resource URLs are contructed by prepending the given URL prefix (in
this example, `http://mediaserver/`) with the URL-encoded filename
in the local directory. The expectation is that these map 1-1 with
the files served by the HTTP server.

### Current status

It works, but some of the code is a little rough and needs some
clean-up.

[UPnP MediaServer]: http://upnp.org/specs/av/UPnP-av-MediaServer-v1-Device.pdf
[UPnP ContentDirectory]: http://upnp.org/specs/av/UPnP-av-ContentDirectory-v1-Service.pdf
