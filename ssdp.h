/* SPDX-License-Identifier: ISC */
struct ssdp_target {
	char nt[128];
	char usn[128];
};

struct ssdp_device {
	char system[128];
	char location[128];
	const struct ssdp_target *targets;
	size_t targets_len;
};

void ssdp_target_init(struct ssdp_target *, const char *, const char *);

int ssdp_open(const struct ssdp_device *);
void ssdp_event(int, const struct ssdp_device *);
void ssdp_close(int, const struct ssdp_device *);
