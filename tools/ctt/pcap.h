#ifndef CTT_PCAP_H
#define CTT_PCAP_H

#include <stddef.h>
#include <stdint.h>

int ctt_pcap_write_one(const char *path, const uint8_t *frame, size_t len);
int ctt_pcap_read_first(const char *path, uint8_t *frame, size_t cap,
                        size_t *out_len);
int ctt_bin_write(const char *path, const uint8_t *frame, size_t len);
int ctt_bin_read(const char *path, uint8_t *frame, size_t cap, size_t *out_len);

int ctt_golden_load(const char *path, uint8_t *frame, size_t cap, size_t *out_len);
int ctt_resolve_path(const char *scenario_path, const char *rel, char *out,
                     size_t cap);

#endif /* CTT_PCAP_H */
