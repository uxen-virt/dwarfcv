
#ifndef _DWARFCV_H_
#define _DWARFCV_H_

#define _exit(val) exit(val)
#ifdef _WIN32
#define ERR_WINDOWS
#endif
#include "err.h"

#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define PACKAGE "dwarfcv"
#include <bfd.h>
#define _offsetof(st, m) ((size_t)(&((st *)0)->m))
#define err_bfd(fmt, ...)                                               \
    errx(1, fmt ": %s", ## __VA_ARGS__, bfd_errmsg(bfd_get_error()))

#define aprintf(fmt, ...)                                               \
    printf("%s:%d " fmt, __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define dprintf(fmt, ...) do {                                          \
        if (dprint)                                                     \
            printf("%s:%d " fmt, __FUNCTION__, __LINE__, ## __VA_ARGS__); \
    } while (0)
#define dnewline() do {                         \
        if (dprint)                             \
            printf("\n");                       \
    } while (0)
#define vprintf(fmt, ...) do {                                          \
        if (vprint)                                                     \
            printf("%s:%d " fmt, __FUNCTION__, __LINE__, ## __VA_ARGS__); \
    } while (0)

/* dwarfcv.c */
extern int dprint;
extern int vprint;

extern int portion_align;

extern unsigned int debug_abbrev_length;
extern uint8_t *debug_abbrev;
extern unsigned int debug_frame_length;
extern uint8_t *debug_frame;
extern unsigned int debug_info_length;
extern uint8_t *debug_info;
extern unsigned int debug_line_length;
extern uint8_t *debug_line;
extern unsigned int debug_loc_length;
extern uint8_t *debug_loc;
extern unsigned int debug_ranges_length;
extern uint8_t *debug_ranges;
extern uint8_t *debug_str;

extern int symcount;
extern asymbol **isympp;

#define SYMTYPE_FIRST 0
#define SYMTYPE_STATIC 1
#define SYMTYPE_GLOBAL 2
#define SYMTYPE_USER 3
#define SYMTYPE_debugS 4
#define NR_SYMTYPE 5

extern unsigned int reloc_off[NR_SYMTYPE];

extern uint8_t *debugS;
extern unsigned long debugS_length;
extern uint8_t *debugT;
extern unsigned long debugT_length;
extern uint8_t *file_strings;
extern unsigned long file_strings_length;
extern uint8_t *file_info;
extern unsigned long file_info_length;

bool add_reloc(struct bfd *bfd, int symtype, asymbol **asym,
               int secrel_offset, int section_offset);

/* image.c */
void read_sections(struct bfd *);
asymbol **find_symbol(struct bfd *bfd, const char *name);
asection *find_section(struct bfd *bfd, uint64_t vma);

struct section_info {
    asymbol **sym_ptr_ptr;
};
typedef struct section_info section_info;

extern section_info *all_sec;

/* lines.c */
void process_lines(struct bfd *bfd);

/* symtypes.c */
void process_types(struct bfd *bfd);
void process_symbols(struct bfd *bfd);

#endif  /* _DWARFCV_H_ */
