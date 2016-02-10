
#include "dwarfcv.h"

#ifdef _WIN32
DECLARE_PROGNAME;
#endif  /* _WIN32 */

int dprint = 0;
int vprint = 0;

int portion_align = 4;

static void setup_section(bfd *, asection *, void *);
static void copy_relocations_in_section(bfd *, asection *, void *);
static void copy_section(bfd *, asection *, void *);

static void create_section(bfd *, const char *, size_t, int);
static void fill_section(bfd *, const char *, uint8_t *, size_t);
#if 0
static void add_reloc_section(bfd *abfd, const char *name, arelent *relents,
                              int nr, int offset);
#endif
static void add_relocs_to_section(bfd *abfd, const char *name);

unsigned int debug_abbrev_length = 0;
uint8_t *debug_abbrev = NULL;
unsigned int debug_frame_length = 0;
uint8_t *debug_frame = NULL;
unsigned int debug_info_length = 0;
uint8_t *debug_info = NULL;
unsigned int debug_line_length = 0;
uint8_t *debug_line = NULL;
unsigned int debug_loc_length = 0;
uint8_t *debug_loc = NULL;
unsigned int debug_ranges_length = 0;
uint8_t *debug_ranges = NULL;
uint8_t *debug_str = NULL;

asymbol **isympp = NULL;
static asymbol **osympp = NULL;
int symcount;

static arelent *reloc[NR_SYMTYPE];
static unsigned int reloc_idx[NR_SYMTYPE];
static unsigned int reloc_max[NR_SYMTYPE];
unsigned int reloc_off[NR_SYMTYPE];

uint8_t *debugS = NULL;
unsigned long debugS_length = 0;
uint8_t *debugT = NULL;
unsigned long debugT_length = 0;
uint8_t *file_strings = NULL;
unsigned long file_strings_length = 0;
uint8_t *file_info = NULL;
unsigned long file_info_length = 0;

static void
usage(void)
{

    errx(1, "usage: [-d] in.o out.o\n");
}

int
main(int argc, char **argv, char **envp)
{
    bfd *ibfd, *obfd;
    char **matching;
    int ret;

#ifdef _WIN32
    setprogname(argv[0]);
#endif  /* _WIN32 */

    while (1) {
        int c, index = 0;

        /* enum { LI_xxx }; */

        static int long_index;
        static struct option long_options[] = {
            {"debug",         no_argument,       NULL,       'd'},
            {"help",          no_argument,       NULL,       'h'},
            {"verbose",       no_argument,       NULL,       'v'},

            {NULL,   0,                 NULL, 0}
        };

        long_index = 0;
        c = getopt_long(argc, argv, "dhv", long_options,
                        &index);
        if (c == -1)
            break;

        switch (c) {
        case 0:
            switch (long_index) {
            /* case LI_xxx: */
            /*     break; */
            }
            break;
        case 'd':
            dprint = 1;
            break;
        case 'h':
            usage();
            /* NOTREACHED */
        case 'v':
            vprint = 1;
            break;
        }
    }
    argc -= optind;
    argv += optind;

    if (argc != 2)
        usage();

    ibfd = bfd_openr(argv[0], NULL);
    if (!ibfd)
        err_bfd("bfd_openr failed");

    ret = bfd_check_format_matches(ibfd, bfd_object, &matching);
    if (!ret) {
        if (bfd_get_error () != bfd_error_file_ambiguously_recognized)
            err_bfd("bfd_check_format_matches failed");

        ret = bfd_close(ibfd);
        ibfd = bfd_openr(argv[0], matching[0]);
        if (!ibfd)
            err_bfd("bfd_openr failed");

        ret = bfd_check_format(ibfd, bfd_object);
        if (!ret)
            err_bfd("bfd_check_format failed");
    }

    obfd = bfd_openw(argv[1], bfd_get_target(ibfd));
    if (!obfd)
        errx(1, "bfd_openw failed");

    ret = bfd_set_arch_mach(obfd, bfd_get_arch(ibfd), bfd_get_mach(ibfd));
    if (!ret)
        err_bfd("bfd_set_arch_mach failed");

    ret = bfd_set_format(obfd, bfd_get_format(ibfd));
    if (!ret)
        err_bfd("bfd_set_format failed");

    ret = bfd_set_start_address(obfd, bfd_get_start_address(ibfd));
    if (!ret)
        err_bfd("bfd_set_start_address failed");

    ret = bfd_set_file_flags(obfd, bfd_get_file_flags(ibfd));
    if (!ret)
        err_bfd("bfd_set_file_flags failed");

    if (!ibfd->sections)
        errx(1, "input file %s has no sections",
             bfd_get_filename(ibfd));

    vprintf("copy from `%s' [%s] to `%s' [%s]\n",
            bfd_get_filename(ibfd), bfd_get_target(ibfd),
            bfd_get_filename(obfd), bfd_get_target(obfd));

    long symsize;
    symsize = bfd_get_symtab_upper_bound(ibfd);
    if (symsize < 0)
        err_bfd("bfd_get_symtab_upper_bound failed");

    osympp = isympp = (asymbol **)malloc(symsize);
    if (!isympp)
        err(1, "malloc symsize %ld failed", symsize);
    (void)osympp;

    symcount = bfd_canonicalize_symtab(ibfd, isympp);
    if (symcount == 0) {
        free(isympp);
        osympp = isympp = NULL;
    }

    read_sections(ibfd);

    memset(reloc, 0, sizeof(reloc));
    memset(reloc_idx, 0, sizeof(reloc_idx));
    memset(reloc_max, 0, sizeof(reloc_max));
    memset(reloc_off, 0, sizeof(reloc_off));

    process_types(ibfd);

    process_symbols(ibfd);

    process_lines(ibfd);

    bfd_map_over_sections(ibfd, setup_section, obfd);

    if (file_info_length) {
        debugS = (uint8_t *)realloc(debugS, debugS_length +
                                    file_info_length + portion_align);
        *(unsigned int *)&file_info[sizeof(unsigned int)] =
            file_info_length - sizeof(unsigned int) -
            sizeof(unsigned int);
        memcpy(debugS + debugS_length, file_info, file_info_length);
        debugS_length += file_info_length;
        while (debugS_length % portion_align)
            debugS[debugS_length++] = 0;

        debugS = (uint8_t *)realloc(debugS, debugS_length +
                                    file_strings_length + portion_align);
        *(unsigned int *)&file_strings[sizeof(unsigned int)] =
            file_strings_length - sizeof(unsigned int) -
            sizeof(unsigned int);
        memcpy(debugS + debugS_length, file_strings, file_strings_length);
        debugS_length += file_strings_length;
        while (debugS_length % portion_align)
            debugS[debugS_length++] = 0;
    }
    if (debugS_length)
        create_section(obfd, ".debug$S", debugS_length, 0);
    if (debugT_length)
        create_section(obfd, ".debug$T", debugT_length, 0);

    bfd_set_symtab(obfd, osympp, symcount);

    bfd_map_over_sections(ibfd, copy_relocations_in_section, obfd);

    add_relocs_to_section(obfd, ".debug$S");

    bfd_map_over_sections(ibfd, copy_section, obfd);

    if (debugS_length)
        fill_section(obfd, ".debug$S", debugS, debugS_length);
    if (debugT_length)
        fill_section(obfd, ".debug$T", debugT, debugT_length);

    ret = bfd_close(obfd);
    if (!ret)
        err_bfd("bfd_close failed");

    return 0;
}

static void
setup_section(bfd *ibfd, asection *isection, void *obfdarg)
{
    bfd *obfd = (bfd *)obfdarg;
    sec_ptr osection;
    bfd_size_type size;
    bfd_vma vma;
    bfd_vma lma;
    flagword flags;
    const char *name;

    name = bfd_section_name(ibfd, isection);

    if (!strcmp(name, ".debug$S"))
        name = ".odebug$S";
    else if (!strcmp(name, ".debug$T"))
        name = ".odebug$T";

    flags = bfd_get_section_flags(ibfd, isection);

    osection = bfd_make_section_anyway_with_flags(obfd, name, flags);
    if (!osection)
        err_bfd("failed to create output section");

    size = bfd_section_size(ibfd, isection);
    if (!bfd_set_section_size(obfd, osection, size))
        err_bfd("failed to set size");

    vma = bfd_section_vma(ibfd, isection);
    if (!bfd_set_section_vma(obfd, osection, vma))
        err_bfd("failed to set vma");

    lma = isection->lma;
    osection->lma = lma;

    /* FIXME: This is probably not enough.  If we change the LMA we
       may have to recompute the header for the file as well.  */
    if (!bfd_set_section_alignment(obfd,
                                   osection,
                                   bfd_section_alignment(ibfd, isection)))
        err_bfd("failed to set alignment");

    /* Copy merge entity size.  */
    osection->entsize = isection->entsize;

    /* This used to be mangle_section; we do here to avoid using
       bfd_get_section_by_name since some formats allow multiple
       sections with the same name.  */
    isection->output_section = osection;
    isection->output_offset = 0;
}

static void
copy_relocations_in_section(bfd *ibfd, asection *isection, void *obfdarg)
{
  bfd *obfd = (bfd *)obfdarg;
  long relsize;
  arelent **relpp;
  long relcount;
  sec_ptr osection;

  osection = isection->output_section;

  relsize = bfd_get_reloc_upper_bound(ibfd, isection);
  if (relsize < 0)
      err_bfd("bfd_get_reloc_upper_bound failed");

  if (relsize == 0) {
      bfd_set_reloc (obfd, osection, NULL, 0);
      osection->flags &= ~SEC_RELOC;
  } else {
      relpp = (arelent **)malloc(relsize);
      relcount = bfd_canonicalize_reloc(ibfd, isection, relpp, isympp);
      if (relcount < 0)
          err_bfd("bfd_canonicalize_reloc failed");

      bfd_set_reloc (obfd, osection, relcount == 0 ? NULL : relpp, relcount);
      if (relcount == 0) {
	  osection->flags &= ~SEC_RELOC;
	  free (relpp);
      }
  }
}

static void
copy_section(bfd *ibfd, sec_ptr isection, void *obfdarg)
{
  bfd *obfd = (bfd *)obfdarg;
  sec_ptr osection;
  bfd_size_type size;

  osection = isection->output_section;
  size = bfd_get_section_size(isection);

  if (bfd_get_section_flags(ibfd, isection) & SEC_HAS_CONTENTS
      && bfd_get_section_flags(obfd, osection) & SEC_HAS_CONTENTS) {
      bfd_byte *memhunk = NULL;

      if (!bfd_get_full_section_contents(ibfd, isection, &memhunk))
          err_bfd("bfd_get_full_section_contents failed");

      if (!bfd_set_section_contents(obfd, osection, memhunk, 0, size))
          err_bfd("bfd_set_section_contents failed");
      free (memhunk);
  }
}

static void
create_section(bfd *obfd, const char *name, size_t size, int alignment)
{
    sec_ptr osection;
    flagword flags;

    flags = SEC_HAS_CONTENTS | SEC_READONLY | SEC_DEBUGGING;

    osection = bfd_make_section_anyway_with_flags(obfd, name, flags);
    if (!osection)
        err_bfd("failed to create output section");

    if (!bfd_set_section_size(obfd, osection, size))
        err_bfd("failed to set size");

    if (!bfd_set_section_alignment(obfd, osection, alignment))
        err_bfd("failed to set alignment");
}

static void
fill_section(bfd *abfd, const char *name, uint8_t *data, size_t size)
{
    sec_ptr osection;
    int ret;

    osection = bfd_get_section_by_name(abfd, name);
    if (!osection)
        err_bfd("bfd_get_section_by_name failed");

#if 0
    if (size != bfd_section_size(abfd, osection))
        errx(1, "size mismatch %ld != %ld\n", (long)size,
             (long)bfd_section_size(abfd, osection));
#endif

    ret = bfd_set_section_contents(abfd, osection, data, 0, size);
    if (!ret)
        err_bfd("bfd_set_section_contents failed");
}

#if 0
static void
add_reloc_section(bfd *abfd, const char *name, arelent *reloc, int relcount,
                  int offset)
{
    sec_ptr osection;
    arelent **relpp;
    int n;

    relpp = (arelent **)malloc(relcount * sizeof(arelent *));
    for (n = 0; n < relcount; n++) {
        relpp[n] = &reloc[n];
        reloc[n].address += offset;
    }

    osection = bfd_get_section_by_name(abfd, name);
    if (!osection)
        err_bfd("bfd_get_section_by_name failed");

    bfd_set_reloc(abfd, osection, relpp, relcount);
}
#endif

static void
add_relocs_to_section(bfd *abfd, const char *name)
{
    int type;
    sec_ptr osection;
    arelent **relpp;
    int n;
    int relcount;
    arelent *relent;

    relcount = 0;
    for (type = 0; type < NR_SYMTYPE; type++)
        relcount += reloc_idx[type];

    relpp = (arelent **)malloc(relcount * sizeof(arelent *));
    relcount = 0;
    for (type = 0; type < NR_SYMTYPE; type++) {
        relent = reloc[type];
        for (n = 0; n < reloc_idx[type]; n++) {
            relpp[relcount] = &relent[n];
            relent[n].address += reloc_off[type];
            relcount++;
        }
    }
    vprintf("relcount %x\n", relcount);

    osection = bfd_get_section_by_name(abfd, name);
    if (!osection)
        err_bfd("bfd_get_section_by_name failed");

    bfd_set_reloc(abfd, osection, relpp, relcount);
}

static bool
do_add_reloc(int symtype, struct bfd_symbol **sym_ptr_ptr,
             bfd_size_type address, bfd_vma addend, reloc_howto_type *howto)
{

    if (reloc_idx[symtype] == reloc_max[symtype]) {
        reloc_max[symtype] += 100;
        reloc[symtype] = (arelent *)realloc(
            reloc[symtype], reloc_max[symtype] * sizeof(arelent));
    }
    reloc[symtype][reloc_idx[symtype]].sym_ptr_ptr = sym_ptr_ptr;
    reloc[symtype][reloc_idx[symtype]].address = address;
    reloc[symtype][reloc_idx[symtype]].addend = addend;
    reloc[symtype][reloc_idx[symtype]].howto = howto;
    reloc_idx[symtype]++;

    return true;
}

bool
add_reloc(struct bfd *bfd, int symtype, asymbol **asym,
          int secrel_offset, int section_offset)
{
    static reloc_howto_type *howto = NULL;
    static reloc_howto_type *howto_seg = NULL;

    if (!howto) {
        howto = bfd_reloc_type_lookup(bfd, BFD_RELOC_32_SECREL);
        howto_seg = bfd_reloc_type_lookup(bfd, BFD_RELOC_SECTION);
    }

    if (asym - isympp < 0 || asym - isympp >= symcount) {
        long i;
        for (i = 0; i < symcount; i++) {
            dprintf("isympp[%ld] = %p *asym = %p asym = %p\n", i, isympp[i],
                    *asym, asym);
            if (isympp[i] == *asym) {
                asym = &isympp[i];
                break;
            }
            if (isympp[i]->section == (*asym)->section && !isympp[i]->value &&
                !strcmp(isympp[i]->name, (*asym)->name)) {
                asym = &isympp[i];
                break;
            }
        }
    }

    dprintf("name %s sec %s type %d idx %lx\n", (*asym)->name,
            (*asym)->section->name, symtype, (long)(asym - isympp));

    do_add_reloc(symtype, asym, secrel_offset, 0, howto);
    do_add_reloc(symtype, asym, section_offset, 0, howto_seg);

    return true;
}
