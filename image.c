
#include "dwarfcv.h"

static void
read_section(struct bfd *bfd, const char *name, uint8_t **buf,
             unsigned int *len)
{
    asection *asec;
    uint8_t *p;

    *len = 0;
    *buf = NULL;

    asec = bfd_get_section_by_name(bfd, name);
    if (!asec)
        return;
    *len = bfd_section_size(bfd, asec);
    *buf = (uint8_t *)calloc(1, *len);
    if (!*buf)
        err(1, "calloc %s %u", name, *len);
    p = bfd_simple_get_relocated_section_contents(bfd, asec, *buf, NULL);
    if (p != *buf)
        err_bfd("bfd_simple_get_relocated_section_contents(%s) failed", name);
}

section_info *all_sec = NULL;

static void
fill_sec_array(bfd *abfd, asection *asect, void *obj)
{
    asymbol **asym;

    asym = asect->symbol_ptr_ptr;
    if (asym - isympp < 0 || asym - isympp >= symcount) {
        int i;
        for (i = 0; i < symcount; i++) {
            /* dprintf("isympp[%d] = %p *asym = %p asym = %p\n", i, */
            /*         isympp[i], *asym, asym); */
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
        if (i == symcount) {
            dprintf("%s: section %s symbol not found", __FUNCTION__,
                    asect->name);
            asym = NULL;
        }
    }
    all_sec[asect->index].sym_ptr_ptr = asym;
}

void
read_sections(struct bfd *bfd)
{
    unsigned int length, nsec;

    read_section(bfd, ".debug_abbrev", &debug_abbrev, &debug_abbrev_length);
    read_section(bfd, ".debug_frame", &debug_frame, &debug_frame_length);
    read_section(bfd, ".debug_info", &debug_info, &debug_info_length);
    read_section(bfd, ".debug_line", &debug_line, &debug_line_length);
    read_section(bfd, ".debug_loc", &debug_loc, &debug_loc_length);
    read_section(bfd, ".debug_ranges", &debug_ranges, &debug_ranges_length);
    read_section(bfd, ".debug_str", &debug_str, &length);

#if 0
    asec = bfd_get_section_by_name(bfd, ".text");
    codeSegment = asec->index;
#endif

    nsec = bfd_count_sections(bfd);
    dprintf("%d sections\n", nsec);
    all_sec = (section_info *)malloc(nsec * sizeof(section_info));
    if (!all_sec)
        err(1, "malloc %d * struct section_info", nsec);
    bfd_map_over_sections(bfd, fill_sec_array, all_sec);
}

asymbol **
find_symbol(struct bfd *bfd, const char *name)
{
    static int symcursor = 0;
    int i;

    i = symcursor;
    do {
        if (!strcmp(name, isympp[i]->name))
            break;
        i++;
        if (i == symcount)
            i = 0;
    } while (i != symcursor);

    if (i == symcursor) {
        dprintf("%s: name %s not found in syms\n", __FUNCTION__, name);
        return NULL;
    }
    dprintf("sym %s seg %x segoff %lx\n", name, isympp[i]->section->index,
            (long)isympp[i]->value);

    return &isympp[i];
}

static bfd_boolean
find_section_at_off(bfd *abfd, asection *sect, void *obj)
{
    uintptr_t vma = (uintptr_t)bfd_get_section_vma(abfd, sect);

    if (vma <= *(uint64_t *)obj &&
        (vma + bfd_section_size(abfd, sect) > *(uint64_t *)obj))
        return 1;

    return 0;
}

asection *
find_section(struct bfd *bfd, uint64_t vma)
{
    asection *sect = bfd_sections_find_if(bfd, find_section_at_off, &vma);

    if (sect)
        dprintf("vma %"PRIx64" in sec %x\n", vma, sect->index);

    return sect;
}
