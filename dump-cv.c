
#define _exit(val) exit(val)
#ifdef _WIN32
#define ERR_WINDOWS
#endif
#include "err.h"

#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mscvpdb.h"

#define PACKAGE "dump-cv"
#include <bfd.h>
#define _offsetof(st, m) ((size_t)(&((st *)0)->m))
#define err_bfd(fmt, ...)                                               \
    errx(1, fmt ": %s", ## __VA_ARGS__, bfd_errmsg(bfd_get_error()))

#ifdef _WIN32
DECLARE_PROGNAME;
#endif  /* _WIN32 */

static void
usage(void)
{

    errx(1, "usage: infile\n");
}

bfd_size_type debugS_size;
uint8_t *debugS;
bfd_size_type debugT_size;
uint8_t *debugT;

int
p_cvs(int base, int len)
{
    // uint8_t *cvs = debugS + base;
    union codeview_symbol *cvs = (union codeview_symbol *)(debugS + base);

    switch (cvs->generic.id) {
    case S_UDT_V1:
        printf("cvs size %02x at <%04x> id UDT_V1 type %x name %*s\n",
               cvs->generic.len, base,
               cvs->udt_v1.type,
               cvs->udt_v1.p_name.namelen,
               cvs->udt_v1.p_name.name);
        break;
    case S_ENDARG_V1:
        printf("cvs size %02x at <%04x> id ENDARG_V1\n",
               cvs->generic.len, base);
        break;
    case S_COMPILAND_V3:
        printf("cvs size %02x at <%04x> id COMPILAND_V3 \"%s\"\n",
               cvs->generic.len, base, cvs->compiland_v3.name);
        break;
    case S_BLOCK_V3:
        printf("cvs size %02x at <%04x> id BLOCK_V3 parent %x end %x length %x "
               "offset %x segment %x\n",
               cvs->generic.len, base,
               cvs->block_v3.parent,
               cvs->block_v3.end,
               cvs->block_v3.length,
               cvs->block_v3.offset,
               cvs->block_v3.segment);
        break;
    case S_UDT_V3:
        printf("cvs size %02x at <%04x> id UDT_V3 type %x name %s\n",
               cvs->generic.len, base,
               cvs->udt_v3.type,
               cvs->udt_v3.name);
        break;
    case S_GDATA_V3:
        printf("cvs size %02x at <%04x> id GDATA_V3 symtype %x offset %x "
               "segment %x name %s\n", cvs->generic.len, base,
               cvs->data_v3.symtype,
               cvs->data_v3.offset,
               cvs->data_v3.segment,
               cvs->data_v3.name);
        break;
    case S_GPROC_V3:
        printf("cvs size %02x at <%04x> id GPROC_V3 pparent %x pend %x "
               "next %x proc_len %x debug_start %x debug_end %x proctype %x "
               "offset %x segment %x flags %x name %s\n", cvs->generic.len,
               base, cvs->proc_v3.pparent, cvs->proc_v3.pend,
               cvs->proc_v3.next, cvs->proc_v3.proc_len,
               cvs->proc_v3.debug_start, cvs->proc_v3.debug_end,
               cvs->proc_v3.proctype, cvs->proc_v3.offset,
               cvs->proc_v3.segment, cvs->proc_v3.flags, cvs->proc_v3.name);
        break;
    case S_REGREL_V3:
        printf("cvs size %02x at <%04x> id REGREL_V3 offset %x symtype %x "
               "reg %x name %s\n",
               cvs->generic.len, base,
               cvs->regrel_v3.offset,
               cvs->regrel_v3.symtype,
               cvs->regrel_v3.reg,
               cvs->regrel_v3.name);
        break;
    case S_FRAMEINFO_V2:
        printf("cvs size %02x at <%04x> id FRAMEINFO_V2 sz_frame %x "
               "unknown2 %x unknown3 %x sz_saved_regs %x eh_offset %x "
               "eh_sect %x flags %x\n", cvs->generic.len, base,
               cvs->frame_info_v2.sz_frame, cvs->frame_info_v2.unknown2,
               cvs->frame_info_v2.unknown3, cvs->frame_info_v2.sz_saved_regs,
               cvs->frame_info_v2.eh_offset, cvs->frame_info_v2.eh_sect,
               cvs->frame_info_v2.flags);
        break;
    case S_END_V1:
        printf("cvs size %02x at <%04x> id END_V1\n", cvs->generic.len,
               base);
        break;
    default:
        printf("cvs size %02x at <%04x> id %04x\n", cvs->generic.len,
               base, cvs->generic.id);
        break;
    }

    return sizeof(cvs->generic.len) + cvs->generic.len;
}

struct lines {
    unsigned int sec_offset;
    unsigned short section;
    unsigned short pad;
    unsigned int len;
} __attribute__((packed));

struct lines_mapping {
    unsigned int source_offset;
    unsigned int n_pairs;
    unsigned int len;
    struct {
        unsigned int sec_offset;
        unsigned int line;
    } __attribute__((packed)) pairs[];
} __attribute__((packed));

int
p_lines(int base, int len)
{
    struct lines *lines = (struct lines *)(debugS + base);
    struct lines_mapping *lmap = (struct lines_mapping *)
        (debugS + base + sizeof(struct lines));
    int dlen = len - sizeof(struct lines);
    int p;

    printf("lines sec_offset %x sec %x len %x\n",
           lines->sec_offset,
           lines->section,
           lines->len);
    while (dlen > 0) {
        printf("  mapping source_offset %x n_pairs %x len %x\n",
               lmap->source_offset,
               lmap->n_pairs,
               lmap->len);

        for (p = 0; p < lmap->n_pairs; p++)
            printf("    offset %x line %d%s\n",
                   lmap->pairs[p].sec_offset,
                   lmap->pairs[p].line & ~0x80000000,
                   lmap->pairs[p].line & 0x80000000 ? " eos" : "");

        dlen -= lmap->len;
        lmap = (struct lines_mapping *)((uint8_t *)lmap + lmap->len);
    }

    return len;
}

int
p_file_strings(int base, int len)
{
    char *strings = (char *)(debugS + base);
    int dlen = len;
    int n = 0;

    while (dlen > 0) {
        printf("%x<%"PRIx64">: %s\n", n, (uint8_t *)strings - (debugS + base),
               strings);
        dlen -= strlen(strings) + 1;
        strings += strlen(strings) + 1;
        n++;
    }

    return len;
}

struct file_info {
    unsigned int offset;
    unsigned short type;
    uint8_t data[];
} __attribute__((packed));

int
p_file_info(int base, int len)
{
    struct file_info *info = (struct file_info *)(debugS + base);
    int dlen = len;
    int n = 0;
    int l;

    while (dlen > 0) {
        printf("%x<%"PRIx64">: offset %x type %04x\n", n,
               (uint8_t *)info - (debugS + base), info->offset,
               info->type);
        if (info->type)
            l = sizeof(struct file_info) + 16 /* md5 */;
        else
            l = sizeof(struct file_info) + sizeof(unsigned short);
        dlen -= l;
        info = (struct file_info *)((uint8_t *)info + l);
        n++;
    }

    return len;
}

struct fx {
    unsigned int id;
    unsigned int len;
    uint8_t data[];
} __attribute__((packed));

static int
p_fx(int base, int (*process)(int, int))
{
    // uint8_t *fx = debugS + base;
    struct fx *fx = (struct fx *)(debugS + base);
    int size;
    int off;

    printf("%x size %x at <%04x>\n", fx->id, fx->len, base);

    if (process) {
        size = fx->len + _offsetof(struct fx, data);
        off = _offsetof(struct fx, data);
        while (off <= size - sizeof(((union codeview_symbol *)0x0)->generic))
            off += process(base + off, fx->len);
    }

    return sizeof(fx->id) + sizeof(fx->len) + fx->len;
}

static int tidx = 0x1000;

static int
p_t(int base)
{
    union codeview_type *cvt = (union codeview_type *)(debugT + base);
    union codeview_reftype *cvrt = (union codeview_reftype *)(debugT + base);

    switch (cvt->generic.id) {
    case LF_MODIFIER_V2:
        printf("cvt idx %04x size %02x at <%04x> id MODIFIER_V2 type %x "
               "attribute %x\n",
               tidx, cvt->generic.len, base,
               cvt->modifier_v2.type,
               cvt->modifier_v2.attribute);
        break;
    case LF_POINTER_V2: {
        int has_name = cvt->pointer_v2.len >
            _offsetof(union codeview_type, pointer_v2.p_name);
        printf("cvt idx %04x size %02x at <%04x> id POINTER_V2 datatype %x "
               "attribute %x name %*s\n",
               tidx, cvt->generic.len, base,
               cvt->pointer_v2.datatype,
               cvt->pointer_v2.attribute,
               has_name ? cvt->pointer_v2.p_name.namelen : 9,
               has_name ? cvt->pointer_v2.p_name.name : "<not-set>");
    }
        break;
    case LF_FIELDLIST_V2:
        printf("cvt idx %04x size %02x at <%04x> id FIELDLIST_V2\n",
               tidx, cvt->generic.len, base);
        break;
    case LF_PROCEDURE_V2:
        printf("cvt idx %04x size %02x at <%04x> id PROCEDURE_V2 rvtype %x "
               "call %x reserved %x params %x arglist %x\n",
               tidx, cvt->generic.len, base,
               cvt->procedure_v2.rvtype,
               cvt->procedure_v2.call,
               cvt->procedure_v2.reserved,
               cvt->procedure_v2.params,
               cvt->procedure_v2.arglist);
        break;
    case LF_ARGLIST_V2:
        printf("cvt idx %04x size %02x at <%04x> id ARGLIST_V2 num %x\n",
               tidx, cvrt->generic.len, base,
               cvrt->arglist_v2.num);
        break;
    case LF_ARRAY_V3:
        printf("cvt idx %04x size %02x at <%04x> id ARRAY_V3 elemtype %x "
               "idxtype %x arrlen %x name %s\n",
               tidx, cvrt->generic.len, base,
               cvt->array_v3.elemtype,
               cvt->array_v3.idxtype,
               cvt->array_v3.arrlen,
               cvt->array_v3.name);
        break;
    case LF_STRUCTURE_V3:
        printf("cvt idx %04x size %02x at <%04x> id STRUCTURE_V3 n_element %x "
               "property %x fieldlist %x derived %x vshape %x structlen %x "
               "name %s\n",
               tidx, cvrt->generic.len, base,
               cvt->struct_v3.n_element,
               cvt->struct_v3.property,
               cvt->struct_v3.fieldlist,
               cvt->struct_v3.derived,
               cvt->struct_v3.vshape,
               cvt->struct_v3.structlen,
               cvt->struct_v3.name);
        break;
    default:
        printf("cvt idx %04x size %02x at <%04x> id %04x\n", tidx,
               cvt->generic.len, base, cvt->generic.id);
        break;
    }

    tidx++;

    return sizeof(cvt->generic.len) + cvt->generic.len;
}

int
main(int argc, char **argv, char **envp)
{
    int ret;
    bfd *ibfd;
    char **matching;
    asymbol **isympp = NULL;
    long symcount;
    asection *isec;
    uint8_t *p;
    int off;

#ifdef _WIN32
    setprogname(argv[0]);
#endif  /* _WIN32 */

    while (1) {
        int c, index = 0;

        /* enum { LI_xxx }; */

        static int long_index;
        static struct option long_options[] = {
            {"help",          no_argument,       NULL,       'h'},

            {NULL,   0,                 NULL, 0}
        };

        long_index = 0;
        c = getopt_long(argc, argv, "h", long_options,
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
        case 'h':
            usage();
            /* NOTREACHED */
        }
    }
    argc -= optind;
    argv += optind;

    if (argc != 1)
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

    long symsize;
    symsize = bfd_get_symtab_upper_bound(ibfd);
    if (symsize < 0)
        err_bfd("bfd_get_symtab_upper_bound failed");

    /* osympp = */ isympp = (asymbol **)malloc(symsize);
    if (!isympp)
        err(1, "malloc symsize %ld failed", symsize);
    /* (void)osympp; */

    symcount = bfd_canonicalize_symtab(ibfd, isympp);
    if (symcount == 0) {
        free(isympp);
        /* osympp = */ isympp = NULL;
    }

    isec = bfd_get_section_by_name(ibfd, ".debug$S");
    if (!isec) {
        warnx("bfd_get_section_by_name(%s) failed", ".debug$S");
        goto no_debugS;
    }

    debugS_size = bfd_section_size(ibfd, isec);
    debugS = (uint8_t *)calloc(1, debugS_size);
    if (!debugS)
        err(1, "calloc %lx bytes for section %s failed", (long)debugS_size,
            ".debug$S");

    p = bfd_simple_get_relocated_section_contents(ibfd, isec, debugS, NULL);
    if (p != debugS)
        err_bfd("bfd_simple_get_relocated_section_contents(%s) failed",
                ".debug$S");

    printf("debugS size %lx\n", (long)debugS_size);

    off = 0;
    printf("%d: 4 at <%04x>\n", __LINE__, off);
    if (*(uint32_t *)&debugS[off] != 4)
        errx(1, "not found");
    off += sizeof(uint32_t);

    while (off <= debugS_size - sizeof(struct fx)) {
        printf("\n");
        switch (*(uint32_t *)&debugS[off]) {
        case 0xf1:
            off += p_fx(off, p_cvs);
            break;
        case 0xf2:
            off += p_fx(off, p_lines);
            break;
        case 0xf3:
            off += p_fx(off, p_file_strings);
            break;
        case 0xf4:
            off += p_fx(off, p_file_info);
            break;
        default:
            errx(1, "unknown tag %x at <%04x>", *(uint32_t *)&debugS[off], off);
        }
        if (off % 4)
            off += 4 - (off % 4);
    }

  no_debugS:
    isec = bfd_get_section_by_name(ibfd, ".debug$T");
    if (!isec) {
        warnx("bfd_get_section_by_name(%s) failed", ".debug$T");
        goto no_debugT;
    }

    debugT_size = bfd_section_size(ibfd, isec);
    debugT = (uint8_t *)calloc(1, debugT_size);
    if (!debugT)
        err(1, "calloc %lx bytes for section %s failed", (long)debugT_size,
            ".debug$T");

    p = bfd_simple_get_relocated_section_contents(ibfd, isec, debugT, NULL);
    if (p != debugT)
        err_bfd("bfd_simple_get_relocated_section_contents(%s) failed",
                ".debug$T");

    printf("\n");
    printf("debugT size %lx\n", (long)debugT_size);

    off = 0;
    printf("%d: 4 at <%04x>\n", __LINE__, off);
    if (*(uint32_t *)&debugT[off] != 4)
        errx(1, "not found");
    off += sizeof(uint32_t);

    while (off <= debugT_size - sizeof(((union codeview_type *)0x0)->generic))
        off += p_t(off);

  no_debugT:
    return 0;
}



#include <stdlib.h>

size_t
strnlen(const char *s, size_t max)
{
    size_t n;

    for (n = 0; n < max; n++)
        if (!s[n])
            break;
    return n;
}
