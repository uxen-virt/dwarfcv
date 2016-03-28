
#include "dwarfcv.h"

#include "dwarf.h"
#include "dwarfdef.h"

struct push_array {
    int max;
    int used;
    int size;
    uint8_t *elems;
};
typedef struct push_array push_array;

static void
push_back(push_array *arr, void *elem, int esize)
{

    if (!arr->size)
        arr->size = esize;
    assert(arr->size == esize);
    if (arr->used == arr->max) {
        arr->max += 1 + arr->max / 2;
        arr->elems = realloc(arr->elems, arr->max * arr->size);
    }
    memcpy(&arr->elems[arr->used * arr->size], elem, esize);
    arr->used++;
}

static int
push_array_size(push_array *arr)
{

    return arr->used;
}

static void *
push_array_first(push_array *arr)
{

    return &arr->elems[0 * arr->size];
}

static void *
push_array_elem(push_array *arr, int n)
{

    return &arr->elems[n * arr->size];
}

static void *
push_array_last(push_array *arr)
{

    return &arr->elems[(arr->used - 1) * arr->size];
}

static void
push_array_resize(push_array *arr, int size)
{

    arr->used = size;
}

struct LineInfoEntry
{
    unsigned int offset;
    unsigned int line;
};
typedef struct LineInfoEntry LineInfoEntry;

#include "pshpack1.h"

struct DWARF_FileName {
    const char *file_name;
    unsigned int  dir_index;
    unsigned long last_modification;
    unsigned long file_length;
};
typedef struct DWARF_FileName DWARF_FileName;

static void
filename_read(DWARF_FileName *fname, uint8_t **p)
{
    fname->file_name = (char *)*p;
    *p += strlen((char *)*p) + 1;
    fname->dir_index = LEB128(*p);
    fname->last_modification = LEB128(*p);
    fname->file_length = LEB128(*p);
}

struct DWARF_LineNumberProgramHeader {
    unsigned int unit_length; // 12 byte in DWARF-64
    unsigned short version;
    unsigned int header_length; // 8 byte in DWARF-64
    uint8_t minimum_instruction_length;
    //byte maximum_operations_per_instruction; (// not in DWARF 2
    uint8_t default_is_stmt;
    signed char line_base;
    uint8_t line_range;
    uint8_t opcode_base;
    //LEB128 standard_opcode_lengths[opcode_base]; 
    // string include_directories[] // zero byte terminated
    // DWARF_FileNames file_names[] // zero byte terminated
};
typedef struct DWARF_LineNumberProgramHeader DWARF_LineNumberProgramHeader;

struct DWARF_LineState {
    // hdr info
    push_array include_dirs;
    push_array files;

    uint64_t address;
    unsigned int op_index;
    unsigned int file;
    unsigned int line;
    unsigned int column;
    bool is_stmt;
    bool basic_block;
    bool end_sequence;
    bool prologue_end;
    bool epilogue_end;
    unsigned int isa;
    unsigned int discriminator;

    // not part of the "documented" state
    DWARF_FileName *file_ptr;
    uint64_t seg_offset;
    // unsigned long section;
    uint64_t last_addr;
    push_array lineInfo;
};
typedef struct DWARF_LineState DWARF_LineState;

static void
init_LineState(DWARF_LineState *ls, DWARF_LineNumberProgramHeader *hdr)
{
    ls->address = 0;
    ls->op_index = 0;
    ls->file = 1;
    ls->line = 1;
    ls->column = 0;
    ls->is_stmt = hdr && hdr->default_is_stmt != 0;
    ls->basic_block = false;
    ls->end_sequence = false;
    ls->prologue_end = false;
    ls->epilogue_end = false;
    ls->isa = 0;
    ls->discriminator = 0;
    ls->last_addr = 0;
}

static const int maximum_operations_per_instruction = 1;

static void
advance_addr_LineState(DWARF_LineState *ls, DWARF_LineNumberProgramHeader *hdr,
                       int operation_advance)
{
    int address_advance = hdr->minimum_instruction_length *
        ((ls->op_index + operation_advance) /
         maximum_operations_per_instruction);
    ls->address += address_advance;
    ls->op_index = (ls->op_index + operation_advance) %
        maximum_operations_per_instruction;
}

static void
addLineInfo_LineState(DWARF_LineState *ls)
{
    LineInfoEntry entry;

#if 0
    const char* fname = (ls->file == 0 ? ls->file_ptr->file_name : ls->files[ls->file - 1].file_name);
    printf("Adr:%08lx Line: %5d File: %s\n", ls->address, ls->line, fname);
#endif
    if (ls->address < ls->seg_offset)
        return;

    entry.offset = ls->address - ls->seg_offset;
    entry.line = ls->line;
    push_back(&ls->lineInfo, &entry, sizeof(LineInfoEntry));
}

#include "poppack.h"

static bool
is_relative_path(const char *s)
{
    int l = strlen(s);

    if (l < 1)
        return true;
    if (s[0] == '/' || s[0] == '\\')
        return false;
    if (l < 2)
        return true;
    if (s[1] == ':')
        return false;
    return true;
}

static int
path_strcpy(char *d, const char *s)
{
    int len = strlen(s);
    int i;

    memcpy(d, s, len + 1);

    for (i = 0; i < len; i++)
        if (d[i] == '/')
            d[i] = '\\';

    return len + 1;
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

struct _file_info {
    unsigned int offset;
    unsigned short type;
    uint8_t data[];
} __attribute__((packed));

static int
add_lines(struct bfd *bfd, char const *fname, asection *asec,
          unsigned int sec_offset, unsigned int size,
          unsigned int offset, unsigned int firstline,
          LineInfoEntry *lineInfo, int nr_lineInfo) {
#if 0
    unsigned int p;
#endif
    struct lines *lines;
    struct lines_mapping *lmap;
    struct _file_info *info;

    dprintf("%s: fname %s sec %x/%s/%s sec_offset %x size %x offset %x firstline %d nr_lineInfo %x\n", __FUNCTION__, fname, asec->index, asec->name, (*all_sec[asec->index].sym_ptr_ptr)->name, sec_offset, size, offset, firstline, nr_lineInfo);
    dprintf("strings %lx info %lx\n", file_strings_length, file_info_length);

    if (!file_strings_length) {
        file_strings = (uint8_t *)
            realloc(NULL, sizeof(uint32_t) + sizeof(uint32_t) +
                    sizeof(char));
        *(uint32_t *)&file_strings[file_strings_length] = 0xf3;
        /* 2nd uint32_t length field filled in later */
        file_strings_length = sizeof(uint32_t) + sizeof(uint32_t);
        /* filename 0 */
        file_strings[file_strings_length] = 0;
        file_strings_length++;

        file_info = (uint8_t *)
            realloc(NULL, sizeof(uint32_t) + sizeof(uint32_t));
        *(uint32_t *)&file_info[file_info_length] = 0xf4;
        /* 2nd uint32_t length field filled in later */
        file_info_length =
            sizeof(uint32_t) + sizeof(uint32_t);
    }

    file_strings = (uint8_t *)realloc(file_strings,
                                      file_strings_length +
                                      strlen(fname) + sizeof(char));

    file_info = (uint8_t *)realloc(file_info, file_info_length +
                                   sizeof(struct _file_info) +
                                   sizeof(uint16_t));
    info = (struct _file_info *)(file_info + file_info_length);
    info->offset = file_strings_length - sizeof(uint32_t) - sizeof(uint32_t);
    info->type = 0;
    info->data[0] = info->data[1] = 0;

    path_strcpy((char *)file_strings + file_strings_length, fname);
    file_strings_length += strlen(fname) + 1;

    debugS = (uint8_t *)realloc(debugS, debugS_length +
                                sizeof(uint32_t) +
                                sizeof(uint32_t) +
                                sizeof(struct lines) +
                                sizeof(struct lines_mapping) +
                                nr_lineInfo * sizeof(LineInfoEntry) +
                                portion_align);
    if (!debugS)
        err(1, "realloc debugS %p",
            (void *)(debugS_length +
                     sizeof(uint32_t) + sizeof(uint32_t) +
                     sizeof(struct lines) + sizeof(struct lines_mapping) +
                     nr_lineInfo * sizeof(LineInfoEntry)));

    lines = (struct lines *)
        (debugS + debugS_length + sizeof(uint32_t) + sizeof(uint32_t));
    lmap = (struct lines_mapping *)
        (debugS + debugS_length + sizeof(uint32_t) + sizeof(uint32_t) +
         sizeof(struct lines));

    *(uint32_t *)(debugS + debugS_length) = 0xf2;
    /* 2nd uint32_t length field filled in later */
    if (!add_reloc(
            bfd, SYMTYPE_debugS, all_sec[asec->index].sym_ptr_ptr,
            debugS_length + sizeof(uint32_t) + sizeof(uint32_t) +
            _offsetof(struct lines, sec_offset),
            debugS_length + sizeof(uint32_t) + sizeof(uint32_t) +
            _offsetof(struct lines, section)))
        return -1;
    lines->sec_offset = sec_offset; // +reloc
    lines->section = 0; // reloc sec
    lines->pad = 0;
    lines->len = size;

    lmap->source_offset =
        file_info_length - sizeof(uint32_t) - sizeof(uint32_t);
    file_info_length += sizeof(struct _file_info) + sizeof(uint16_t);

    dprintf("  offset %x line %d\n",
            offset,
            firstline);
#if 0
    lmap->pairs[0].sec_offset = 0;
    lmap->pairs[0].line = firstline;
    for (p = 0; _offsetof(struct LineInfo, entries[p]) <
             (unsigned)cbLineInfo; p++) {
        dprintf("  offset %lx line %d\n",
                lineinfo->entries[p].offset,
                lineinfo->entries[p].line + firstline);
        lmap->pairs[p + 1].sec_offset =
            lineinfo->entries[p].offset;
        lmap->pairs[p + 1].line = lineinfo->entries[p].line + firstline;
    }

    lmap->n_pairs = p + 1;
    lmap->len = sizeof(struct lines_mapping) +
        (p + 1) * sizeof(((struct lines_mapping *)0)->pairs[0]);
#else
    memcpy(lmap->pairs, lineInfo, nr_lineInfo * sizeof(LineInfoEntry));
    lmap->n_pairs = nr_lineInfo;
    lmap->len = sizeof(struct lines_mapping) +
        nr_lineInfo * sizeof(LineInfoEntry);
#endif

    *(uint32_t *)(debugS + debugS_length + sizeof(uint32_t)) =
        sizeof(struct lines) + lmap->len;

    debugS_length += sizeof(uint32_t) + sizeof(uint32_t) +
        sizeof(struct lines) + lmap->len;

    while (debugS_length % portion_align)
        debugS[debugS_length++] = 0;

    return 1;
}

#ifndef MAX_PATH
#define MAX_PATH FILENAME_MAX
#endif

static bool
_flush_lines(struct bfd *bfd, DWARF_LineState *state)
{
    char fname[MAX_PATH];
    int len;
    LineInfoEntry *start, *end;
    unsigned int saddr, eaddr;
    asection *sec;
    const DWARF_FileName *dfn;
    size_t i;
    bool dump = dprint || false;
    int rc = 1;
    unsigned int firstLine;
    unsigned int firstAddr;
    size_t ln;
    LineInfoEntry *info, *entry, *first_entry;
    unsigned int length;

    if (push_array_size(&state->lineInfo) == 0)
        return true;

    start = push_array_first(&state->lineInfo);
    end = push_array_last(&state->lineInfo);

    saddr = start->offset;
    eaddr = end->offset;

    sec = find_section(bfd, saddr + state->seg_offset);
    if(!sec) {
        // throw away invalid lines (mostly due to "set address to 0")
        push_array_resize(&state->lineInfo, 0);
        return true;
    }

    if (state->file == 0)
        dfn = state->file_ptr;
    else if(state->file > 0 && state->file <= push_array_size(&state->files))
        dfn = push_array_elem(&state->files, state->file - 1);
    else
        return false;

    if (is_relative_path(dfn->file_name) &&
        dfn->dir_index > 0 &&
        dfn->dir_index <= push_array_size(&state->include_dirs)) {
        const char **_dir = push_array_elem(&state->include_dirs,
                                            dfn->dir_index - 1);
        const char *dir = *_dir;
        int l = strlen(dir);

        if (l > 0 && dir[l - 1] != '/' && dir[l - 1] != '\\')
            len = snprintf(fname, sizeof(fname), "%s\\%s", dir, dfn->file_name);
        else
            len = snprintf(fname, sizeof(fname), "%s%s", dir, dfn->file_name);
    } else
        len = snprintf(fname, sizeof(fname), "%s", dfn->file_name);

    for (i = 0; i < (size_t)len; i++)
        if (fname[i] == '/')
            fname[i] = '\\';

    entry = push_array_first(&state->lineInfo);
    firstLine = entry->line;
    firstAddr = entry->offset;
    first_entry = entry;
    info = NULL;

    for (ln = 0; ln < push_array_size(&state->lineInfo); ln++) {
        info = push_array_elem(&state->lineInfo, ln);
        if (info->line < firstLine || info->offset < firstAddr) {
            if (entry != first_entry) {
                length = entry->offset + 1; // firstAddr has been subtracted before
                if (dump)
                    printf("AddLines(%08x+%04x, Line=%4d+%3"PRId64", %s)\n",
                           firstAddr, length, firstLine,
                           (uint64_t)(entry - first_entry), fname);
#if 0
                /* ZZZ */
                rc = mod->AddLines(fname, sec, firstAddr, length, firstAddr, firstLine,
                                   (unsigned char*) &state->lineInfo[firstEntry],
                                   (entry - first_entry) * sizeof(state->lineInfo[0]));
#endif
                firstLine = info->line;
                firstAddr = info->offset;
                first_entry = entry;
            }
        } else if (entry != first_entry &&
                   info->offset - firstAddr == entry->offset)
            continue; // skip entries without offset change
        entry->line = info->line;
        entry->offset = info->offset - firstAddr;
        entry++;
    }

    length = eaddr - firstAddr;
    if (dump)
        printf("AddLines(%08x+%04x, Line=%4d+%3d, entries %"PRId64", %s)\n",
               firstAddr, length, firstLine,
               (entry - 1)->line - first_entry->line,
               (uint64_t)(entry - first_entry), fname);
    rc = add_lines(bfd, fname, sec, firstAddr, length, firstAddr, firstLine,
                   first_entry, entry - first_entry);

    push_array_resize(&state->lineInfo, 0);
    return rc > 0;
}

void
process_lines(struct bfd *bfd)
{
    unsigned int off;
    uint64_t *opcode_lengths = NULL;
    unsigned int opcode_lengths_max = 0;
    uint64_t base;

    base = bfd_get_start_address(bfd);

    for (off = 0; off < debug_line_length; ) {
        DWARF_LineNumberProgramHeader *hdr =
            (DWARF_LineNumberProgramHeader *)(debug_line + off);
        DWARF_LineState state = { };
        DWARF_FileName fname = { };
        uint8_t *p, *end;
        int length;

        length = hdr->unit_length;
        if (length < 0)
            break;

        length += sizeof(length);

        p = (unsigned char *)(hdr + 1);
        end = (unsigned char *)hdr + length;

        if (opcode_lengths_max < hdr->opcode_base) {
            opcode_lengths_max = hdr->opcode_base;
            opcode_lengths = (uint64_t *)realloc(
                opcode_lengths, opcode_lengths_max * sizeof(uint64_t));
        }
        if (hdr->opcode_base > 0) {
            int o;
            opcode_lengths[0] = 0;
            for (o = 1; o < hdr->opcode_base && p < end; o++)
                opcode_lengths[o] = LEB128(p);
        }

        // dirs
        while (p < end && *p) {
            push_back(&state.include_dirs, &p, sizeof(char *));
            p += strlen((char *)p) + 1;
        }
        p++;

        // files
        while (p < end && *p) {
            filename_read(&fname, &p);
            push_back(&state.files, &fname, sizeof(fname));
        }
        p++;

        init_LineState(&state, hdr);
        state.seg_offset = base;
        while (p < end) {
            int opcode = *p++;
            if (opcode >= hdr->opcode_base) {
                // special opcode
                int adjusted_opcode = opcode - hdr->opcode_base;
                int operation_advance = adjusted_opcode / hdr->line_range;
                int line_advance;

                advance_addr_LineState(&state, hdr, operation_advance);
                line_advance = hdr->line_base +
                    (adjusted_opcode % hdr->line_range);
                state.line += line_advance;

                addLineInfo_LineState(&state);

                state.basic_block = false;
                state.prologue_end = false;
                state.epilogue_end = false;
                state.discriminator = 0;
            } else {
                switch (opcode) {
                case 0: { // extended
                    int exlength = LEB128(p);
                    unsigned char* q = p + exlength;
                    int excode = *p++;
                    switch (excode) {
                    case DW_LNE_end_sequence:
                        /* if (p - debug_line >= 0xe4e0) */
                        /*     p = p; */
                        state.end_sequence = true;
                        state.last_addr = state.address;
                        addLineInfo_LineState(&state);
                        if (!_flush_lines(bfd, &state))
                            return;
                        init_LineState(&state, hdr);
                        break;
                    case DW_LNE_set_address: {
                        uint64_t adr;
                        adr = RDsize(p, exlength - 1);
                        if (adr)
                            state.address = adr;
                        else
                            state.address = state.last_addr; // strange adr 0 for templates?
                        state.op_index = 0;
                        break;
                    }
                    case DW_LNE_define_file:
                        filename_read(&fname, &p);
                        state.file_ptr = &fname;
                        state.file = 0;
                        break;
                    case DW_LNE_set_discriminator:
                        state.discriminator = LEB128(p);
                        break;
                    }
                    p = q;
                    break;
                }
                case DW_LNS_copy:
                    addLineInfo_LineState(&state);
                    state.basic_block = false;
                    state.prologue_end = false;
                    state.epilogue_end = false;
                    state.discriminator = 0;
                    break;
                case DW_LNS_advance_pc:
                    advance_addr_LineState(&state, hdr, LEB128(p));
                    break;
                case DW_LNS_advance_line:
                    state.line += SLEB128(p);
                    break;
                case DW_LNS_set_file:
                    if (!_flush_lines(bfd, &state))
                        return;
                    state.file = LEB128(p);
                    break;
                case DW_LNS_set_column:
                    state.column = LEB128(p);
                    break;
                case DW_LNS_negate_stmt:
                    state.is_stmt = !state.is_stmt;
                    break;
                case DW_LNS_set_basic_block:
                    state.basic_block = true;
                    break;
                case DW_LNS_const_add_pc:
                    advance_addr_LineState(
                        &state, hdr,
                        (255 - hdr->opcode_base) / hdr->line_range);
                    break;
                case DW_LNS_fixed_advance_pc:
                    state.address += RD2(p);
                    state.op_index = 0;
                    break;
                case DW_LNS_set_prologue_end:
                    state.prologue_end = true;
                    break;
                case DW_LNS_set_epilogue_begin:
                    state.epilogue_end = true;
                    break;
                case DW_LNS_set_isa:
                    state.isa = LEB128(p);
                    break;
                default: {
                    // unknown standard opcode
                    unsigned int arg;
                    for (arg = 0; arg < opcode_lengths[opcode]; arg++)
                        LEB128(p);
                    break;
                }
                }
            }
        }
        if (!_flush_lines(bfd, &state))
            return;

        off += length;
    }
}
