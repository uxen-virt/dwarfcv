
#include "dwarfcv.h"

#include "dwarfdef.h"
#include "dwarf.h"
#include "mscvpdb.h"
#include "rbtree.h"

static unsigned int next_user_type = 0x1000;
static unsigned int next_dwarf_type = 0;

static bool use_typedef_enum = false;

static uint8_t *user_types = NULL;
static unsigned int user_types_used = 0;
static unsigned int user_types_max = 0;

static int *typedefs = NULL;
static unsigned int typedefs_used = 0;
static unsigned int typedefs_max = 0;
static int *translated_typedefs = NULL;
/* use typedefs_used for translated_typedefs_used */
static unsigned int translated_typedefs_max = 0;

static uint8_t *user_symbols = NULL;
static unsigned int user_symbols_used = 0;
static unsigned int user_symbols_max = 0;

static uint8_t *dwarf_types = NULL;
static unsigned int dwarf_types_used = 0;
static unsigned int dwarf_types_max = 0;

// class properties (also apply to struct,union and enum)
static const int kPropNone        = 0x00;
static const int kPropPacked      = 0x01;
static const int kPropHasCtorDtor = 0x02;
static const int kPropHasOverOps  = 0x04;
static const int kPropIsNested    = 0x08;
static const int kPropHasNested   = 0x10;
static const int kPropHasOverAsgn = 0x20;
static const int kPropHasCasting  = 0x40;
static const int kPropIncomplete  = 0x80;
static const int kPropScoped      = 0x100;
static const int kPropReserved2   = 0x200;

static uint32_t *offset_to_type = NULL;

static uint64_t code_seg_off = 0;
static asymbol **code_seg_sym = NULL;

static void
_check(void **p, unsigned int size, unsigned int *used, unsigned int *max,
       unsigned int needed, unsigned int addon)
{

    if (*used + needed < *max)
        return;

    *max += needed + addon;
    *p = realloc(*p, *max * size);
    assert(*p);
}

#define check_user_types(n)                                             \
    _check((void **)&user_types, sizeof(uint8_t), &user_types_used,     \
           &user_types_max, (n), 4096)

#if 0
#define add_user(t, v) do {                             \
        check_user_types(sizeof(t));                    \
        *(t *)(user_types + user_types_used) = (v);     \
        user_types_used += sizeof(t);                   \
    } while (0)
#endif

#define user_ptr_extra(t, extra) (({                    \
                uint8_t *p;                             \
                check_user_types(sizeof(t) + (extra));  \
                p = user_types + user_types_used;       \
                user_types_used += sizeof(t) + (extra); \
                p;                                      \
            }))

#define user_ptr(t) user_ptr_extra(t, 0)

#define check_typedefs() do {                                           \
        _check((void **)&typedefs, sizeof(int),                         \
               &typedefs_used, &typedefs_max, 1, 4);                    \
        _check((void **)&translated_typedefs, sizeof(int),              \
               &typedefs_used, &translated_typedefs_max, 1, 4);         \
        assert(typedefs_max == translated_typedefs_max);                \
    } while (0)

#define check_user_symbols(n)                                           \
    _check((void **)&user_symbols, sizeof(uint8_t), &user_symbols_used, \
           &user_symbols_max, (n), 4096)

#define symbol_ptr_extra(t, extra) (({                     \
                uint8_t *p;                                \
                check_user_symbols(sizeof(t) + (extra));   \
                p = user_symbols + user_symbols_used;      \
                user_symbols_used += sizeof(t) + (extra);  \
                p;                                         \
            }))

#define symbol_ptr(t) symbol_ptr_extra(t, 0)

#define check_dwarf_types(n)                                            \
    _check((void **)&dwarf_types, sizeof(uint8_t), &dwarf_types_used,   \
           &dwarf_types_max, (n), 4096)

#define dwarf_ptr_extra(t, extra) (({                           \
                uint8_t *p;                                     \
                check_dwarf_types(sizeof(t) + (extra));         \
                p = dwarf_types + dwarf_types_used;             \
                dwarf_types_used += sizeof(t) + (extra);        \
                p;                                              \
            }))

#define dwarf_ptr(t) dwarf_ptr_extra(t, 0)

#define add_dwarf_types(n) do {                 \
        check_dwarf_types(n);                   \
        dwarf_types_used += (n);                \
    } while (0)

struct DIECursor {
    DWARF_CompilationUnit *cu;
    uint8_t *ptr;
    int level;
    bool hasChild;
    uint8_t *sibling;
};
typedef struct DIECursor DIECursor;

static bool die_read_next(DIECursor *cursor, DWARF_InfoData *id,
                          bool stop_at_null);

static void
init_die_cursor(DIECursor *cursor, DWARF_CompilationUnit *cu, uint8_t *ptr)
{

    cursor->cu = cu;
    cursor->ptr = ptr;
    cursor->level = 0;
    cursor->hasChild = false;
    cursor->sibling = NULL;
}

static void
get_subtree_cursor(DIECursor *subtree_cursor, DIECursor *cursor)
{

    *subtree_cursor = *cursor;
    if (cursor->hasChild) {
        subtree_cursor->level = 0;
        subtree_cursor->hasChild = false;
    } else
        /* set invalid cursor */
        subtree_cursor->level = -1;
}

static void
goto_sibling(DIECursor *cursor)
{

    if (cursor->sibling) {
        /* use sibling pointer, if available */
        cursor->ptr = cursor->sibling;
        cursor->hasChild = false;
    } else if (cursor->hasChild) {
        DWARF_InfoData dummy;
        int curr_level = cursor->level;
        cursor->level = curr_level + 1;
        cursor->hasChild = false;

        /* read until we pop back to the level we were at */
        while (cursor->level > curr_level)
            die_read_next(cursor, &dummy, false);
    }
}

struct abbrev_map_key {
    unsigned int off;
    unsigned int code;
};

struct abbrev_map {
    uint8_t *abbrev;
    struct abbrev_map_key key;
    struct rb_node rbnode;
};

static intptr_t
abbrev_map_compare_key(void *ctx, const void *b, const void *key)
{
    const struct abbrev_map * const pnp =
        (const struct abbrev_map * const)b;
    const struct abbrev_map_key * const fhp =
        (const struct abbrev_map_key * const)key;

    if (pnp->key.off > fhp->off)
        return 1;
    else if (pnp->key.off < fhp->off)
        return -1;
    if (pnp->key.code > fhp->code)
        return 1;
    else if (pnp->key.code < fhp->code)
        return -1;
    return 0;
}

static intptr_t
abbrev_map_compare_nodes(void *ctx, const void *parent, const void *node)
{
    const struct abbrev_map * const np =
        (const struct abbrev_map * const)node;

    return abbrev_map_compare_key(ctx, parent, &np->key);
}

static const rb_tree_ops_t abbrev_map_rbtree_ops = {
    .rbto_compare_nodes = abbrev_map_compare_nodes,
    .rbto_compare_key = abbrev_map_compare_key,
    .rbto_node_offset = offsetof(struct abbrev_map, rbnode),
    .rbto_context = NULL

};

static rb_tree_t abbrev_map_rbtree = { };

static uint8_t *
get_abbrev(unsigned off, unsigned code)
{
    struct abbrev_map_key key;
    struct abbrev_map *m;
    uint8_t *p, *end;

    if (!abbrev_map_rbtree.rbt_ops)
        rb_tree_init(&abbrev_map_rbtree, &abbrev_map_rbtree_ops);

    key.off = off;
    key.code = code;
    m = rb_tree_find_node(&abbrev_map_rbtree, &key);
    if (m)
        return m->abbrev;

    p = debug_abbrev + off;
    end = debug_abbrev + debug_abbrev_length;
    while (p < end) {
        int attr, form;
        int c = LEB128(p);

        if (c == code) {
            m = (struct abbrev_map *)calloc(1, sizeof(struct abbrev_map));
            m->key.off = off;
            m->key.code = code;
            m->abbrev = p;
            rb_tree_insert_node(&abbrev_map_rbtree, m);
            return p;
        }
        if (c == 0)
            return 0;

        /* int tag = */ (void)LEB128(p);
        /* int hasChild = */ (void)*p++;

        // skip attributes
        do {
            attr = LEB128(p);
            form = LEB128(p);
        } while (attr || form);
    }
    return 0;
}

static bool
read_code(DIECursor *cursor, DWARF_InfoData *id, bool stop_at_null)
{

    for (;;) {
        if (cursor->level == -1)
            return false; /* we were already at the end of the subtree */

        if (cursor->ptr >= ((uint8_t *)cursor->cu +
                            sizeof(cursor->cu->unit_length) +
                            cursor->cu->unit_length))
            return false;     /* root of the tree does not have a null
                               * terminator, but we know the length */

        id->entry_ptr = cursor->ptr;
        id->entry_off = cursor->ptr - (uint8_t *)cursor->cu;
        id->code = LEB128(cursor->ptr);
        if (id->code == 0) {
            cursor->level--;    /* pop up one level */
            if (stop_at_null) {
                cursor->hasChild = false;
                return false;
            }
            continue;           /* read the next DIE */
        }

        break;
    }
    return true;
}

static bool
parse_abbrev(DIECursor *cursor, DWARF_InfoData *id, uint8_t *abbrev)
{
    int attr, form;

    for (;;) {
        DWARF_Attribute a;

        attr = LEB128(abbrev);
        form = LEB128(abbrev);

        if (attr == 0 && form == 0)
            break;

        while (form == DW_FORM_indirect)
            form = LEB128(cursor->ptr);

        switch (form) {
        case DW_FORM_addr:
            a.type = Addr;
            a.addr = (unsigned long)RDsize(cursor->ptr,
                                           cursor->cu->address_size);
            break;
        case DW_FORM_block:
            a.type = Block;
            a.block.len = LEB128(cursor->ptr);
            a.block.ptr = cursor->ptr;
            cursor->ptr += a.block.len;
            break;
        case DW_FORM_block1:
            a.type = Block;
            a.block.len = *cursor->ptr++;
            a.block.ptr = cursor->ptr;
            cursor->ptr += a.block.len;
            break;
        case DW_FORM_block2:
            a.type = Block;
            a.block.len = RD2(cursor->ptr);
            a.block.ptr = cursor->ptr;
            cursor->ptr += a.block.len;
            break;
        case DW_FORM_block4:
            a.type = Block;
            a.block.len = RD4(cursor->ptr);
            a.block.ptr = cursor->ptr;
            cursor->ptr += a.block.len;
            break;
        case DW_FORM_data1:
            a.type = Const;
            a.cons = *cursor->ptr++;
            break;
        case DW_FORM_data2:
            a.type = Const;
            a.cons = RD2(cursor->ptr);
            break;
        case DW_FORM_data4:
            a.type = Const;
            a.cons = RD4(cursor->ptr);
            break;
        case DW_FORM_data8:
            a.type = Const;
            a.cons = RD8(cursor->ptr);
            break;
        case DW_FORM_sdata:
            a.type = Const;
            a.cons = SLEB128(cursor->ptr);
            break;
        case DW_FORM_udata:
            a.type = Const;
            a.cons = LEB128(cursor->ptr);
            break;
        case DW_FORM_string:
            a.type = String;
            a.string = (const char*)cursor->ptr;
            cursor->ptr += strlen(a.string) + 1;
            break;
        case DW_FORM_strp:
            a.type = String;
            a.string = (const char*)(debug_str +
                                     RDsize(cursor->ptr, refSize(cursor->cu)));
            break;
        case DW_FORM_flag:
            a.type = Flag;
            a.flag = (*cursor->ptr++ != 0);
            break;
        case DW_FORM_flag_present:
            a.type = Flag;
            a.flag = true;
            break;
        case DW_FORM_ref1:
            a.type = Ref;
            a.ref = (uint8_t *)cursor->cu + *cursor->ptr++;
            break;
        case DW_FORM_ref2:
            a.type = Ref;
            a.ref = (uint8_t *)cursor->cu + RD2(cursor->ptr);
            break;
        case DW_FORM_ref4:
            a.type = Ref;
            a.ref = (uint8_t *)cursor->cu + RD4(cursor->ptr);
            break;
        case DW_FORM_ref8:
            a.type = Ref;
            a.ref = (uint8_t *)cursor->cu + RD8(cursor->ptr);
            break;
        case DW_FORM_ref_udata:
            a.type = Ref;
            a.ref = (uint8_t *)cursor->cu + LEB128(cursor->ptr);
            break;
        case DW_FORM_ref_addr:
            a.type = Ref;
            a.ref = debug_info + RDsize(cursor->ptr, refSize(cursor->cu));
            break;
        case DW_FORM_ref_sig8:
            a.type = Invalid;
            cursor->ptr += 8;
            break;
        case DW_FORM_exprloc:
            a.type = ExprLoc;
            a.expr.len = LEB128(cursor->ptr);
            a.expr.ptr = cursor->ptr;
            cursor->ptr += a.expr.len;
            break;
        case DW_FORM_sec_offset:
            a.type = SecOffset;
            a.sec_offset = RDsize(cursor->ptr, refSize(cursor->cu));
            break;
        case DW_FORM_indirect:
        default:
            assert(false && "Unsupported DWARF attribute form");
            return false;
        }

        switch (attr) {
        case DW_AT_byte_size:
            assert(a.type == Const || a.type == Ref || a.type == ExprLoc);
            if (a.type == Const) // TODO: other types not supported yet
                id->byte_size = a.cons;
            break;
        case DW_AT_sibling:
            assert(a.type == Ref);
            id->sibling = a.ref;
            break;
        case DW_AT_encoding:
            assert(a.type == Const);
            id->encoding = a.cons;
            break;
        case DW_AT_name:
            assert(a.type == String);
            id->name = a.string;
            break;
        case DW_AT_MIPS_linkage_name:
            assert(a.type == String);
            id->linkage_name = a.string;
            break;
        case DW_AT_comp_dir:
            assert(a.type == String);
            id->dir = a.string;
            break;
        case DW_AT_low_pc:
            if (a.type != Addr)
                __asm("int $3");
            assert(a.type == Addr);
            id->pclo = a.addr;
            break;
        case DW_AT_high_pc:
            if (a.type == Addr)
                id->pchi = a.addr;
            else if (a.type == Const)
                id->pchi = id->pclo + a.cons;
            else
                assert(false);
            break;
        case DW_AT_ranges:
            if (a.type == SecOffset)
                id->ranges = a.sec_offset;
            else if (a.type == Const)
                id->ranges = a.cons;
            else
                assert(false);
            break;
        case DW_AT_type:
            assert(a.type == Ref);
            id->type = a.ref;
            break;
        case DW_AT_inline:
            assert(a.type == Const);
            id->inlined = a.cons;
            break;
        case DW_AT_external:
            assert(a.type == Flag);
            id->external = a.flag;
            break;
        case DW_AT_upper_bound:
            assert(a.type == Const || a.type == Ref || a.type == ExprLoc);
            if (a.type == Const) // TODO: other types not supported yet
                id->upper_bound = a.cons;
            break;
        case DW_AT_lower_bound:
            assert(a.type == Const || a.type == Ref || a.type == ExprLoc);
            if (a.type == Const) // TODO: other types not supported yet
                id->lower_bound = a.cons;
            break;
        case DW_AT_containing_type:
            assert(a.type == Ref);
            id->containing_type = a.ref;
            break;
        case DW_AT_specification:
            assert(a.type == Ref);
            id->specification = a.ref;
            break;
        case DW_AT_data_member_location:
            id->member_location = a;
            break;
        case DW_AT_location:
            id->location = a;
            break;
        case DW_AT_frame_base:
            id->frame_base = a;
            break;
        case DW_AT_abstract_origin: {
            DIECursor icursor;
            DWARF_InfoData iid;
            uint8_t *iabbrev;

            if (a.type != Ref)
                errx(1, "<%"PRIx64"> expected ref, have %x",
                     id->entry_ptr - debug_info, a.type);
            init_die_cursor(&icursor, cursor->cu, a.ref);
            if (!read_code(&icursor, &iid, true))
                errx(1, "<%"PRIx64"> no code at origin <%"PRIx64">",
                     id->entry_ptr - debug_info, a.ref - debug_info);
            iabbrev = get_abbrev(icursor.cu->debug_abbrev_offset, iid.code);
            if (!iabbrev)
                errx(1, "<%"PRIx64"> missing abbrev code %x",
                     id->entry_ptr - debug_info, iid.code);
            /* skip tag */(void)LEB128(iabbrev);
            /* skip hasChild */(void)*iabbrev++;
            if (!parse_abbrev(&icursor, id, iabbrev))
                errx(1, "<%"PRIx64"> parse abbrev <%"PRIx64"> failed",
                     id->entry_ptr - debug_info, a.ref - debug_info);
            break;
        }
        }
    }
    return true;
}

static bool
die_read_next(DIECursor *cursor, DWARF_InfoData *id, bool stop_at_null)
{
    uint8_t *abbrev;

    memset(id, 0, sizeof(*id));
    id->member_location.type = Invalid;
    id->location.type = Invalid;
    id->frame_base.type = Invalid;

    if (cursor->hasChild)
        cursor->level++;

#if 0
    for (;;) {
        if (cursor->level == -1)
            return false; /* we were already at the end of the subtree */

        if (cursor->ptr >= ((uint8_t *)cursor->cu +
                            sizeof(cursor->cu->unit_length) +
                            cursor->cu->unit_length))
            return false;     /* root of the tree does not have a null
                               * terminator, but we know the length */

        id->entry_ptr = cursor->ptr;
        id->entry_off = cursor->ptr - (uint8_t *)cursor->cu;
        id->code = LEB128(cursor->ptr);
        if (id->code == 0) {
            cursor->level--;    /* pop up one level */
            if (stop_at_null) {
                cursor->hasChild = false;
                return false;
            }
            continue;           /* read the next DIE */
        }

        break;
    }
#else
    if (!read_code(cursor, id, stop_at_null))
        return false;
#endif

    abbrev = get_abbrev(cursor->cu->debug_abbrev_offset, id->code);
    if (!abbrev)
        warnx("missing abbrev %d with debug abbrev offset %x\n", id->code,
              cursor->cu->debug_abbrev_offset);
    if (!abbrev)
        return false;

    id->abbrev = abbrev;
    id->tag = LEB128(abbrev);
    id->hasChild = *abbrev++;

    id->name = NULL;

    if (!parse_abbrev(cursor, id, abbrev))
        return false;

    cursor->hasChild = id->hasChild != 0;
    cursor->sibling = id->sibling;

    return true;
}

#define DW_REG_CFA 257

enum location_type {
    Location_Invalid, // Failed to evaluate the location expression
    Location_InReg,   // In register (reg)
    Location_Abs,     // Absolute address (off)
    Location_RegRel   // Register-relative address ($reg + off)
};

struct Location {
    enum location_type type;
    unsigned int reg;
    uint64_t off;
};
typedef struct Location Location;

bool
loc_is_invalid(const Location *loc)
{
    return loc->type == Location_Invalid;
}

bool
loc_is_inreg(const Location *loc)
{
    return loc->type == Location_InReg;
}

bool
loc_is_abs(const Location *loc)
{
    return loc->type == Location_Abs;
}

bool
loc_is_regrel(const Location *loc)
{
    return loc->type == Location_RegRel;
}

static int location_address_size = 0;

static void
mkInReg(Location *l, unsigned int reg)
{
    l->type = Location_InReg;
    l->reg = reg;
}

static void
mkAbs(Location *l, uint64_t off)
{
    l->type = Location_Abs;
    l->off = off;
}

static void
mkRegRel(Location *l, int reg, uint64_t off)
{
    l->type = Location_RegRel;
    l->reg = reg;
    l->off = off;
}

static void
decodeLocation(Location *location, const DWARF_Attribute attr,
               const Location *frameBase, int at)
{
    static Location invalid = { Location_Invalid };
    Location stack[256];
    int stackDepth = 0;
    uint8_t* p;

    if (attr.type == Const)
        return mkAbs(location, attr.cons);

    if (attr.type != ExprLoc && attr.type != Block) { // same memory layout
        *location = invalid;
        return;
    }

    p = attr.expr.ptr;
    if (at == DW_AT_data_member_location)
        mkAbs(&stack[stackDepth++], 0);

    for (;;) {
        int op;

        if (p >= attr.expr.ptr + attr.expr.len)
            break;

        op = *p++;
        if (op == 0)
            break;

        switch (op) {
        case DW_OP_reg0:  case DW_OP_reg1:  case DW_OP_reg2:  case DW_OP_reg3:
        case DW_OP_reg4:  case DW_OP_reg5:  case DW_OP_reg6:  case DW_OP_reg7:
        case DW_OP_reg8:  case DW_OP_reg9:  case DW_OP_reg10: case DW_OP_reg11:
        case DW_OP_reg12: case DW_OP_reg13: case DW_OP_reg14: case DW_OP_reg15:
        case DW_OP_reg16: case DW_OP_reg17: case DW_OP_reg18: case DW_OP_reg19:
        case DW_OP_reg20: case DW_OP_reg21: case DW_OP_reg22: case DW_OP_reg23:
        case DW_OP_reg24: case DW_OP_reg25: case DW_OP_reg26: case DW_OP_reg27:
        case DW_OP_reg28: case DW_OP_reg29: case DW_OP_reg30: case DW_OP_reg31:
            mkInReg(&stack[stackDepth++], op - DW_OP_reg0);
            break;
        case DW_OP_regx:
            mkInReg(&stack[stackDepth++], LEB128(p));
            break;

        case DW_OP_const1u: mkAbs(&stack[stackDepth++], *p); break;
        case DW_OP_const2u: mkAbs(&stack[stackDepth++], RD2(p)); break;
        case DW_OP_const4u: mkAbs(&stack[stackDepth++], RD4(p)); break;
        case DW_OP_const1s: mkAbs(&stack[stackDepth++], (char)*p); break;
        case DW_OP_const2s: mkAbs(&stack[stackDepth++], (short)RD2(p)); break;
        case DW_OP_const4s: mkAbs(&stack[stackDepth++], (int)RD4(p)); break;
        case DW_OP_constu:  mkAbs(&stack[stackDepth++], LEB128(p)); break;
        case DW_OP_consts:  mkAbs(&stack[stackDepth++], SLEB128(p)); break;

        case DW_OP_plus_uconst:
            if (loc_is_inreg(&stack[stackDepth - 1])) {
                *location = invalid;
                return;
            }
            stack[stackDepth - 1].off += LEB128(p);
            break;

        case DW_OP_lit0:  case DW_OP_lit1:  case DW_OP_lit2:  case DW_OP_lit3:
        case DW_OP_lit4:  case DW_OP_lit5:  case DW_OP_lit6:  case DW_OP_lit7:
        case DW_OP_lit8:  case DW_OP_lit9:  case DW_OP_lit10: case DW_OP_lit11:
        case DW_OP_lit12: case DW_OP_lit13: case DW_OP_lit14: case DW_OP_lit15:
        case DW_OP_lit16: case DW_OP_lit17: case DW_OP_lit18: case DW_OP_lit19:
        case DW_OP_lit20: case DW_OP_lit21: case DW_OP_lit22: case DW_OP_lit23:
            mkAbs(&stack[stackDepth++], op - DW_OP_lit0);
            break;

        case DW_OP_breg0:  case DW_OP_breg1:  case DW_OP_breg2:  case DW_OP_breg3:
        case DW_OP_breg4:  case DW_OP_breg5:  case DW_OP_breg6:  case DW_OP_breg7:
        case DW_OP_breg8:  case DW_OP_breg9:  case DW_OP_breg10: case DW_OP_breg11:
        case DW_OP_breg12: case DW_OP_breg13: case DW_OP_breg14: case DW_OP_breg15:
        case DW_OP_breg16: case DW_OP_breg17: case DW_OP_breg18: case DW_OP_breg19:
        case DW_OP_breg20: case DW_OP_breg21: case DW_OP_breg22: case DW_OP_breg23:
        case DW_OP_breg24: case DW_OP_breg25: case DW_OP_breg26: case DW_OP_breg27:
        case DW_OP_breg28: case DW_OP_breg29: case DW_OP_breg30: case DW_OP_breg31:
            mkRegRel(&stack[stackDepth++], op - DW_OP_breg0, SLEB128(p));
            break;
        case DW_OP_bregx: {
            unsigned reg = LEB128(p);
            mkRegRel(&stack[stackDepth++], reg, SLEB128(p));
        }   break;


        case DW_OP_abs: case DW_OP_neg: case DW_OP_not: {
            Location *op1 = &stack[stackDepth - 1];
            if (!loc_is_abs(op1)) {
                *location = invalid;
                return;
            }
            switch (op)
            {
            case DW_OP_abs:   mkAbs(op1, abs(op1->off)); break;
            case DW_OP_neg:   mkAbs(op1, -op1->off); break;
            case DW_OP_not:   mkAbs(op1, ~op1->off); break;
            }
        }   break;

        case DW_OP_plus: { // op2 + op1
            Location *op1 = &stack[stackDepth - 1];
            Location *op2 = &stack[stackDepth - 2];
            // Can add only two offsets or a regrel and an offset.
            if (loc_is_regrel(op2) && loc_is_abs(op1))
                mkRegRel(op2, op2->reg, op2->off + op1->off);
            else if (loc_is_abs(op2) && loc_is_regrel(op1))
                mkRegRel(op2, op1->reg, op2->off + op1->off);
            else if (loc_is_abs(op2) && loc_is_abs(op1))
                mkAbs(op2, op2->off + op1->off);
            else {
                *location = invalid;
                return;
            }
            --stackDepth;
        }   break;

        case DW_OP_minus: { // op2 - op1
            Location *op1 = &stack[stackDepth - 1];
            Location *op2 = &stack[stackDepth - 2];
            if (loc_is_regrel(op2) && loc_is_regrel(op1) &&
                op2->reg == op1->reg)
                mkAbs(op2, 0); // X - X == 0
            else if (loc_is_regrel(op2) && loc_is_abs(op1))
                mkRegRel(op2, op2->reg, op2->off - op1->off);
            else if (loc_is_abs(op2) && loc_is_abs(op1))
                mkAbs(op2, op2->off - op1->off);
            else {
                *location = invalid;
                return;
            }
            --stackDepth;
        }   break;

        case DW_OP_mul: {
            Location *op1 = &stack[stackDepth - 1];
            Location *op2 = &stack[stackDepth - 2];
            if ((loc_is_abs(op1) && op1->off == 0) ||
                (loc_is_abs(op2) && op2->off == 0))
                mkAbs(op2, 0); // X * 0 == 0
            else if (loc_is_abs(op1) && loc_is_abs(op2))
                mkAbs(op2, op1->off * op2->off);
            else {
                *location = invalid;
                return;
            }
            --stackDepth;
        }   break;

        case DW_OP_and: {
            Location *op1 = &stack[stackDepth - 1];
            Location *op2 = &stack[stackDepth - 2];
            if ((loc_is_abs(op1) && op1->off == 0) ||
                (loc_is_abs(op2) && op2->off == 0))
                mkAbs(op2, 0); // X & 0 == 0
            else if (loc_is_abs(op1) && loc_is_abs(op2))
                mkAbs(op2, op1->off & op2->off);
            else {
                *location = invalid;
                return;
            }
            --stackDepth;
        }   break;

        case DW_OP_div: case DW_OP_mod: case DW_OP_shl:
        case DW_OP_shr: case DW_OP_shra: case DW_OP_or:
        case DW_OP_xor:
        case DW_OP_eq:  case DW_OP_ge:  case DW_OP_gt:
        case DW_OP_le:  case DW_OP_lt:  case DW_OP_ne: {
            Location *op1 = &stack[stackDepth - 1];
            Location *op2 = &stack[stackDepth - 2];
            if (!loc_is_abs(op1) || !loc_is_abs(op2)) {
                // can't combine unless both are constants
                *location = invalid;
                return;
            }
            switch (op) {
            case DW_OP_div:   op2->off = op2->off / op1->off; break;
            case DW_OP_mod:   op2->off = op2->off % op1->off; break;
            case DW_OP_shl:   op2->off = op2->off << op1->off; break;
            case DW_OP_shr:   op2->off = op2->off >> op1->off; break;
            case DW_OP_shra:  op2->off = op2->off >> op1->off; break;
            case DW_OP_or:    op2->off = op2->off | op1->off; break;
            case DW_OP_xor:   op2->off = op2->off ^ op1->off; break;
            case DW_OP_eq:    op2->off = op2->off == op1->off; break;
            case DW_OP_ge:    op2->off = op2->off >= op1->off; break;
            case DW_OP_gt:    op2->off = op2->off > op1->off; break;
            case DW_OP_le:    op2->off = op2->off <= op1->off; break;
            case DW_OP_lt:    op2->off = op2->off < op1->off; break;
            case DW_OP_ne:    op2->off = op2->off != op1->off; break;
            }
            --stackDepth;
        }   break;

        case DW_OP_fbreg: {
            Location loc;

            if (!frameBase) {
                *location = invalid;
                return;
            }

            if (loc_is_inreg(frameBase)) // ok in frame base specification, per DWARF4 spec #3.3.5
                mkRegRel(&loc, frameBase->reg, SLEB128(p));
            else if (loc_is_regrel(frameBase))
                mkRegRel(&loc, frameBase->reg, frameBase->off + SLEB128(p));
            else {
                *location = invalid;
                return;
            }
            stack[stackDepth++] = loc;
        }   break;

        case DW_OP_dup:   stack[stackDepth] = stack[stackDepth - 1];
            stackDepth++; break;
        case DW_OP_drop:  stackDepth--; break;
        case DW_OP_over:  stack[stackDepth] = stack[stackDepth - 2];
            stackDepth++; break;
        case DW_OP_pick:  stack[stackDepth++] = stack[*p]; break;
        case DW_OP_swap:  { Location tmp = stack[stackDepth - 1];
                stack[stackDepth - 1] = stack[stackDepth - 2];
                stack[stackDepth - 2] = tmp; } break;
        case DW_OP_rot:   { Location tmp = stack[stackDepth - 1];
                stack[stackDepth - 1] = stack[stackDepth - 2];
                stack[stackDepth - 2] = stack[stackDepth - 3];
                stack[stackDepth - 3] = tmp; } break;

        case DW_OP_addr:
            mkAbs(&stack[stackDepth++], RDsize(p, location_address_size)); // TODO: 64-bit
            break;

        case DW_OP_skip: {
            unsigned off = RD2(p);
            p = p + off;
        }   break;

        case DW_OP_bra: {
            Location *op1 = &stack[stackDepth - 1];
            if (!loc_is_abs(op1)) {
                *location = invalid;
                return;
            }
            if (op1->off != 0)
            {
                unsigned off = RD2(p);
                p = p + off;
            }
            --stackDepth;
        }   break;

        case DW_OP_nop:
            break;

        case DW_OP_call_frame_cfa: // assume ebp+8/rbp+16
            mkRegRel(&stack[stackDepth++], DW_REG_CFA, 0);
            break;

        case DW_OP_deref:
        case DW_OP_deref_size:
        case DW_OP_push_object_address:
        case DW_OP_call2:
        case DW_OP_call4:
        case DW_OP_form_tls_address:
        case DW_OP_call_ref:
        case DW_OP_bit_piece:
        case DW_OP_implicit_value:
        case DW_OP_stack_value:
        default:
            *location = invalid;
            return;
        }
    }

    assert(stackDepth > 0);
    *location = stack[0];
}

struct LOCEntry {
    uint8_t *ptr;
    uint64_t beg_offset;
    uint64_t end_offset;
    Location loc;
};
typedef struct LOCEntry LOCEntry;

static bool
loc_entry_eol(LOCEntry *entry)
{
    return entry->beg_offset == 0 && entry->end_offset == 0;
}

struct LOCCursor {
    uint8_t *beg;
    uint8_t *end;
    uint8_t *ptr;
};
typedef struct LOCCursor LOCCursor;

static void
init_loc_cursor(LOCCursor *cursor, DWARF_CompilationUnit *cu, unsigned long off)
{

    cursor->beg = debug_loc;
    cursor->end = debug_loc + debug_loc_length;
    cursor->ptr = cursor->beg + off;
}

static bool
loc_read_next(LOCCursor *cursor, LOCEntry *entry)
{
    DWARF_Attribute attr;

    if (cursor->ptr >= cursor->end)
        return false;
    entry->beg_offset = RDsize(cursor->ptr, location_address_size);
    entry->end_offset = RDsize(cursor->ptr, location_address_size);
    if (loc_entry_eol(entry))
        return true;

    attr.type = Block;
    attr.block.len = RD2(cursor->ptr);
    attr.block.ptr = cursor->ptr;
    decodeLocation(&entry->loc, attr, NULL, 0);
    cursor->ptr += attr.expr.len;

    return true;
}

static int reg_ebp = 0;
static int ebp_off = 0;

static void
find_best_fbloc(Location *loc, DWARF_CompilationUnit* cu,
                unsigned long fblocoff)
{
    LOCCursor cursor;
    LOCEntry entry;
    Location longest = { Location_RegRel, DW_REG_CFA, 0 };
    unsigned long longest_range = 0;
    unsigned long range;

    init_loc_cursor(&cursor, cu, fblocoff);
    while(loc_read_next(&cursor, &entry) && !loc_entry_eol(&entry)) {
        if (loc_is_regrel(&entry.loc) && entry.loc.reg == reg_ebp) {
            *loc = entry.loc;
            return;
        }
        range = entry.end_offset - entry.beg_offset;
        if (range > longest_range) {
            longest_range = range;
            longest = entry.loc;
        }
    }
    *loc = longest;
}

// Call Frame Information entry (CIE or FDE)
enum CFIEntry_Type {
    CFIEntry_CIE,
    CFIEntry_FDE
};

struct CFIEntry {
    uint8_t *ptr;
    uint8_t *end;
    enum CFIEntry_Type type;
    uint64_t CIE_pointer;

    // CIE
    uint8_t version;
    const char *augmentation;
    uint8_t address_size;
    uint8_t segment_size;
    uint64_t code_alignment_factor;
    uint64_t data_alignment_factor;
    uint64_t return_address_register;
    uint8_t *initial_instructions;
    uint64_t initial_instructions_length;

    // FDE
    uint64_t segment;
    uint64_t initial_location;
    uint64_t address_range;
    uint8_t *instructions;
    uint64_t instructions_length;
};
typedef struct CFIEntry CFIEntry;

struct CFICursor {
    uint8_t *beg;
    uint8_t *end;
    uint8_t *ptr;
};
typedef struct CFICursor CFICursor;

static void
init_cfi_cursor(CFICursor *cursor)
{
    cursor->beg = debug_frame;
    cursor->end = debug_frame + debug_frame_length;
    cursor->ptr = cursor->beg;
}

static bool
cfi_read_CIE(CFIEntry *entry, uint8_t **_p)
{
    uint8_t *p = *_p;

    entry->version = *p++;
    entry->augmentation = (char *)p++;
    if (entry->augmentation[0]) {
        // not supporting any augmentation
        entry->address_size = 4;
        entry->segment_size = 0;
        entry->code_alignment_factor = 0;
        entry->data_alignment_factor = 0;
        entry->return_address_register = 0;
    } else {
        if (entry->version >= 4) {
            entry->address_size = *p++;
            entry->segment_size = *p++;
        } else {
            entry->address_size = location_address_size;
            entry->segment_size = 0;
        }
        entry->code_alignment_factor = LEB128(p);
        entry->data_alignment_factor = SLEB128(p);
        entry->return_address_register = LEB128(p);
    }
    entry->initial_instructions = p;
    entry->initial_instructions_length = 0; // to be calculated outside

    *_p = p;
    return true;
}

static bool
cfi_read_header(CFICursor *cursor, uint8_t **_p, uint8_t **_pend,
                uint64_t *CIE_pointer)
{
    uint8_t *p = *_p;
    uint8_t *pend = *_pend;
    int64_t len;
    bool dwarf64;
    int ptrsize;

    if (p >= cursor->end)
        return false;
    len = RDsize(p, 4);
    dwarf64 = (len == 0xffffffff);
    ptrsize = dwarf64 ? 8 : 4;
    if (dwarf64)
        len = RDsize(p, 8);
    if (p + len > cursor->end) {
        *_p = p;
        return false;
    }

    pend = p + (uint64_t)len;
    *CIE_pointer = RDsize(p, ptrsize);
    *_p = p;
    *_pend = pend;
    return true;
}

static bool
cfi_read_next(CFICursor *cursor, CFIEntry *entry)
{
    uint8_t *p = cursor->ptr;

    if(!cfi_read_header(cursor, &p, &entry->end, &entry->CIE_pointer))
        return false;

    entry->ptr = cursor->ptr;

    if (entry->CIE_pointer == 0xffffffff) {
        entry->type = CFIEntry_CIE;

        cfi_read_CIE(entry, &p);

        entry->initial_instructions_length = entry->end - p;
    } else {
        uint8_t *q, *qend;
        uint64_t cie_off;

        entry->type = CFIEntry_FDE;

        q = cursor->beg + entry->CIE_pointer;
        if (!cfi_read_header(cursor, &q, &qend, &cie_off))
            return false;
        if (cie_off != 0xffffffff)
            return false;
        cfi_read_CIE(entry, &q);
        entry->initial_instructions_length = qend -
            entry->initial_instructions;

        entry->segment = entry->segment_size > 0 ?
            RDsize(p, entry->segment_size) : 0;
        entry->initial_location = RDsize(p, entry->address_size);
        entry->address_range = RDsize(p, entry->address_size);
        entry->instructions = p;
        entry->instructions_length = entry->end - p;
    }
    cursor->ptr = entry->end;
    return true;
}

struct CFACursor {
    const CFIEntry entry;
    uint8_t* beg;
    uint8_t* end;
    uint8_t* ptr;

    uint64_t loc;
    Location cfa;
};
typedef struct CFACursor CFACursor;

static void
cfa_set_instructions(CFACursor *cursor, uint8_t *instructions, int length);

static void
init_cfa_cursor(CFACursor *cursor, const CFIEntry *cfientry,
                uint64_t location)
{
    cursor->loc = location;
    cursor->cfa = (Location){ Location_RegRel, DW_REG_CFA, 0 };
    *(CFIEntry *)&cursor->entry = *cfientry;
    cfa_set_instructions(cursor, cursor->entry.initial_instructions,
                         cursor->entry.initial_instructions_length);
}

static void
cfa_set_instructions(CFACursor *cursor, uint8_t *instructions, int length)
{
    cursor->beg = instructions;
    cursor->end = instructions + length;
    cursor->ptr = cursor->beg;
}

static bool
cfa_before_restore(CFACursor *cursor)
{
    uint8_t instr;

    if (cursor->ptr >= cursor->end)
        return false;

    instr = *cursor->ptr;
    if ((instr & 0xc0) == DW_CFA_restore ||
        instr == DW_CFA_restore_extended ||
        instr == DW_CFA_restore_state)
        return true;
    return false;
}

static bool
cfa_process_next(CFACursor *cursor)
{
    uint8_t instr;
    int reg, off;

    if (cursor->ptr >= cursor->end)
        return false;

    instr = *cursor->ptr++;
    switch(instr & 0xc0) {
    case DW_CFA_advance_loc:
        cursor->loc += (instr & 0x3f) * cursor->entry.code_alignment_factor;
        break;
    case DW_CFA_offset:
        reg = instr & 0x3f; // set register rule to "factored offset"
        off = LEB128(cursor->ptr) * cursor->entry.data_alignment_factor;
        break;
    case DW_CFA_restore:
        reg = instr & 0x3f; // restore register to initial state
        break;

    case DW_CFA_extended:
        switch(instr) {
        case DW_CFA_set_loc:
            cursor->loc = RDsize(cursor->ptr, cursor->entry.address_size);
            break;
        case DW_CFA_advance_loc1:
            cursor->loc = *cursor->ptr++;
            break;
        case DW_CFA_advance_loc2:
            cursor->loc = RDsize(cursor->ptr, 2);
            break;
        case DW_CFA_advance_loc4:
            cursor->loc = RDsize(cursor->ptr, 4);
            break;

        case DW_CFA_def_cfa:
            cursor->cfa.reg = LEB128(cursor->ptr);
            cursor->cfa.off = LEB128(cursor->ptr);
            break;
        case DW_CFA_def_cfa_sf:
            cursor->cfa.reg = LEB128(cursor->ptr);
            cursor->cfa.off = SLEB128(cursor->ptr) *
                cursor->entry.data_alignment_factor;
            break;
        case DW_CFA_def_cfa_register:
            cursor->cfa.reg = LEB128(cursor->ptr);
            break;
        case DW_CFA_def_cfa_offset:
            cursor->cfa.off = LEB128(cursor->ptr);
            break;
        case DW_CFA_def_cfa_offset_sf:
            cursor->cfa.off = SLEB128(cursor->ptr) *
                cursor->entry.data_alignment_factor;
            break;
        case DW_CFA_def_cfa_expression: {
            DWARF_Attribute attr;
            attr.type = ExprLoc;
            attr.expr.len = LEB128(cursor->ptr);
            attr.expr.ptr = cursor->ptr;
            decodeLocation(&cursor->cfa, attr, NULL, 0);
            cursor->ptr += attr.expr.len;
            break;
        }

        case DW_CFA_undefined:
            reg = LEB128(cursor->ptr); // set register rule to "undefined"
            break;
        case DW_CFA_same_value:
            reg = LEB128(cursor->ptr); // set register rule to "same value"
            break;
        case DW_CFA_offset_extended:
            reg = LEB128(cursor->ptr); // set register rule to "factored offset"
            off = LEB128(cursor->ptr) * cursor->entry.data_alignment_factor;
            break;
        case DW_CFA_offset_extended_sf:
            reg = LEB128(cursor->ptr); // set register rule to "factored offset"
            off = SLEB128(cursor->ptr) * cursor->entry.data_alignment_factor;
            break;
        case DW_CFA_val_offset:
            reg = LEB128(cursor->ptr); // set register rule to "val offset"
            off = LEB128(cursor->ptr) * cursor->entry.data_alignment_factor;
            break;
        case DW_CFA_val_offset_sf:
            reg = LEB128(cursor->ptr); // set register rule to "val offset"
            off = SLEB128(cursor->ptr) * cursor->entry.data_alignment_factor;
            break;
        case DW_CFA_register:
            reg = LEB128(cursor->ptr); // set register rule to "register"
            reg = LEB128(cursor->ptr);
            break;
        case DW_CFA_expression:
        case DW_CFA_val_expression: {
            DWARF_Attribute attr;
            reg = LEB128(cursor->ptr); // set register rule to "expression"
            attr.type = Block;
            attr.block.len = LEB128(cursor->ptr);
            attr.block.ptr = cursor->ptr;
            decodeLocation(&cursor->cfa, attr, NULL, 0);
            // TODO: push cfa on stack
            cursor->ptr += attr.expr.len;
            break;
        }
        case DW_CFA_restore_extended:
            reg = LEB128(cursor->ptr); // restore register to initial state
            break;

        case DW_CFA_remember_state:
        case DW_CFA_restore_state:
        case DW_CFA_nop:
            break;
        }
    }
    (void)reg;
    (void)off;
    return true;
}

static void
find_best_cfa(Location *cfa, uint64_t pclo, uint64_t pchi)
{
    Location ebp = { Location_RegRel, reg_ebp, ebp_off };
    CFICursor cursor;
    CFIEntry entry;

    if (!debug_frame)
        goto out;

    init_cfi_cursor(&cursor);

    while (cfi_read_next(&cursor, &entry)) {
        if (entry.type == CFIEntry_FDE &&
            entry.initial_location <= pclo &&
            entry.initial_location + entry.address_range >= pchi) {
            int best_off = -1;
            CFACursor cfa_cursor;
            init_cfa_cursor(&cfa_cursor, &entry, pclo);
            while (cfa_process_next(&cfa_cursor)) { /* nothing */ }
            cfa_set_instructions(&cfa_cursor, entry.instructions,
                                 entry.instructions_length);
            while (!cfa_before_restore(&cfa_cursor) &&
                   cfa_process_next(&cfa_cursor)) {
                if ((int)cfa_cursor.cfa.off < best_off) {
                    cfa_cursor.cfa.off = best_off;
                    break;
                }
                best_off = cfa_cursor.cfa.off;
            }
            *cfa = cfa_cursor.cfa;
            return;
        }
    }
  out:
    *cfa = ebp;
}

static int
get_array_bounds(DWARF_InfoData *arrayid, DWARF_CompilationUnit* cu,
                 DIECursor *cursor, int *upper_bound);

static int
get_type_by_ptr(uint8_t *off)
{
    if (off)
        return offset_to_type[off - debug_info] ? : 0x3;
    return 0x3;                 /* void */
}

static int
get_type_size(DWARF_CompilationUnit *cu, uint8_t *type_ptr)
{
    DWARF_InfoData id;
    DIECursor cursor;

    init_die_cursor(&cursor, cu, type_ptr);

    if (!die_read_next(&cursor, &id, false))
        return 0;

    if (id.byte_size > 0)
        return id.byte_size;

    switch (id.tag) {
    case DW_TAG_ptr_to_member_type:
    case DW_TAG_reference_type:
    case DW_TAG_pointer_type:
        return cu->address_size;
    case DW_TAG_array_type: {
        int upper_bound, lower_bound;

        lower_bound = get_array_bounds(&id, cu, &cursor, &upper_bound);
        return (upper_bound - lower_bound + 1) * get_type_size(cu, id.type);
    }
    default:
        if (id.type)
            return get_type_size(cu, id.type);
        break;
    }
    return 0;
}

int
translate_type(int type)
{

    if (type < 0x1000) {
        int i;

        for (i = 0; i < typedefs_used; i++)
            if (type == typedefs[i])
                return translated_typedefs[i];
        return type;
    }

    return type;
}

static void
update_type_len(codeview_type *type, int len, int extra)
{
    /* unsigned char *p = (unsigned char *)type; */

    len += extra;

    /* for (; len & 3; len++) */
    /* 	p[len] = 0xf4 - (len & 3); */

    type->generic.len = len - sizeof(type->generic.len);

    assert((uintptr_t)type + len == (uintptr_t)user_types + user_types_used);
}

static void
update_reftype_len(codeview_reftype *type, int len, int extra)
{

    len += extra;
    type->generic.len = len - sizeof(type->generic.len);

    assert((uintptr_t)type + len == (uintptr_t)user_types + user_types_used ||
           (uintptr_t)type + len == (uintptr_t)dwarf_types + dwarf_types_used);
}

static void
update_symbol_len(codeview_symbol *symbol, int len, int extra)
{
    /* unsigned char *p = (unsigned char *)type; */

    len += extra;

    /* for (; len & 3; len++) */
    /* 	p[len] = 0xf4 - (len & 3); */

    symbol->generic.len = len - sizeof(symbol->generic.len);

    assert((uintptr_t)symbol + len ==
           (uintptr_t)user_symbols + user_symbols_used);
}

static int
create_empty_field_list_type()
{
    static int empty_field_list_type = 0;
    codeview_reftype *cvrt;

    if (empty_field_list_type > 0)
        return empty_field_list_type;

    cvrt = (codeview_reftype *)user_ptr(cvrt->fieldlist);
    cvrt->fieldlist.id = LF_FIELDLIST_V2;
    update_reftype_len(cvrt, sizeof(cvrt->fieldlist), 0);

    empty_field_list_type = next_user_type++;
    return empty_field_list_type;
}

static int
append_modifier_type(int type, int attr)
{
    codeview_type *cvt;

    cvt = (codeview_type *)user_ptr(cvt->modifier_v2);
    cvt->modifier_v2.id = LF_MODIFIER_V2;
    cvt->modifier_v2.type = translate_type(type);
    cvt->modifier_v2.attribute = attr;
    update_type_len(cvt, sizeof(cvt->modifier_v2), 0);

    dprintf("%x = type %x attr %x\n", next_user_type, type, attr);

    return next_user_type++;
}

static int
append_typedef(int type, const char *name, bool save_translation)
{
    int basetype = type;
    int typedef_type;

    if (type == 0x78)
        basetype = 0x75; // dchar type not understood by debugger, use uint instead

    if (use_typedef_enum) {
        codeview_type *cvt;

        cvt = (codeview_type *)user_ptr_extra(cvt->enumeration_v3,
                                              strlen(name) + 1);
        cvt->enumeration_v3.id = LF_ENUM_V3;
        cvt->enumeration_v3.type = basetype;
        cvt->enumeration_v3.fieldlist = create_empty_field_list_type();
        cvt->enumeration_v3.count = 0;
        cvt->enumeration_v3.property = kPropReserved2;
        strcpy(cvt->enumeration_v3.name, name);
        update_type_len(cvt, sizeof(cvt->enumeration_v3),
                        strlen(name) + 1);
        typedef_type = next_user_type++;
    } else
        typedef_type = append_modifier_type(type, 0);

    if (save_translation) {
        __asm("int $3");
        check_typedefs();
        typedefs[typedefs_used] = type;
        translated_typedefs[typedefs_used] = typedef_type;
        typedefs_used++;
    }

    dprintf("%x = type %x name %s\n", typedef_type, type, name);

    return typedef_type;
}

static int
append_pointer_type(int pointed_type, int attr)
{
    codeview_type *cvt;

    cvt = (codeview_type *)user_ptr(cvt->pointer_v2);
    cvt->pointer_v2.id = LF_POINTER_V2;
    cvt->pointer_v2.datatype = translate_type(pointed_type);
    cvt->pointer_v2.attribute = attr;
    update_type_len(cvt, sizeof(cvt->pointer_v2), 0);

    dprintf("%x = type %x attr %x\n", next_user_type, pointed_type, attr);

    return next_user_type++;
}

static int
add_basic_type(const char *name, uint64_t encoding, uint64_t byte_size)
{
    int type = 0, size = 0;
    int t, cvtype;

    switch (encoding) {
    case DW_ATE_boolean:
        type = 3;
        break;
    case DW_ATE_complex_float:
        type = 5;
        byte_size /= 2;
        break;
    case DW_ATE_float:
        type = 4;
        break;
    case DW_ATE_signed:
        type = 1;
        break;
    case DW_ATE_signed_char:
        type = 7;
        break;
    case DW_ATE_unsigned:
        type = 2;
        break;
    case DW_ATE_unsigned_char:
        type = 7;
        break;
    case DW_ATE_imaginary_float:
        type = 4;
        break;
    case DW_ATE_UTF:
        type = 7;
        break;
    default:
        errx(1, "%s: unknown basic type encoding %"PRIx64, __FUNCTION__,
             encoding);
    }

    switch (type) {
    case 1: /* signed */
    case 2: /* unsigned */
    case 3: /* boolean */
        switch (byte_size) {
        case 1:
            size = 0;
            break;
        case 2:
            size = 1;
            break;
        case 4:
            size = 2;
            break;
        case 8:
            size = 3;
            break;
        case 16:
            size = 4;
            break; // __int128? experimental, type exists with GCC for Win64
        default:
            errx(1, "%s: unsupported integer type size %"PRIx64, __FUNCTION__,
                 byte_size);
        }
        break;
    case 4:
    case 5:
        switch (byte_size) {
        case 4:
            size = 0;
            break;
        case 8:
            size = 1;
            break;
        case 10:
            size = 2;
            break;
        case 12:
            size = 2;
            break; // with padding bytes
        case 16:
            size = 3;
            break;
        case 6:
            size = 4;
            break;
        default:
            errx(1, "%s: unsupported real type size %"PRIx64, __FUNCTION__,
                 byte_size);
        }
        break;
    case 7:
        switch (byte_size) {
        case 1:
            size = 0;
            break;
        case 2:
            size = encoding == DW_ATE_signed_char ? 2 : 3;
            break;
        case 4:
            size = encoding == DW_ATE_signed_char ? 4 : 5;
            break;
        case 8:
            size = encoding == DW_ATE_signed_char ? 6 : 7;
            break;
        default:
            errx(1, "%s: unsupported real int type size %"PRIx64, __FUNCTION__,
                 byte_size);
        }
    }

    t = translate_type(size | (type << 4));
    cvtype = append_typedef(t, name, false);
    /* if (use_typedef_enum) */
    /*     addUdtSymbol(cvtype, name); */
    dprintf("%x = name %s encoding %"PRIx64" byte_size %"PRIx64"\n",
            cvtype, name, encoding, byte_size);
    return cvtype;
}

static void
append_global_var(struct bfd *bfd, const char* name, int type, asymbol** asym)
{
    codeview_symbol *cvs;

    /* for(char* cname = (char*) name; *cname; cname++) */
    /*     if (*cname == '.') */
    /*         *cname = dotReplacementChar; */

    if (!add_reloc(
            bfd, SYMTYPE_USER, asym,
            user_symbols_used + _offsetof(codeview_symbol, data_v3.offset),
            user_symbols_used + _offsetof(codeview_symbol, data_v3.segment)))
        return;

    cvs = (codeview_symbol *)symbol_ptr_extra(cvs->data_v3, strlen(name) + 1);
    cvs->data_v3.id = S_GDATA_V3;
    cvs->data_v3.offset = 0; // reloc offset;
    cvs->data_v3.symtype = type;
    cvs->data_v3.segment = 0; // reloc segment;
    strcpy(cvs->data_v3.name, name);
    update_symbol_len(cvs, sizeof(cvs->data_v3), strlen(name) + 1);

    dprintf("name %s type %x seg %x offset %lx\n",
            name,
            type,
            (*asym)->section->index,
            (long)(*asym)->value);
}

static bool
add_user_symbol(int type, const char *name)
{
    codeview_symbol *cvs;

    cvs = (codeview_symbol *)symbol_ptr_extra(cvs->udt_v3, strlen(name) + 1);
    cvs->udt_v3.id = S_UDT_V3;
    cvs->udt_v3.type = translate_type(type);
    strcpy(cvs->udt_v3.name, name);
    update_symbol_len(cvs, sizeof(cvs->udt_v3), strlen(name) + 1);

    dprintf("%x = name %s\n",
            type,
            name);
    return true;
}

static void
add_aggregate(bool clss, int n_element, int fieldlist, int property,
              int derived, int vshape, int structlen, const char* name)
{
    codeview_type *cvt;
    cvt = (codeview_type *)user_ptr_extra(cvt->struct_v3,
                                          name ? strlen(name) + 1 : 1);
    cvt->struct_v3.id = clss ? LF_CLASS_V3 : LF_STRUCTURE_V3;
    cvt->struct_v3.n_element = n_element;
    cvt->struct_v3.fieldlist = fieldlist;
    cvt->struct_v3.property = property;
    cvt->struct_v3.derived = derived;
    cvt->struct_v3.vshape = vshape;
    cvt->struct_v3.structlen = structlen;
    strcpy(cvt->struct_v3.name, name);
    update_type_len(cvt, sizeof(cvt->struct_v3), name ? strlen(name) + 1 : 1);
}

static void
add_field_member(int attr, int offset, int type, const char* name)
{
    codeview_fieldtype *cvftype;

    cvftype = (codeview_fieldtype *)dwarf_ptr_extra(cvftype->member_v3,
                                                    strlen(name) + 1);

    cvftype->member_v3.id = LF_MEMBER_V3;
    cvftype->member_v3.attribute = attr;
    cvftype->member_v3.offset = offset;
    cvftype->member_v3.type = translate_type(type);
    strcpy(cvftype->member_v3.name, name);

    /* unsigned char* p = (unsigned char*) cvftype; */
    /* for (; len & 3; len++) */
    /*     p[len] = 0xf4 - (len & 3); */
}

static int
add_structure(DWARF_InfoData *structid, DWARF_CompilationUnit *cu,
              DIECursor *cursor)
{
    bool isunion = structid->tag == DW_TAG_union_type;
    int fieldlist_type = 0;
    int nfields = 0;
    int cvtype;
    static char tmpname[16];

    //printf("Adding struct %s, entryoff %d, abbrev %d\n", structid->name, structid->entryOff, structid->abbrev);

    if (!structid->name) {
        sprintf(tmpname, "__%ct%x", isunion ? 'u' : 's', next_user_type);
        structid->name = tmpname;
    }

    if (cu) {
        codeview_reftype *fl;
        int flbegin;
        DWARF_InfoData id;

        flbegin = dwarf_types_used;
        fl = (codeview_reftype *)dwarf_ptr(fl->fieldlist);
        fl->fieldlist.id = LF_FIELDLIST_V2;

#if 0
        if(structid->containing_type && structid->containing_type != structid->entryOff)
        {
            codeview_fieldtype* bc = (codeview_fieldtype*) (dwarfTypes + cbDwarfTypes);
            bc->bclass_v2.id = LF_BCLASS_V2;
            bc->bclass_v2.offset = 0;
            bc->bclass_v2.type = getTypeByDWARFPtr(cu, structid->containing_type);
            bc->bclass_v2.attribute = 3; // public
            cbDwarfTypes += sizeof(bc->bclass_v2);
            for (; cbDwarfTypes & 3; cbDwarfTypes++)
                dwarfTypes[cbDwarfTypes] = 0xf4 - (cbDwarfTypes & 3);
            nfields++;
        }
#endif

        // cursor points to the first member
        while (die_read_next(cursor, &id, true)) {
            int cvid = -1;

            dprintf("<%"PRIx64"> id %s tag %x\n",
                    id.entry_ptr - debug_info,
                    id.name ? : "<null>",
                    id.tag);

            if (id.tag == DW_TAG_member) {
                int off = 0;

                if (!isunion) {
                    Location loc;

                    decodeLocation(&loc, id.member_location, NULL,
                                   DW_AT_data_member_location);
                    if (loc_is_abs(&loc)) {
                        off = loc.off;
                        cvid = S_CONSTANT_V2;
                    }
                }

                if (isunion || cvid == S_CONSTANT_V2) {
                    int type = get_type_by_ptr(id.type);
                    add_field_member(0, off, type, id.name ? : "");
                    dprintf("field %s offset %x type %x<%"PRIx64">\n",
                            id.name,
                            off,
                            type,
                            id.type ? id.type - debug_info : 0);
                    nfields++;
                }
            } else if (id.tag == DW_TAG_inheritance) {
                int off;
                Location loc;
                decodeLocation(&loc, id.member_location, NULL,
                               DW_AT_data_member_location);
                if (loc_is_abs(&loc)) {
                    cvid = S_CONSTANT_V2;
                    off = loc.off;
                }
                if (cvid == S_CONSTANT_V2) {
                    codeview_fieldtype *cvft;

                    cvft = (codeview_fieldtype *)dwarf_ptr(cvft->bclass_v2);
                    cvft->bclass_v2.id = LF_BCLASS_V2;
                    cvft->bclass_v2.offset = off;
                    cvft->bclass_v2.type =
                        translate_type(get_type_by_ptr(id.type));
                    cvft->bclass_v2.attribute = 3; // public
                    /* XXX pad? */
                    nfields++;
                }
            }
            goto_sibling(cursor);
        }

        fl = (codeview_reftype*)(dwarf_types + flbegin);
        update_reftype_len(fl, 0 /* sizeof(fl->fieldlist) */,
                           dwarf_types_used - flbegin);
        fieldlist_type = next_dwarf_type++;
    }

    add_aggregate(false, nfields, fieldlist_type,
                  fieldlist_type ? 0 : kPropIncomplete, 0, 0,
                  structid->byte_size, structid->name);

    cvtype = next_user_type++;
    add_user_symbol(cvtype, structid->name);
    dprintf("%x = %s fields %d fieldlist %x byte_size %"PRIx64
            " name %s\n",
            cvtype,
            isunion ? "union" : "structure",
            nfields,
            fieldlist_type,
            structid->byte_size,
            structid->name);
    return cvtype;
}

static int
get_array_bounds(DWARF_InfoData *arrayid, DWARF_CompilationUnit* cu,
                 DIECursor *cursor, int *upper_bound)
{
    int lower_bound = 0;
    DWARF_InfoData id;

    if (!cu)
        return 0;

    while (die_read_next(cursor, &id, true)) {
        if (id.tag == DW_TAG_subrange_type) {
            lower_bound = id.lower_bound;
            *upper_bound = id.upper_bound;
        }
        goto_sibling(cursor);
    }

    return lower_bound;
}

static int
write_numeric_leaf(int value, void *leaf)
{
    unsigned short int *type = (unsigned short int *)leaf;

    if (value >= 0 && value < LF_NUMERIC) {
        *(unsigned short int *)leaf = (unsigned short int)value;
        return 2;
    }

    leaf = type + 1;
    if (value >= -128 && value <= 127) {
        *type = LF_CHAR;
        *(char *)leaf = (char)value;
        return 3;
    }
    if (value >= -32768 && value <= 32767) {
        *type = LF_SHORT;
        *(short *)leaf = (short)value;
        return 4;
    }
    if (value >= 0 && value <= 65535) {
        *type = LF_USHORT;
        *(unsigned short *)leaf = (unsigned short)value;
        return 4;
    }
    *type = LF_LONG;
    *(uint32_t *) leaf = (uint32_t)value; /* not long */
    return 6;
}

static int
add_array(DWARF_InfoData *arrayid, DWARF_CompilationUnit *cu, DIECursor *cursor)
{
    int cvtype;
    codeview_type *cvt;
    int upper_bound, lower_bound;
    int size, len, extra;

    lower_bound = get_array_bounds(arrayid, cu, cursor, &upper_bound);
    size = (upper_bound - lower_bound + 1) * get_type_size(cu, arrayid->type);
    len = -(int)sizeof(cvt->array_v3.arrlen);

    extra = 6 + len + 1;        /* max size numeric leaf + 1 */
    cvt = (codeview_type*)user_ptr_extra(cvt->array_v3, extra);
    cvt->array_v3.id = LF_ARRAY_V3;
    cvt->array_v3.elemtype = get_type_by_ptr(arrayid->type);
    cvt->array_v3.idxtype = 0x74;

    len += write_numeric_leaf(size, &cvt->array_v3.arrlen);
    ((uint8_t *)cvt)[len++] = 0; // empty name
    /* for (; len & 3; len++) */
    /*     userTypes[cbUserTypes + len] = 0xf4 - (len & 3); */

    assert(len < extra);
    user_types_used -= extra - len;
    update_type_len(cvt, sizeof(cvt->array_v3), len);

    cvtype = next_user_type++;
    dprintf("%x = array size %x\n",
            cvtype,
            size);
    return cvtype;
}

static int
add_subroutine(DWARF_InfoData *id, DWARF_CompilationUnit *cu, DIECursor *cursor)
{
    int cvtype;
    int arglist_type = 0;
    int nargs = 0;
    codeview_type *cvt;

    if (cu) {
        codeview_reftype *al;
        int albegin;
        DWARF_InfoData id;

        albegin = dwarf_types_used;
        al = (codeview_reftype *)dwarf_ptr(al->arglist_v2);
        al->arglist_v2.id = LF_ARGLIST_V2;

        // cursor points to the first member
        while (die_read_next(cursor, &id, true)) {
            if (id.tag == DW_TAG_formal_parameter) {
                int type = get_type_by_ptr(id.type);

                add_dwarf_types(sizeof(al->arglist_v2.args[0]));
                al = (codeview_reftype *)(dwarf_types + albegin);
                al->arglist_v2.args[nargs] = type;
                dprintf("arg type %x<%"PRIx64">\n",
                        type,
                        id.type ? id.type - debug_info : 0);
                nargs++;
            } else if (id.tag == DW_TAG_unspecified_parameters) {
                /* XXX do something */
            } else
                dprintf("<%"PRIx64"> tag %x not formal parameter\n",
                        id.entry_ptr - debug_info, id.tag);
            goto_sibling(cursor);
        }

        al = (codeview_reftype *)(dwarf_types + albegin);
        al->arglist_v2.num = nargs;
        update_reftype_len(al, sizeof(al->arglist_v2),
                           nargs * sizeof(al->arglist_v2.args[0]));
        arglist_type = next_dwarf_type++;
    }

    cvt = (codeview_type *)user_ptr(cvt->procedure_v2);
    cvt->procedure_v2.id = LF_PROCEDURE_V2;
    cvt->procedure_v2.rvtype = get_type_by_ptr(id->type);
    cvt->procedure_v2.call = 0;
    cvt->procedure_v2.reserved = 0;
    cvt->procedure_v2.params = nargs;
    cvt->procedure_v2.arglist = arglist_type;
    update_type_len(cvt, sizeof(cvt->procedure_v2), 0);

    cvtype = next_user_type++;
    dprintf("%x = subroutine args %x typelist %x\n",
            cvtype,
            nargs,
            arglist_type);
    return cvtype;
}

#if 0
static void
append_end_arg(void)
{
    codeview_symbol *cvs;

    cvs = (codeview_symbol *)symbol_ptr(cvs->generic);
    cvs->generic.id = S_ENDARG_V1;
    update_symbol_len(cvs, sizeof(cvs->generic), 0);
}
#endif

static void
append_end(void)
{
    codeview_symbol *cvs;

    cvs = (codeview_symbol *)symbol_ptr(cvs->generic);
    cvs->generic.id = S_END_V1;
    update_symbol_len(cvs, sizeof(cvs->generic), 0);
}

enum CV_X86_REG {
    CV_REG_NONE = 0,
    CV_REG_EAX = 17,
    CV_REG_ECX = 18,
    CV_REG_EDX = 19,
    CV_REG_EBX = 20,
    CV_REG_ESP = 21,
    CV_REG_EBP = 22,
    CV_REG_ESI = 23,
    CV_REG_EDI = 24,
    CV_REG_ES = 25,
    CV_REG_CS = 26,
    CV_REG_SS = 27,
    CV_REG_DS = 28,
    CV_REG_FS = 29,
    CV_REG_GS = 30,
    CV_REG_IP = 31,
    CV_REG_FLAGS = 32,
    CV_REG_EIP = 33,
    CV_REG_EFLAGS = 34,
    CV_REG_ST0 = 128, /* this includes ST1 to ST7 */
    CV_REG_XMM0 = 154, /* this includes XMM1 to XMM7 */
    CV_REG_XMM8 = 252, /* this includes XMM9 to XMM15 */

    // 64-bit regular registers
    CV_AMD64_RAX      =  328,
    CV_AMD64_RBX      =  329,
    CV_AMD64_RCX      =  330,
    CV_AMD64_RDX      =  331,
    CV_AMD64_RSI      =  332,
    CV_AMD64_RDI      =  333,
    CV_AMD64_RBP      =  334,
    CV_AMD64_RSP      =  335,

    // 64-bit integer registers with 8-, 16-, and 32-bit forms (B, W, and D)
    CV_AMD64_R8       =  336,
    CV_AMD64_R9       =  337,
    CV_AMD64_R10      =  338,
    CV_AMD64_R11      =  339,
    CV_AMD64_R12      =  340,
    CV_AMD64_R13      =  341,
    CV_AMD64_R14      =  342,
    CV_AMD64_R15      =  343,
};
typedef enum CV_X86_REG CV_X86_REG;

static CV_X86_REG
dwarf_to_x86_reg(unsigned int dwarf_reg)
{
    switch (dwarf_reg) {
    case  0: return CV_REG_EAX;
    case  1: return CV_REG_ECX;
    case  2: return CV_REG_EDX;
    case  3: return CV_REG_EBX;
    case  4: return CV_REG_ESP;
    case  5: return CV_REG_EBP;
    case  6: return CV_REG_ESI;
    case  7: return CV_REG_EDI;
    case  8: return CV_REG_EIP;
    case  9: return CV_REG_EFLAGS;
    case 10: return CV_REG_CS;
    case 11: return CV_REG_SS;
    case 12: return CV_REG_DS;
    case 13: return CV_REG_ES;
    case 14: return CV_REG_FS;
    case 15: return CV_REG_GS;

    case 16: case 17: case 18: case 19:
    case 20: case 21: case 22: case 23:
        return (CV_X86_REG)(CV_REG_ST0 + dwarf_reg - 16);
    case 32: case 33: case 34: case 35:
    case 36: case 37: case 38: case 39:
        return (CV_X86_REG)(CV_REG_XMM0 + dwarf_reg - 32);
    default:
        return CV_REG_NONE;
    }
}

static CV_X86_REG
dwarf_to_amd64_reg(unsigned int dwarf_reg)
{
    switch (dwarf_reg) {
    case  0: return CV_AMD64_RAX;
    case  1: return CV_AMD64_RDX;
    case  2: return CV_AMD64_RCX;
    case  3: return CV_AMD64_RBX;
    case  4: return CV_AMD64_RSI;
    case  5: return CV_AMD64_RDI;
    case  6: return CV_AMD64_RBP;
    case  7: return CV_AMD64_RSP;
    case  8: return CV_AMD64_R8;
    case  9: return CV_AMD64_R9;
    case 10: return CV_AMD64_R10;
    case 11: return CV_AMD64_R11;
    case 12: return CV_AMD64_R12;
    case 13: return CV_AMD64_R13;
    case 14: return CV_AMD64_R14;
    case 15: return CV_AMD64_R15;
    case 16: return CV_REG_IP;
    case 49: return CV_REG_EFLAGS;
    case 50: return CV_REG_ES;
    case 51: return CV_REG_CS;
    case 52: return CV_REG_SS;
    case 53: return CV_REG_DS;
    case 54: return CV_REG_FS;
    case 55: return CV_REG_GS;

    case 17: case 18: case 19: case 20:
    case 21: case 22: case 23: case 24:
        return (CV_X86_REG)(CV_REG_XMM0 + dwarf_reg - 17);
    case 25: case 26: case 27: case 28:
    case 29: case 30: case 31: case 32:
        return (CV_X86_REG)(CV_REG_XMM8 + dwarf_reg - 25);
    case 33: case 34: case 35: case 36:
    case 37: case 38: case 39: case 40:
        return (CV_X86_REG)(CV_REG_ST0 + dwarf_reg - 33);
    default:
        return CV_REG_NONE;
    }
}

static bool isX64 = false;

static void
append_stack_var(const char *name, int type, Location *loc, Location *cfa)
{
    codeview_symbol *cvs;
    int reg = loc->reg;
    int off = loc->off;
    CV_X86_REG baseReg;

    if (reg == DW_REG_CFA) {
        reg = cfa->reg;
        off += cfa->off;
    }

    if (isX64)
        baseReg = dwarf_to_amd64_reg(reg);
    else
        baseReg = dwarf_to_x86_reg(reg);

    if (baseReg == CV_REG_NONE)
        return;

    if (baseReg == CV_REG_EBP) {
        cvs = (codeview_symbol*)symbol_ptr_extra(cvs->stack_v3,
                                                 strlen(name) + 1);
        cvs->stack_v3.id = S_BPREL_V3;
        cvs->stack_v3.offset = off;
        cvs->stack_v3.symtype = type;
        strcpy(cvs->stack_v3.name, name);
        update_symbol_len(cvs, sizeof(cvs->stack_v3), strlen(name) + 1);
        dprintf("var %s ebprel off %x type %x\n", name, off, type);
    } else {
        cvs = (codeview_symbol*)symbol_ptr_extra(cvs->regrel_v3,
                                                 strlen(name) + 1);
        cvs->regrel_v3.id = S_REGREL_V3;
        cvs->regrel_v3.offset = off;
        cvs->regrel_v3.symtype = type;
        cvs->regrel_v3.reg = baseReg;
        strcpy(cvs->regrel_v3.name, name);
        update_symbol_len(cvs, sizeof(cvs->regrel_v3), strlen(name) + 1);
        dprintf("var %s regrel reg %x off %x type %x\n", name, baseReg,
                off, type);
    }
}

static void
append_lexical_block(struct bfd *bfd, DWARF_InfoData *id, unsigned int proclo)
{
    codeview_symbol *cvs;

    if (!add_reloc(
            bfd, SYMTYPE_USER, code_seg_sym,
            user_symbols_used + _offsetof(codeview_symbol, block_v3.offset),
            user_symbols_used + _offsetof(codeview_symbol, block_v3.segment)))
        return;

    cvs = (codeview_symbol *)symbol_ptr_extra(cvs->block_v3, 1);
    cvs->block_v3.id = S_BLOCK_V3;
    cvs->block_v3.parent = 0;
    cvs->block_v3.end = 0; // destSize + sizeof(cvs->block_v3) + 12;
    cvs->block_v3.length = id->pchi - id->pclo;
    cvs->block_v3.offset = id->pclo - code_seg_off; /* reloc */
    cvs->block_v3.segment = 0;  /* reloc */
    cvs->block_v3.name[0] = 0;
    update_symbol_len(cvs, sizeof(cvs->block_v3), 1);
}

struct DIECursorStack {
    struct DIECursorStack *next;
    DIECursor c;
};
typedef struct DIECursorStack DIECursorStack;

static int
add_proc(struct bfd *bfd, DWARF_InfoData *procid, DWARF_CompilationUnit *cu,
         DIECursor *cursor)
{
    uint64_t pclo = procid->pclo - code_seg_off;
    uint64_t pchi = procid->pchi - code_seg_off;
    int cvtype = -1;
    codeview_symbol *cvs;
    int procbegin;
    Location framebase;
    Location cfa;
    asymbol **asym = NULL;
    int nargs = 0;
    int arglist_type = 0;

    asym = find_symbol(bfd, procid->name);
    if (!asym)
        return cvtype;

    if (!add_reloc(
            bfd, SYMTYPE_USER, asym,
            user_symbols_used + _offsetof(codeview_symbol, proc_v3.offset),
            user_symbols_used + _offsetof(codeview_symbol, proc_v3.segment)))
        return cvtype;

    // GLOBALPROC
    procbegin = user_symbols_used;
    cvs = (codeview_symbol *)symbol_ptr_extra(cvs->proc_v3,
                                              strlen(procid->name) + 1);
    cvs->proc_v3.id = S_GPROC_V3;
    cvs->proc_v3.pparent = 0;
    cvs->proc_v3.pend = 0;
    cvs->proc_v3.next = 0;
    cvs->proc_v3.proc_len = pchi - pclo;
    cvs->proc_v3.debug_start = pclo - pclo;
    cvs->proc_v3.debug_end = pchi - pclo;
    cvs->proc_v3.proctype = 0; // updated below
    cvs->proc_v3.offset = 0; // reloc pclo;
    cvs->proc_v3.segment = 0; // reloc img.codeSegment + 1;
    cvs->proc_v3.flags = 0;
    strcpy(cvs->proc_v3.name, procid->name);
    update_symbol_len(cvs, sizeof(cvs->proc_v3), strlen(procid->name) + 1);

#if 0 // add funcinfo
    cvs = (codeview_symbol*) (udtSymbols + cbUdtSymbols);
    cvs->funcinfo_32.id = S_FUNCINFO_32;
    cvs->funcinfo_32.sizeLocals = 20;
    memset(cvs->funcinfo_32.unknown, 0, sizeof(cvs->funcinfo_32.unknown));
    cvs->funcinfo_32.unknown[5] = 4;
    cvs->funcinfo_32.info = 0x4200;
    cvs->funcinfo_32.unknown2 = 0x11;
    len = sizeof(cvs->funcinfo_32);
    for (; len & (align-1); len++)
        udtSymbols[cbUdtSymbols + len] = 0xf4 - (len & 3);
    cvs->funcinfo_32.len = len - 2;
    cbUdtSymbols += len;
#endif

    cvs = (codeview_symbol *)symbol_ptr(cvs->frame_info_v2);
    cvs->frame_info_v2.id = S_FRAMEINFO_V2;
    cvs->frame_info_v2.sz_frame = 0x18;
    cvs->frame_info_v2.unknown2 = 0;
    cvs->frame_info_v2.unknown3 = 0;
    cvs->frame_info_v2.sz_saved_regs = 0;
    cvs->frame_info_v2.eh_offset = 0;
    cvs->frame_info_v2.eh_sect = 0;
    cvs->frame_info_v2.flags = 0x200;
    update_symbol_len(cvs, sizeof(cvs->frame_info_v2), 0);

#if 0
    addStackVar("local_var", 0x1001, 8);
#endif

    /* __asm("int $3"); */
    decodeLocation(&framebase, procid->frame_base, 0, DW_AT_frame_base);
    if (loc_is_abs(&framebase)) // pointer into location list in .debug_loc? assume CFA
        find_best_fbloc(&framebase, cu, framebase.off);

    find_best_cfa(&cfa, procid->pclo, procid->pchi);

    if (cu) {
        codeview_reftype* al;
        int albegin;
        DWARF_InfoData id;
        int stackvar = 0;
        DIECursor prev;
        codeview_type *cvt;

        albegin = dwarf_types_used;
        al = (codeview_reftype *)dwarf_ptr(al->arglist_v2);
        al->arglist_v2.id = LF_ARGLIST_V2;

        prev = *cursor;
        while (die_read_next(cursor, &id, true) &&
               id.tag == DW_TAG_formal_parameter) {
            if (id.tag == DW_TAG_formal_parameter) {
                int type = get_type_by_ptr(id.type);
                if (id.name && (id.location.type == ExprLoc ||
                                id.location.type == Block)) {
                    Location loc;
                    decodeLocation(&loc, id.location, &framebase, 0);
                    if (loc_is_regrel(&loc)) {
                        append_stack_var(id.name, type, &loc, &cfa);
                        stackvar++;
                    }
                }
                add_dwarf_types(sizeof(al->arglist_v2.args[0]));
                al = (codeview_reftype *)(dwarf_types + albegin);
                al->arglist_v2.args[nargs] = type;
                dprintf("param %s type %x<%"PRIx64">\n",
                        id.name,
                        type,
                        id.type ? id.type - debug_info : 0);
                nargs++;
            } else if (id.tag == DW_TAG_unspecified_parameters) {
                /* XXX do something */
            } else
                dprintf("<%"PRIx64"> tag %x not formal parameter\n",
                        id.entry_ptr - debug_info, id.tag);
            prev = *cursor;
        }
        /* if (stackvar) */
        /*     append_end_arg(); */

        al = (codeview_reftype *)(dwarf_types + albegin);
        al->arglist_v2.num = nargs;
        update_reftype_len(al, sizeof(al->arglist_v2),
                           nargs * sizeof(al->arglist_v2.args[0]));
        arglist_type = next_dwarf_type++;

        cvt = (codeview_type *)user_ptr(cvt->procedure_v2);
        cvt->procedure_v2.id = LF_PROCEDURE_V2;
        cvt->procedure_v2.rvtype = get_type_by_ptr(procid->type);
        cvt->procedure_v2.call = 0;
        cvt->procedure_v2.reserved = 0;
        cvt->procedure_v2.params = nargs;
        cvt->procedure_v2.arglist = arglist_type;
        update_type_len(cvt, sizeof(cvt->procedure_v2), 0);

        cvs = (codeview_symbol*)(user_symbols + procbegin);
        cvtype = cvs->proc_v3.proctype = next_user_type++;

        DIECursorStack *cstack = NULL, *cs;
        cs = (DIECursorStack *)malloc(sizeof(DIECursorStack));
        cs->c = prev;
        cs->next = cstack;
        cstack = cs;

        while (cstack) {
            cs = cstack;
            prev = cs->c;
            cursor = &prev;
            cstack = cs->next;
            free(cs);

            stackvar = 0;
            while (die_read_next(cursor, &id, false)) {
                if (id.tag == DW_TAG_lexical_block) {
                    if (id.hasChild && id.pchi != id.pclo) {
                        DIECursor next = *cursor;
                        append_lexical_block(bfd, &id, pclo + code_seg_off);
                        goto_sibling(&next);
                        cs = (DIECursorStack *)malloc(sizeof(DIECursorStack));
                        cs->c = next;
                        cs->next = cstack;
                        cstack = cs;
                        get_subtree_cursor(cursor, cursor);
                        continue;
                    }
                } else if (id.tag == DW_TAG_variable) {
                    if (id.name && (id.location.type == ExprLoc ||
                                    id.location.type == Block)) {
                        Location loc;
                        decodeLocation(&loc, id.location, &framebase, 0);
                        if (loc_is_regrel(&loc)) {
                            append_stack_var(
                                id.name, get_type_by_ptr(id.type), &loc, &cfa);
                            stackvar++;
                        }
                    }
                }
                goto_sibling(cursor);
            }
            if (1 || stackvar)
                append_end();
        }
    } else {
        // appendEndArg();
        append_end();
    }

    dprintf("%x = subprogram name %s args %x typelist %x\n",
            cvtype,
            procid->name,
            nargs,
            arglist_type);
    return cvtype;
}

static void
map_types(struct bfd *bfd)
{
    int tid = next_user_type;
    unsigned int off = 0;

    offset_to_type = (uint32_t *)calloc(debug_info_length, sizeof(uint32_t));

    while (off < debug_info_length) {
        DWARF_CompilationUnit *cu = (DWARF_CompilationUnit*)(debug_info + off);
        DIECursor cursor;
        DWARF_InfoData id;

        /* dprintf("cu %x len %x abbrev offset %x\n", off, cu->unit_length, */
        /*         cu->debug_abbrev_offset); */

        init_die_cursor(&cursor, cu, cu->data);

        while (die_read_next(&cursor, &id, false)) {
            /* dprintf("0x%08"PRIx64", level = %d, id.code = %x, " */
            /*         "id.tag = %x\n", id.entry_ptr - debug_info, */
            /*         cursor.level, id.code, id.tag); */

            switch (id.tag) {
            case DW_TAG_subprogram:
                if (!id.pclo && !id.pchi)
                    break;

            case DW_TAG_base_type:
            case DW_TAG_typedef:
            case DW_TAG_pointer_type:
            case DW_TAG_subroutine_type:
            case DW_TAG_array_type:
            case DW_TAG_const_type:
            case DW_TAG_structure_type:
            case DW_TAG_reference_type:

            case DW_TAG_class_type:
            case DW_TAG_enumeration_type:
            case DW_TAG_string_type:
            case DW_TAG_union_type:
            case DW_TAG_ptr_to_member_type:
            case DW_TAG_set_type:
            /* case DW_TAG_subrange_type: */
            case DW_TAG_file_type:
            case DW_TAG_packed_type:
            case DW_TAG_thrown_type:
            case DW_TAG_volatile_type:
            case DW_TAG_restrict_type: // DWARF3
            case DW_TAG_interface_type:
            case DW_TAG_unspecified_type:
            case DW_TAG_mutable_type: // withdrawn
            case DW_TAG_shared_type:
            case DW_TAG_rvalue_reference_type:
                offset_to_type[id.entry_ptr - debug_info] = tid;
                tid++;
            }
        }

        off += sizeof(cu->unit_length) + cu->unit_length;
    }
    vprintf("found %x types\n", tid);
    next_dwarf_type = tid;
}

static void
create_types(struct bfd *bfd)
{
    int tid = next_user_type;
    unsigned int off = 0;

    while (off < debug_info_length) {
        DWARF_CompilationUnit *cu = (DWARF_CompilationUnit*)(debug_info + off);
        DIECursor cursor;
        DWARF_InfoData id;
        int pointer_attr = bfd_get_arch_size(bfd) == 64 ? 0x1000C : 0x800A;

        dprintf("cu %x len %x abbrev offset %x\n", off, cu->unit_length,
                cu->debug_abbrev_offset);

        init_die_cursor(&cursor, cu, cu->data);

        while (die_read_next(&cursor, &id, false)) {
            int cvtype = -1;
            int type;

            /* dprintf("0x%08"PRIx64", level = %d, id.code = %x, " */
            /*         "id.tag = %x\n", id.entry_ptr - debug_info, */
            /*         cursor.level, id.code, id.tag); */

            if (id.specification) {
                __asm("int $3");
#if 0
                DIECursor spec_cursor;
                DWARF_InfoData idspec;

                init_die_cursor(&spec_cursor, cu, id.specification);
                die_read_next(&spec_cursor, &idspec, false);
                //assert seems invalid, combination DW_TAG_member and
                //DW_TAG_variable found in the wild
                //assert(id.tag == idspec.tag);
                id.merge(idspec);
#endif
            }

            dnewline();
            dprintf("<%"PRIx64"> id %s tag %x\n",
                    id.entry_ptr - debug_info,
                    id.name ? : "<null>",
                    id.tag);

            switch (id.tag) {
            case DW_TAG_base_type:
                cvtype = add_basic_type(id.name, id.encoding, id.byte_size);
                dprintf("<%"PRIx64"> %x = id %s base enc %"PRIx64" bs %"PRIx64
                        "\n",
                        id.entry_ptr - debug_info,
                        cvtype,
                        id.name ? : "<null>",
                        id.encoding,
                        id.byte_size);
                break;
            case DW_TAG_typedef:
                type = get_type_by_ptr(id.type);
                cvtype = append_modifier_type(type, 0);
                add_user_symbol(cvtype, id.name);
                dprintf("<%"PRIx64"> %x = id %s typedef type %x<%"PRIx64">\n",
                        id.entry_ptr - debug_info,
                        cvtype,
                        id.name ? : "<null>",
                        type,
                        id.type ? id.type - debug_info : 0);
                break;
            case DW_TAG_pointer_type:
                type = get_type_by_ptr(id.type);
                cvtype = append_pointer_type(type, pointer_attr); // XXX id.byte_size?
                dprintf("<%"PRIx64"> %x = id %s pointer type %x<%"PRIx64">\n",
                        id.entry_ptr - debug_info,
                        cvtype,
                        id.name ? : "<null>",
                        type,
                        id.type ? id.type - debug_info : 0);
                break;
            case DW_TAG_const_type:
                type = get_type_by_ptr(id.type);
                cvtype = append_modifier_type(type, 1);
                dprintf("<%"PRIx64"> %x = id %s const type %x<%"PRIx64">\n",
                        id.entry_ptr - debug_info,
                        cvtype,
                        id.name ? : "<null>",
                        type,
                        id.type ? id.type - debug_info : 0);
                break;
            case DW_TAG_reference_type:
                type = get_type_by_ptr(id.type);
                cvtype = append_pointer_type(type, pointer_attr | 0x20);
                dprintf("<%"PRIx64"> %x = id %s reference type %x<%"PRIx64">\n",
                        id.entry_ptr - debug_info,
                        cvtype,
                        id.name ? : "<null>",
                        type,
                        id.type ? id.type - debug_info : 0);
                break;

            case DW_TAG_class_type:
            case DW_TAG_structure_type:
            case DW_TAG_union_type: {
                DIECursor subtree_cursor;

                get_subtree_cursor(&subtree_cursor, &cursor);
                cvtype = add_structure(&id, cu, &subtree_cursor);
                dprintf("<%"PRIx64"> %x = id %s struct\n",
                        id.entry_ptr - debug_info,
                        cvtype,
                        id.name ? : "<null>");
                break;
            }
            case DW_TAG_array_type: {
                DIECursor subtree_cursor;

                get_subtree_cursor(&subtree_cursor, &cursor);
                cvtype = add_array(&id, cu, &subtree_cursor);
                dprintf("<%"PRIx64"> %x = id %s array\n",
                        id.entry_ptr - debug_info,
                        cvtype,
                        id.name ? : "<null>");
                break;
            }
            case DW_TAG_subroutine_type: {
                DIECursor subtree_cursor;

                get_subtree_cursor(&subtree_cursor, &cursor);
                cvtype = add_subroutine(&id, cu, &subtree_cursor);
                dprintf("<%"PRIx64"> %x = id %s subroutine\n",
                        id.entry_ptr - debug_info,
                        cvtype,
                        id.name ? : "<null>");
                break;
            }

            /* case DW_TAG_subrange_type: */
            case DW_TAG_enumeration_type: /* XXXcl */
            case DW_TAG_string_type:
            case DW_TAG_ptr_to_member_type:
            case DW_TAG_set_type:
            case DW_TAG_file_type:
            case DW_TAG_packed_type:
            case DW_TAG_thrown_type:
            case DW_TAG_volatile_type: /* XXXcl */
            case DW_TAG_restrict_type: // DWARF3
            case DW_TAG_interface_type:
            case DW_TAG_unspecified_type:
            case DW_TAG_mutable_type: // withdrawn
            case DW_TAG_shared_type:
            case DW_TAG_rvalue_reference_type:
                type = 0x74;
                cvtype = append_pointer_type(type, pointer_attr);
                dprintf("<%"PRIx64"> %x = id %s ****** tag %x\n",
                        id.entry_ptr - debug_info,
                        cvtype,
                        id.name ? : "<null>",
                        id.tag);
                break;

            case DW_TAG_subprogram:
                if (id.entry_off == 49683)
                    __asm("int $3");
                if (id.name && (id.pclo || id.pchi)) {
                    DIECursor subtree_cursor;

                    get_subtree_cursor(&subtree_cursor, &cursor);
                    cvtype = add_proc(bfd, &id, cu, &subtree_cursor);
                    if (cvtype >= 0)
                        dprintf("<%"PRIx64"> %x = id %s subprogram pclo %"
                                PRIx64" pchi %"PRIx64"\n",
                                id.entry_ptr - debug_info,
                                cvtype,
                                id.name ? : "<null>",
                                id.pclo,
                                id.pchi);
                    else {
                        codeview_type *cvt;

                        cvt = (codeview_type *)user_ptr(cvt->generic);
                        cvt->generic.id = 0;
                        update_type_len(cvt, sizeof(cvt->generic), 0);
                        cvtype = next_user_type++;
                        dprintf("<%"PRIx64"> %x = id %s invalid subprogram "
                                "pclo %"PRIx64" pchi %"PRIx64"\n",
                                id.entry_ptr - debug_info,
                                cvtype,
                                id.name ? : "<null>",
                                id.pclo,
                                id.pchi);
                    }
                }
                break;

            case DW_TAG_compile_unit:
#if 0
                if (/* id.dir && */ id.name) {
                    if (id.ranges > 0 && id.ranges < debug_ranges_length) {
                        unsigned char *r = (unsigned char *)debug_ranges +
                            id.ranges;
                        unsigned char *rend = (unsigned char *)debug_ranges +
                            debug_ranges_length;
                        while (r < rend) {
                            unsigned long pclo = RD4(r);
                            unsigned long pchi = RD4(r);
                            if (pclo == 0 && pchi == 0)
                                break;
                            /* printf("%s %s %lx - %lx\n", */
                            /*        id.dir, id.name, pclo, pchi); */
                            if (!addDWARFSectionContrib(mod, pclo, pchi))
                                return false;
                        }
                    } else {
                        /* printf("%s %s %"PRIx64" - %"PRIx64"\n", */
                        /*        id.dir, id.name, id.pclo, id.pchi); */
                        if (!addDWARFSectionContrib(mod, id.pclo, id.pchi))
                            return false;
                    }
                }
#endif
                break;

            case DW_TAG_variable:
                if (id.name) {
                    asymbol **asym = NULL;
                    /* int seg = -1; */
                    /* unsigned long segOff; */
                    if (id.location.type == Invalid && id.external &&
                        id.linkage_name)
                        asym = find_symbol(bfd, id.linkage_name/* , */
                                           /* seg, segOff */);
                    else {
                        Location loc;
                        decodeLocation(&loc, id.location, NULL, 0);
                        if (loc_is_abs(&loc))
                            asym = find_symbol(bfd, id.name);
                    }
                    if (asym) {
                        type = get_type_by_ptr(id.type);
                        append_global_var(bfd, id.name, type, asym);
                    }
                    dprintf("<%"PRIx64"> id %s variable\n",
                            id.entry_ptr - debug_info,
                            id.name ? : "<null>");
                }
                break;

            case DW_TAG_formal_parameter:
            case DW_TAG_unspecified_parameters:
            case DW_TAG_inheritance:
            case DW_TAG_member:
            case DW_TAG_inlined_subroutine:
            case DW_TAG_lexical_block:
            default:
                break;
            }

            /* validate cvtype is set for set of tags */
            switch (id.tag) {
            case DW_TAG_subprogram:
                if (!id.pclo && !id.pchi)
                    break;

            case DW_TAG_base_type:
            case DW_TAG_typedef:
            case DW_TAG_pointer_type:
            case DW_TAG_subroutine_type:
            case DW_TAG_array_type:
            case DW_TAG_const_type:
            case DW_TAG_structure_type:
            case DW_TAG_reference_type:

            case DW_TAG_class_type:
            case DW_TAG_enumeration_type:
            case DW_TAG_string_type:
            case DW_TAG_union_type:
            case DW_TAG_ptr_to_member_type:
            case DW_TAG_set_type:
            /* case DW_TAG_subrange_type: */
            case DW_TAG_file_type:
            case DW_TAG_packed_type:
            case DW_TAG_thrown_type:
            case DW_TAG_volatile_type:
            case DW_TAG_restrict_type: // DWARF3
            case DW_TAG_interface_type:
            case DW_TAG_unspecified_type:
            case DW_TAG_mutable_type: // withdrawn
            case DW_TAG_shared_type:
            case DW_TAG_rvalue_reference_type:
                if (cvtype < 0)
                    __asm("int $3");
                break;
            default:
                if (cvtype >= 0)
                    __asm("int $3");
                break;
            }

            if (cvtype >= 0)
            {
                assert(cvtype == tid);
                tid++;
                dprintf("%x tid %x XXXXXXXXXXXXXXXXXXXXXXXXXX\n", user_types_used, tid);
                if (offset_to_type[id.entry_ptr - debug_info] != cvtype)
                    __asm("int $3");
                assert(offset_to_type[id.entry_ptr - debug_info] == cvtype);
            }
        }

        off += sizeof(cu->unit_length) + cu->unit_length;
    }
    vprintf("created %x types\n", tid);
}

void
process_types(struct bfd *bfd)
{
    asection *sec;

    location_address_size = bfd_get_arch_size(bfd) == 64 ? 8 : 4;
    reg_ebp = bfd_get_arch_size(bfd) == 64 ? 6 : 5;
    ebp_off = bfd_get_arch_size(bfd) == 64 ? 16 : 8;
    isX64 = bfd_get_arch_size(bfd) == 64 ? true : false;

    sec = bfd_get_section_by_name(bfd, ".text");
    code_seg_off = bfd_section_vma(bfd, sec);
    code_seg_sym = all_sec[sec->index].sym_ptr_ptr;

    /* debug$T header */
    *(uint32_t *)user_ptr(uint32_t) = 4;

    map_types(bfd);

    create_types(bfd);

    if (user_types_used > 0) {
        debugT_length += user_types_used;
        debugT = (uint8_t *)realloc(debugT, debugT_length);
        memcpy(debugT + debugT_length - user_types_used,
               user_types, user_types_used);
        user_types_used = 0;
    }
    if (dwarf_types_used > 0) {
        debugT_length += dwarf_types_used;
        debugT = (uint8_t *)realloc(debugT, debugT_length);
        memcpy(debugT + debugT_length - dwarf_types_used,
               dwarf_types, dwarf_types_used);
        dwarf_types_used = 0;
    }
}

void
process_symbols(struct bfd *bfd)
{
    codeview_symbol *cvs;
    int used = 0, size;

    debugS_length = sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t);
    size = sizeof(cvs->compiland_v3) + strlen(bfd_get_filename(bfd)) + 1;
    size += user_symbols_used;

    debugS_length += size;
    debugS = (uint8_t *)malloc(debugS_length + portion_align);

    /* debug$S header */
    *(uint32_t *)(debugS + used) = 4;
    used += sizeof(uint32_t);

    *(uint32_t *)(debugS + used) = 0xf1;
    used += sizeof(uint32_t);

    *(uint32_t *)(debugS + used) = size;
    used += sizeof(uint32_t);

    cvs = (codeview_symbol *)(debugS + used);
    cvs->compiland_v3.id = S_COMPILAND_V3;
    cvs->compiland_v3.unknown = 0;
    strcpy(cvs->compiland_v3.name, bfd_get_filename(bfd));
    cvs->compiland_v3.len = sizeof(cvs->compiland_v3) +
        strlen(bfd_get_filename(bfd)) + 1 - sizeof(cvs->compiland_v3.len);
    used += sizeof(cvs->compiland_v3) + strlen(bfd_get_filename(bfd)) + 1;

    reloc_off[SYMTYPE_USER] = used;
    memcpy(debugS + used, user_symbols, user_symbols_used);
    used += user_symbols_used;
    user_symbols_used = 0;

    assert(used == debugS_length);

    while (debugS_length % portion_align)
        debugS[debugS_length++] = 0;
}
