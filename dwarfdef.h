
#ifndef _DWARFDEF_H_
#define _DWARFDEF_H_

#define LEB128(p) (({                                   \
                unsigned int x = 0;                     \
                int shift = 0;                          \
                while (*(p) & 0x80) {                   \
                    x |= (*(p) & 0x7f) << shift;        \
                    shift += 7;                         \
                    (p)++;                              \
                }                                       \
                x |= *(p) << shift;                     \
                (p)++;                                  \
                x;                                      \
            }))

#define SLEB128(p) (({                                          \
                unsigned int x = 0;                             \
                int shift = 0;                                  \
                while (*(p) & 0x80) {                           \
                    x |= (*(p) & 0x7f) << shift;                \
                    shift += 7;                                 \
                    (p)++;                                      \
                }                                               \
                x |= *(p) << shift;                             \
                if (*(p) & 0x40)                                \
                    x |= -(1 << (shift + 7)); /*sign extend */  \
                (p)++;                                          \
                x;                                              \
            }))

#define RD2(p) (({                              \
                uint16_t x = *(p)++;            \
                x |= *(p)++ << 8;               \
                x;                              \
            }))

#define RD4(p) (({                              \
                uint32_t x = *(p)++;            \
                x |= *(p)++ << 8;               \
                x |= *(p)++ << 16;              \
                x |= *(p)++ << 24;              \
                x;                              \
            }))

#define RD8(p) (({                                      \
                int shift;                              \
                uint64_t x = *(p)++;                    \
                for (shift = 8; shift < 64; shift += 8) \
                    x |= (uint64_t)*(p)++ << shift;     \
                x;                                      \
            }))

#define RDsize(p, _size) (({ \
                int size = (_size);                             \
                int shift;                                      \
                uint64_t x = *(p)++;                            \
                if (size > 8)                                   \
                    size = 8;                                   \
                for (shift = 8; shift < size * 8; shift += 8)   \
                    x |= (uint64_t)*(p)++ << shift;             \
                x;                                              \
            }))

enum AttrClass {
    Invalid,
    Addr,
    Block,
    Const,
    String,
    Flag,
    Ref,
    ExprLoc,
    SecOffset
};
typedef enum AttrClass AttrClass;

/* XXX check layout required? */
struct DWARF_Attribute {
    AttrClass type;
    union {
        uint64_t addr;
        struct {
            uint8_t *ptr;
            unsigned int len;
        } block;
        uint64_t cons;
        const char *string;
        bool flag;
        uint8_t *ref;
        struct {
            uint8_t *ptr;
            unsigned int len;
        } expr;
        unsigned int sec_offset;
    };
};
typedef struct DWARF_Attribute DWARF_Attribute;

#include "pshpack1.h"
struct DWARF_CompilationUnit {
    unsigned int unit_length; // 12 byte in DWARF-64
    unsigned short version;
    unsigned int debug_abbrev_offset; // 8 byte in DWARF-64
    uint8_t address_size;
    uint8_t data[];
} __attribute__((packed));
#include "poppack.h"
typedef struct DWARF_CompilationUnit DWARF_CompilationUnit;

#define isDWARF64(cu) ((cu)->unit_length == (unsigned int)~0)
#define refSize(cu) (isDWARF64(cu) ? 8 : 4)

struct DWARF_InfoData {
    uint8_t *entry_ptr;
    unsigned int entry_off; // offset in the cu
    int code;
    uint8_t *abbrev;
    int tag;
    int hasChild;

    const char *name;
    const char *linkage_name;
    const char *dir;
    uint64_t byte_size;
    uint8_t *sibling;
    uint64_t encoding;
    uint64_t pclo;
    uint64_t pchi;
    uint64_t ranges;
    uint8_t *type;
    uint8_t *containing_type;
    uint8_t *specification;
    uint64_t inlined;
    bool external;
    DWARF_Attribute location;
    DWARF_Attribute member_location;
    DWARF_Attribute frame_base;
    uint64_t upper_bound;
    uint64_t lower_bound;
};
typedef struct DWARF_InfoData DWARF_InfoData;

#endif  /* _DWARFDEF_H_ */
