/**
 * @file elf-types.hpp
 * @brief ARM ELF32 little-endian on-disk structures, constants, and decoders.
 *
 * The core is deliberately hard-wired to ARM ELF32-LE as a *data format*. These
 * structs mirror the ELF ABI layout exactly so they can be memcpy'd out of a
 * byte buffer on any little-endian host or on the Cortex-M target.
 */
#pragma once
#include <bit>
#include <cstdint>

namespace loader::elf {

// The on-disk ELF32 structs are memcpy'd directly out of byte buffers, which is
// only correct when the host byte order matches the little-endian file format.
static_assert(std::endian::native == std::endian::little,
              "loader core requires a little-endian host/target (ARM Cortex-M, x86)");

using addr = std::uint32_t;  ///< Unsigned program address.
using off  = std::uint32_t;  ///< File offset.
using word = std::uint32_t;  ///< Unsigned 32-bit word.
using half = std::uint16_t;  ///< Unsigned 16-bit half-word.

/// @brief ELF file header (52 bytes).
struct Ehdr {
    unsigned char e_ident[16]; ///< Magic + class/data/version identification.
    half e_type;       ///< Object file type (ET_DYN expected).
    half e_machine;    ///< Architecture (EM_ARM expected).
    word e_version;    ///< Object file version.
    addr e_entry;      ///< Entry point (0 for these libraries).
    off  e_phoff;      ///< Program header table file offset.
    off  e_shoff;      ///< Section header table file offset.
    word e_flags;      ///< Processor-specific flags.
    half e_ehsize;     ///< ELF header size in bytes.
    half e_phentsize;  ///< Program header entry size.
    half e_phnum;      ///< Program header entry count.
    half e_shentsize;  ///< Section header entry size.
    half e_shnum;      ///< Section header entry count.
    half e_shstrndx;   ///< Section header string table index.
};

/// @brief Program header (32 bytes).
struct Phdr {
    word p_type;    ///< Segment type (PT_LOAD relevant here).
    off  p_offset;  ///< Segment file offset.
    addr p_vaddr;   ///< Segment virtual address.
    addr p_paddr;   ///< Segment physical address.
    word p_filesz;  ///< Bytes of the segment in the file.
    word p_memsz;   ///< Bytes of the segment in memory (>= filesz; bss zero-fill).
    word p_flags;   ///< Segment flags.
    word p_align;   ///< Segment alignment.
};

/// @brief Section header (40 bytes).
struct Shdr {
    word sh_name;       ///< Section name (index into section string table).
    word sh_type;       ///< Section type.
    word sh_flags;      ///< Section attributes.
    addr sh_addr;       ///< Virtual address in memory.
    off  sh_offset;     ///< Offset in file.
    word sh_size;       ///< Size in bytes.
    word sh_link;       ///< Link to another section.
    word sh_info;       ///< Additional section information.
    word sh_addralign;  ///< Address alignment.
    word sh_entsize;    ///< Entry size if the section holds a table.
};

/// @brief Dynamic symbol table entry (16 bytes).
struct Sym {
    word st_name;          ///< Symbol name (index into .dynstr).
    addr st_value;         ///< Symbol value (image-relative address; 0 => external).
    word st_size;          ///< Symbol size in bytes.
    unsigned char st_info; ///< Binding (high nibble) and type (low nibble).
    unsigned char st_other;///< Visibility.
    half st_shndx;         ///< Section index (SHN_UNDEF => external).
};

/// @brief REL relocation entry (8 bytes; ARM uses REL, not RELA).
struct Rel {
    addr r_offset;  ///< Location to apply the relocation.
    word r_info;    ///< Symbol index (high 24 bits) and type (low 8 bits).
};

/// @brief Dynamic-section entry (8 bytes); array terminated by DT_NULL.
struct Dyn {
    std::int32_t d_tag;  ///< Dynamic entry type (DT_*).
    word         d_val;  ///< Value or address (d_val/d_ptr union; same width here).
};

constexpr std::int32_t DT_NULL          = 0;   ///< End of _DYNAMIC array.
constexpr std::int32_t DT_PLTGOT        = 3;   ///< Address of the PLT/GOT.
constexpr std::int32_t DT_HASH          = 4;   ///< Address of the symbol hash table.
constexpr std::int32_t DT_STRTAB        = 5;   ///< Address of the string table.
constexpr std::int32_t DT_SYMTAB        = 6;   ///< Address of the symbol table.
constexpr std::int32_t DT_STRSZ         = 10;  ///< Size in bytes of the string table.
constexpr std::int32_t DT_SYMENT        = 11;  ///< Size of one symbol table entry.
constexpr std::int32_t DT_INIT_ARRAY    = 25;  ///< Address of the init function array.
constexpr std::int32_t DT_FINI_ARRAY    = 26;  ///< Address of the fini function array.
constexpr std::int32_t DT_INIT_ARRAYSZ  = 27;  ///< Size in bytes of the init array.
constexpr std::int32_t DT_FINI_ARRAYSZ  = 28;  ///< Size in bytes of the fini array.

// --- Identification constants ---
constexpr unsigned char ELFMAG0 = 0x7f; ///< e_ident[0].
constexpr unsigned char ELFMAG1 = 'E';  ///< e_ident[1].
constexpr unsigned char ELFMAG2 = 'L';  ///< e_ident[2].
constexpr unsigned char ELFMAG3 = 'F';  ///< e_ident[3].
constexpr unsigned char ELFCLASS32  = 1; ///< e_ident[EI_CLASS] for 32-bit.
constexpr unsigned char ELFDATA2LSB = 1; ///< e_ident[EI_DATA] for little-endian.
constexpr int EI_CLASS = 4; ///< Index of the class byte.
constexpr int EI_DATA  = 5; ///< Index of the data-encoding byte.

constexpr half ET_REL = 1;  ///< Relocatable file type.
constexpr half ET_EXEC = 2; ///< Executable file type.
constexpr half ET_DYN = 3;  ///< Shared object file type.
constexpr half EM_ARM = 40; ///< ARM architecture (0x28).

constexpr word PT_LOAD = 1; ///< Loadable program segment.

constexpr word SHT_REL   = 9; ///< Relocation section (Elf32_Rel entries).
constexpr word SHF_WRITE = 1; ///< Section occupies writable memory.
constexpr word SHF_ALLOC = 2; ///< Section occupies memory during execution.
constexpr word SHT_INIT_ARRAY      = 14;        ///< Constructors.
constexpr word SHT_ARM_EXIDX       = 0x70000001; ///< ARM exception index.
constexpr word SHT_ARM_ATTRIBUTES  = 0x70000003; ///< ARM build attributes.

// ARM EABI flags (e_flags).
constexpr word EF_ARM_EABIMASK       = 0xff000000; ///< EABI version mask.
constexpr word EF_ARM_EABI_VER5      = 0x05000000; ///< EABI version 5.
constexpr word EF_ARM_ABI_FLOAT_SOFT = 0x00000200; ///< Soft-float ABI.
constexpr word EF_ARM_ABI_FLOAT_HARD = 0x00000400; ///< Hard-float ABI.
constexpr word EF_ARM_BE8            = 0x00800000; ///< Big-endian instructions.
constexpr word EF_ARM_LE8            = 0x00400000; ///< Little-endian instructions.

/// @brief A symbol value is in Thumb state when bit 0 is set.
constexpr bool is_thumb(std::uint32_t st_value) noexcept { return (st_value & 1u) != 0; }
/// @brief A symbol value is in ARM state when bit 0 is clear.
constexpr bool is_arm(std::uint32_t st_value) noexcept { return (st_value & 1u) == 0; }
/// @brief Preserve a symbol's own ARM/Thumb bit (do not force Thumb).
constexpr std::uint32_t code_addr(std::uint32_t st_value) noexcept { return st_value; }

/// @brief ARM REL relocation types understood by the loader.
///        The first six are the dynamic types; the rest cover A32/T32 static
///        relocations emitted for ET_REL and no-pic images.
enum class rel_type : std::uint8_t {
    NONE              = 0,   ///< R_ARM_NONE.
    PC24              = 1,   ///< R_ARM_PC24 (legacy B/BL).
    ABS32             = 2,   ///< R_ARM_ABS32.
    REL32             = 3,   ///< R_ARM_REL32.
    ABS16             = 5,   ///< R_ARM_ABS16.
    ABS12             = 6,   ///< R_ARM_ABS12.
    THM_ABS5          = 7,   ///< R_ARM_THM_ABS5.
    ABS8              = 8,   ///< R_ARM_ABS8.
    SBREL32           = 9,   ///< R_ARM_SBREL32.
    THM_CALL          = 10,  ///< R_ARM_THM_CALL (T32 BL/BLX).
    THM_PC8           = 11,  ///< R_ARM_THM_PC8.
    TLS_DTPMOD32      = 17,  ///< TLS module id.
    TLS_DTPOFF32      = 18,  ///< TLS block offset.
    TLS_TPOFF32       = 19,  ///< TLS thread-pointer offset.
    COPY              = 20,  ///< R_ARM_COPY.
    GLOB_DAT          = 21,  ///< R_ARM_GLOB_DAT.
    JUMP_SLOT         = 22,  ///< R_ARM_JUMP_SLOT.
    RELATIVE          = 23,  ///< R_ARM_RELATIVE.
    GOTOFF32          = 24,  ///< R_ARM_GOTOFF32.
    BASE_PREL         = 25,  ///< R_ARM_BASE_PREL (GOT base - P).
    GOT_BREL          = 26,  ///< R_ARM_GOT_BREL.
    PLT32             = 27,  ///< R_ARM_PLT32 (legacy PLT BL).
    CALL              = 28,  ///< R_ARM_CALL (BL/BLX).
    JUMP24            = 29,  ///< R_ARM_JUMP24 (B).
    THM_JUMP24        = 30,  ///< R_ARM_THM_JUMP24 (T32 B.W).
    BASE_ABS          = 31,  ///< R_ARM_BASE_ABS.
    TARGET1           = 38,  ///< R_ARM_TARGET1 (ABS32 on bare-metal).
    SBREL31           = 39,  ///< R_ARM_SBREL31.
    V4BX              = 40,  ///< R_ARM_V4BX (no-op on ARMv5+).
    TARGET2           = 41,  ///< R_ARM_TARGET2 (REL32 on bare-metal).
    PREL31            = 42,  ///< R_ARM_PREL31 (.ARM.exidx).
    MOVW_ABS_NC       = 43,  ///< R_ARM_MOVW_ABS_NC.
    MOVT_ABS          = 44,  ///< R_ARM_MOVT_ABS.
    MOVW_PREL_NC      = 45,  ///< R_ARM_MOVW_PREL_NC.
    MOVT_PREL         = 46,  ///< R_ARM_MOVT_PREL.
    THM_MOVW_ABS_NC   = 47,  ///< R_ARM_THM_MOVW_ABS_NC.
    THM_MOVT_ABS      = 48,  ///< R_ARM_THM_MOVT_ABS.
    THM_MOVW_PREL_NC  = 49,  ///< R_ARM_THM_MOVW_PREL_NC.
    THM_MOVT_PREL     = 50,  ///< R_ARM_THM_MOVT_PREL.
    THM_JUMP19        = 51,  ///< R_ARM_THM_JUMP19.
    THM_JUMP6         = 52,  ///< R_ARM_THM_JUMP6.
    THM_ALU_PREL_11_0 = 53,  ///< R_ARM_THM_ALU_PREL_11_0.
    THM_PC12          = 54,  ///< R_ARM_THM_PC12.
    ABS32_NOI         = 55,  ///< R_ARM_ABS32_NOI.
    REL32_NOI         = 56,  ///< R_ARM_REL32_NOI.
    GOT_PREL          = 96,  ///< R_ARM_GOT_PREL.
    THM_PC11          = 102, ///< R_ARM_THM_PC11.
    THM_PC9           = 103, ///< R_ARM_THM_PC9.
    IRELATIVE         = 160, ///< R_ARM_IRELATIVE.
};

/// @brief Symbol binding (high nibble of st_info).
enum class bind : std::uint8_t {
    LOCAL  = 0, ///< STB_LOCAL.
    GLOBAL = 1, ///< STB_GLOBAL.
    WEAK   = 2, ///< STB_WEAK.
};

/// @brief Extract the symbol-table index from a relocation's r_info.
constexpr word        r_sym (word info) noexcept { return info >> 8; }
/// @brief Extract the relocation type from a relocation's r_info.
constexpr std::uint8_t r_type(word info) noexcept { return static_cast<std::uint8_t>(info & 0xffu); }
/// @brief Extract the binding from a symbol's st_info.
constexpr std::uint8_t st_bind(std::uint8_t info) noexcept { return info >> 4; }
/// @brief Extract the symbol type from a symbol's st_info.
constexpr std::uint8_t st_type(std::uint8_t info) noexcept { return info & 0xfu; }

} // namespace loader::elf
