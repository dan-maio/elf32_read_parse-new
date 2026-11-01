/**
 * @file arm-reloc.hpp
 * @brief ARM A32/T32 relocation engine shared by the SCL loaders.
 *
 * The reader in `elf-types.hpp` defines the relocation numbers.  This header
 * decodes the in-place addend of a REL relocation and applies the relocation,
 * including the A32 `BL`/`BLX`/`B`, `MOVW`/`MOVT` and the T32 counterparts.
 *
 * The engine is header-only and freestanding: it does not allocate, does not
 * use exceptions, and every function is `noexcept`.  A loader supplies the
 * resolved symbol value `S`, the decoded addend `A` and the relocation site
 * `P`; `apply()` writes the instruction or data word and reports range and
 * interworking errors instead of truncating.
 *
 * The Thumb bit is preserved: a symbol value with bit 0 set is Thumb, a value
 * with bit 0 clear is ARM.  `apply()` uses that bit to choose `BL` versus
 * `BLX`, and rejects a `B`/`B.W` that would have to change state.
 */
#ifndef LOADER_ARM_RELOC_HPP
#define LOADER_ARM_RELOC_HPP

#include "loader/elf-types.hpp"
#include "loader/error.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace loader::arm {

/// Instruction set of the relocation site (not of the target).
enum class isa : std::uint8_t { arm, thumb };

struct context {
    std::uint32_t S;  ///< Symbol value, bit 0 = Thumb.
    std::uint32_t A;  ///< Addend, already decoded from the instruction/word.
    std::uint32_t P;  ///< Address of the relocation site.
    isa           site; ///< `arm` for R_ARM_*, `thumb` for R_ARM_THM_*.
};

// ---- little-endian instruction access --------------------------------------

inline std::uint16_t ld16(const std::byte* p) noexcept {
    std::uint16_t v = 0;
    std::memcpy(&v, p, sizeof v);
    return v;
}
inline std::uint32_t ld32(const std::byte* p) noexcept {
    std::uint32_t v = 0;
    std::memcpy(&v, p, sizeof v);
    return v;
}
inline void st16(std::byte* p, std::uint16_t v) noexcept { std::memcpy(p, &v, sizeof v); }
inline void st32(std::byte* p, std::uint32_t v) noexcept { std::memcpy(p, &v, sizeof v); }

inline std::int32_t sext(std::uint32_t v, unsigned bits) noexcept {
    const std::uint32_t sign = 1u << (bits - 1u);
    v &= (bits == 32u) ? 0xffffffffu : ((1u << bits) - 1u);
    return static_cast<std::int32_t>((v ^ sign) - sign);
}

// ---- ARM instruction fields ------------------------------------------------

/// imm16 of an ARM `MOVW`/`MOVT` (`cond 0011 0x00 imm4 Rd imm12`).
inline std::uint32_t arm_movw_imm16(const std::byte* p) noexcept {
    const std::uint32_t w = ld32(p);
    return ((w >> 16) & 0xfu) << 12 | (w & 0xfffu);
}
inline void arm_set_movw_imm16(std::byte* p, std::uint32_t imm16) noexcept {
    std::uint32_t w = ld32(p);
    w = (w & ~0x000f0fffu) | (((imm16 >> 12) & 0xfu) << 16) | (imm16 & 0xfffu);
    st32(p, w);
}

/// imm24 of an ARM `B`/`BL`/`BLX` instruction.
inline std::uint32_t arm_imm24(const std::byte* p) noexcept { return ld32(p) & 0x00ffffffu; }

inline bool in_range_arm(std::int32_t delta) noexcept {
    return (delta & 3) == 0 && delta >= -0x02000000 && delta <= 0x01fffffc;
}
inline bool in_range_thumb(std::int32_t delta) noexcept {
    return (delta & 1) == 0 && delta >= -0x01000000 && delta <= 0x00fffffe;
}

inline error arm_write_b(std::byte* p, std::int32_t delta) noexcept {
    if (!in_range_arm(delta)) return error::RELOC_OVERFLOW;
    st32(p, 0xea000000u | (static_cast<std::uint32_t>(delta) >> 2 & 0x00ffffffu));
    return error::OK;
}
inline error arm_write_bl(std::byte* p, std::int32_t delta, bool blx) noexcept {
    // BL to an ARM target must be 4-aligned; BLX to a Thumb target may be
    // 2-aligned (bit 1 is the H bit of the instruction).
    const bool aligned = blx ? ((delta & 1) == 0) : ((delta & 3) == 0);
    const std::int32_t hi = blx ? 0x01fffffe : 0x01fffffc;
    if (!aligned || delta < -0x02000000 || delta > hi) return error::RELOC_OVERFLOW;
    const std::uint32_t u = static_cast<std::uint32_t>(delta);
    if (blx) {
        const std::uint32_t h = (u >> 1) & 1u;
        st32(p, 0xfa000000u | (h << 24) | ((u >> 2) & 0x00ffffffu));
    } else {
        st32(p, 0xeb000000u | ((u >> 2) & 0x00ffffffu));
    }
    return error::OK;
}

// ---- Thumb-2 instruction fields -------------------------------------------

/// Decode the S/J1/J2/imm10/imm11 fields of a T32 `BL`/`BLX`/`B.W`.
inline std::uint32_t thumb_branch_addend(const std::byte* p) noexcept {
    const std::uint32_t h1 = ld16(p), h2 = ld16(p + 2);
    const std::uint32_t s  = (h1 >> 10) & 1u;
    const std::uint32_t j1 = (h2 >> 13) & 1u, j2 = (h2 >> 11) & 1u;
    const std::uint32_t i1 = (~(j1 ^ s)) & 1u, i2 = (~(j2 ^ s)) & 1u;
    std::uint32_t a = (s << 24) | (i1 << 23) | (i2 << 22) |
                      ((h1 & 0x3ffu) << 12) | ((h2 & 0x7ffu) << 1);
    if (a & 0x01000000u) a |= 0xfe000000u;
    return a;
}

/// Encode a T32 `BL` (bit12=1), `BLX` (bit12=0) or `B.W` (T4, bits15-14=10).
inline error thumb_write_branch(std::byte* p, std::int32_t delta, unsigned form) noexcept {
    // form: 0 = BL, 1 = BLX, 2 = B.W
    if (!in_range_thumb(delta)) return error::RELOC_OVERFLOW;
    const std::uint32_t u = static_cast<std::uint32_t>(delta);
    const std::uint32_t s  = (u >> 24) & 1u;
    const std::uint32_t i1 = (u >> 23) & 1u, i2 = (u >> 22) & 1u;
    const std::uint32_t j1 = (~(i1 ^ s)) & 1u, j2 = (~(i2 ^ s)) & 1u;
    const std::uint32_t h1 = 0xf000u | (s << 10) | ((u >> 12) & 0x3ffu);
    std::uint32_t h2;
    if (form == 2)
        h2 = 0x9000u | (j1 << 13) | (j2 << 11) | ((u >> 1) & 0x7ffu);   // B.W T4
    else
        h2 = (form == 1 ? 0xc000u : 0xd000u) | (j1 << 13) | (j2 << 11) | ((u >> 1) & 0x7ffu);
    st16(p, static_cast<std::uint16_t>(h1));
    st16(p + 2, static_cast<std::uint16_t>(h2));
    return error::OK;
}

/// imm16 of a T32 `MOVW`/`MOVT` (`i:imm4:imm3:imm8`).
inline std::uint32_t thumb_movw_imm16(const std::byte* p) noexcept {
    const std::uint32_t h1 = ld16(p), h2 = ld16(p + 2);
    return (((h1 >> 10) & 1u) << 15) | ((h1 & 0xfu) << 11) |
           (((h2 >> 12) & 0x7u) << 8) | (h2 & 0xffu);
}
inline void thumb_set_movw_imm16(std::byte* p, std::uint32_t imm16) noexcept {
    std::uint32_t h1 = ld16(p), h2 = ld16(p + 2);
    h1 = (h1 & ~0x040fu) | (((imm16 >> 15) & 1u) << 10) | ((imm16 >> 11) & 0xfu);
    h2 = (h2 & ~0x70ffu) | (((imm16 >> 8) & 0x7u) << 12) | (imm16 & 0xffu);
    st16(p, static_cast<std::uint16_t>(h1));
    st16(p + 2, static_cast<std::uint16_t>(h2));
}

// ---- addend decoding -------------------------------------------------------

/// Decode the in-place addend of a REL relocation.  Returns false when the
/// type is not a REL type this engine knows.
inline bool decode_addend(std::uint8_t type, const std::byte* p, std::uint32_t& out) noexcept {
    switch (static_cast<elf::rel_type>(type)) {
    case elf::rel_type::ABS32:
    case elf::rel_type::REL32:
    case elf::rel_type::TARGET1:
    case elf::rel_type::TARGET2:
    case elf::rel_type::ABS32_NOI:
    case elf::rel_type::REL32_NOI:
        out = ld32(p);
        return true;
    case elf::rel_type::PREL31: {
        const std::uint32_t w = ld32(p);
        out = (w & 0x40000000u) ? (w | 0x80000000u) : (w & 0x7fffffffu);
        return true;
    }
    case elf::rel_type::CALL:
    case elf::rel_type::JUMP24:
    case elf::rel_type::PC24:
    case elf::rel_type::PLT32:
        out = static_cast<std::uint32_t>(sext((arm_imm24(p) << 2), 26));
        return true;
    case elf::rel_type::MOVW_ABS_NC:
    case elf::rel_type::MOVW_PREL_NC:
        out = arm_movw_imm16(p);
        return true;
    case elf::rel_type::MOVT_ABS:
    case elf::rel_type::MOVT_PREL:
        out = arm_movw_imm16(p) << 16;
        return true;
    case elf::rel_type::THM_CALL:
    case elf::rel_type::THM_JUMP24:
        out = thumb_branch_addend(p);
        return true;
    case elf::rel_type::THM_MOVW_ABS_NC:
    case elf::rel_type::THM_MOVW_PREL_NC:
        out = thumb_movw_imm16(p);
        return true;
    case elf::rel_type::THM_MOVT_ABS:
    case elf::rel_type::THM_MOVT_PREL:
        out = thumb_movw_imm16(p) << 16;
        return true;
    case elf::rel_type::ABS16:
        out = ld16(p);
        return true;
    case elf::rel_type::ABS12:
        out = ld32(p) & 0xfffu;
        return true;
    case elf::rel_type::THM_ABS5:
        out = (ld16(p) >> 6) & 0x1fu;
        return true;
    case elf::rel_type::ABS8:
        out = *reinterpret_cast<const std::uint8_t*>(p);
        return true;
    case elf::rel_type::NONE:
    case elf::rel_type::V4BX:
    case elf::rel_type::GLOB_DAT:
    case elf::rel_type::JUMP_SLOT:
    case elf::rel_type::RELATIVE:
        out = 0;
        return true;
    default:
        return false;
    }
}

// ---- applying --------------------------------------------------------------

/**
 * @brief Apply a relocation at @p p.
 * @return `OK`, `UNSUPPORTED_RELOC` (PIC/TLS/COPY/RELATIVE are the loader's
 *         job), `RELOC_OVERFLOW` (branch out of range), or
 *         `RELOC_INTERWORK` (a B/B.W cannot switch state).
 */
inline error apply(std::uint8_t type, std::byte* p, const context& c) noexcept {
    using rt = elf::rel_type;
    switch (static_cast<rt>(type)) {
    case rt::NONE:
    case rt::V4BX:
        return error::OK;

    case rt::ABS32:
    case rt::TARGET1:
    case rt::ABS32_NOI:
        st32(p, c.S + c.A);
        return error::OK;
    case rt::REL32:
    case rt::TARGET2:
    case rt::REL32_NOI:
        st32(p, c.S + c.A - c.P);
        return error::OK;
    case rt::PREL31: {
        const std::uint32_t old = ld32(p);
        st32(p, (old & 0x80000000u) | ((c.S + c.A - c.P) & 0x7fffffffu));
        return error::OK;
    }
    case rt::ABS16:
        st16(p, static_cast<std::uint16_t>(c.S + c.A));
        return error::OK;
    case rt::ABS12: {
        const std::uint32_t w = ld32(p);
        st32(p, (w & ~0xfffu) | ((c.S + c.A) & 0xfffu));
        return error::OK;
    }
    case rt::THM_ABS5: {
        const std::uint32_t h = ld16(p);
        st16(p, static_cast<std::uint16_t>((h & ~0x07c0u) | (((c.S + c.A) & 0x1fu) << 6)));
        return error::OK;
    }
    case rt::ABS8:
        *reinterpret_cast<std::uint8_t*>(p) = static_cast<std::uint8_t>(c.S + c.A);
        return error::OK;

    case rt::CALL:
    case rt::PLT32: {
        const bool blx = (c.S & 1u) != 0;
        const std::uint32_t target = blx ? (c.S & ~1u) : c.S;
        return arm_write_bl(p, static_cast<std::int32_t>(target + c.A - c.P), blx);
    }
    case rt::JUMP24:
    case rt::PC24:
        if (c.S & 1u) return error::RELOC_INTERWORK;
        return arm_write_b(p, static_cast<std::int32_t>(c.S + c.A - c.P));

    case rt::MOVW_ABS_NC:
        arm_set_movw_imm16(p, c.S + c.A);
        return error::OK;
    case rt::MOVT_ABS:
        arm_set_movw_imm16(p, (c.S + c.A) >> 16);
        return error::OK;
    case rt::MOVW_PREL_NC:
        arm_set_movw_imm16(p, c.S + c.A - c.P);
        return error::OK;
    case rt::MOVT_PREL:
        arm_set_movw_imm16(p, (c.S + c.A - c.P) >> 16);
        return error::OK;

    case rt::THM_CALL: {
        const bool blx = (c.S & 1u) == 0;   // ARM target -> BLX
        if (blx && (c.S & 3u) != 0) return error::RELOC_INTERWORK;
        return thumb_write_branch(p, static_cast<std::int32_t>((c.S & ~1u) + c.A - c.P),
                                  blx ? 1u : 0u);
    }
    case rt::THM_JUMP24:
        if (c.S & 1u) return error::RELOC_INTERWORK;
        return thumb_write_branch(p, static_cast<std::int32_t>(c.S + c.A - c.P), 2u);

    case rt::THM_MOVW_ABS_NC:
        thumb_set_movw_imm16(p, c.S + c.A);
        return error::OK;
    case rt::THM_MOVT_ABS:
        thumb_set_movw_imm16(p, (c.S + c.A) >> 16);
        return error::OK;
    case rt::THM_MOVW_PREL_NC:
        thumb_set_movw_imm16(p, c.S + c.A - c.P);
        return error::OK;
    case rt::THM_MOVT_PREL:
        thumb_set_movw_imm16(p, (c.S + c.A - c.P) >> 16);
        return error::OK;

    case rt::GLOB_DAT:
    case rt::JUMP_SLOT:
        st32(p, c.S);
        return error::OK;

    default:
        return error::UNSUPPORTED_RELOC;
    }
}

/// @brief True for a relocation that writes an ARM A32 branch instruction.
inline bool is_arm_branch(std::uint8_t type) noexcept {
    switch (static_cast<elf::rel_type>(type)) {
    case elf::rel_type::CALL:
    case elf::rel_type::PLT32:
    case elf::rel_type::JUMP24:
    case elf::rel_type::PC24:
        return true;
    default:
        return false;
    }
}

/// @brief True for a relocation that writes a Thumb-2 branch instruction.
inline bool is_thumb_branch(std::uint8_t type) noexcept {
    switch (static_cast<elf::rel_type>(type)) {
    case elf::rel_type::THM_CALL:
    case elf::rel_type::THM_JUMP24:
        return true;
    default:
        return false;
    }
}

} // namespace loader::arm

#endif // LOADER_ARM_RELOC_HPP
