/**
 * @file arm-attributes.hpp
 * @brief Minimal reader for the `.ARM.attributes` build attributes.
 *
 * ET_REL objects do **not** carry the float ABI in `e_flags`: GCC writes
 * `0x05000000` (EABI5, no float bits) and puts the real information in the
 * `aeabi` vendor subsection.  This header reads the file-level attributes
 * needed by a loader:
 *
 *   Tag_CPU_arch_profile  (7)  'A', 'R', 'M' or 'S'
 *   Tag_ARM_ISA_use       (8)  1 = ARM instructions may be used
 *   Tag_THUMB_ISA_use     (9)  1 = Thumb-1, 2 = Thumb-2
 *   Tag_ABI_VFP_args      (28) 0 = base, 1 = VFP registers, 2/3 = toolchain
 *
 * The parser is deliberately small and bounded: unknown tags are skipped
 * according to their value kind (ULEB128 or NUL-terminated string), and any
 * malformed length ends the walk without throwing.
 */
#ifndef LOADER_ARM_ATTRIBUTES_HPP
#define LOADER_ARM_ATTRIBUTES_HPP

#include "loader/elf-image.hpp"
#include "loader/elf-types.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace loader {

struct arm_attributes {
    bool         valid = false;  ///< `.ARM.attributes` present and readable.
    bool         has_vfp_args = false;
    std::uint8_t vfp_args = 0;   ///< 0 base, 1 VFP, 2 toolchain, 3 compatible.
    char         cpu_profile = 0;///< 'A', 'R', 'M', 'S' or 0.
    bool         arm_isa = false;
    bool         thumb_isa = false;
};

namespace detail {

inline std::uint32_t attr_u32(const std::byte* p) noexcept {
    std::uint32_t v = 0;
    std::memcpy(&v, p, sizeof v);
    return v;
}

inline std::uint64_t attr_uleb(const std::byte* p, std::size_t end, std::size_t& pos) noexcept {
    std::uint64_t v = 0;
    unsigned shift = 0;
    while (pos < end && shift < 64) {
        const std::uint8_t b = std::to_integer<std::uint8_t>(p[pos++]);
        v |= std::uint64_t(b & 0x7fu) << shift;
        if ((b & 0x80u) == 0) break;
        shift += 7;
    }
    return v;
}

inline std::size_t attr_ntbs_end(const std::byte* p, std::size_t pos, std::size_t end) noexcept {
    while (pos < end && p[pos] != std::byte{0}) ++pos;
    return pos < end ? pos + 1 : end;
}

} // namespace detail

/**
 * @brief Read the `.ARM.attributes` section of @p img.
 *
 * A missing section is not an error: `valid` stays false.  A malformed section
 * is also reported as `valid == false`; the caller decides whether to require
 * attributes (ET_REL on a hard-float firmware should).
 */
[[nodiscard]] inline arm_attributes read_arm_attributes(const elf_image& img) noexcept {
    arm_attributes out{};
    auto sec = img.find_section(".ARM.attributes");
    if (!sec || sec->sh_size < 5 || sec->sh_type != elf::SHT_ARM_ATTRIBUTES)
        return out;

    std::byte buf[1024];
    const std::size_t want = sec->sh_size < sizeof buf ? sec->sh_size : sizeof buf;
    if (auto r = img.source().read_at(sec->sh_offset, std::span<std::byte>(buf, want)); !r)
        return out;
    if (buf[0] != std::byte{'A'}) return out;

    const std::size_t end = want;
    std::size_t pos = 1;
    while (pos + 4 <= end) {
        const std::size_t start = pos;
        const std::uint32_t len = detail::attr_u32(buf + pos);
        if (len < 5 || start + len > end) break;
        const std::size_t vend = start + 4;
        const std::size_t vend_end = detail::attr_ntbs_end(buf, vend, start + len);
        const bool aeabi = (vend_end - vend) == 6 &&
                           std::memcmp(buf + vend, "aeabi", 5) == 0;
        if (aeabi) {
            std::size_t sub = vend_end;
            while (sub + 5 <= start + len) {
                const std::uint8_t tag = std::to_integer<std::uint8_t>(buf[sub]);
                const std::uint32_t slen = detail::attr_u32(buf + sub + 1);
                if (slen < 5 || sub + slen > start + len) break;
                const std::size_t body = sub + 5;
                const std::size_t body_end = sub + slen;
                if (tag == 1) {   // Tag_File
                    std::size_t a = body;
                    while (a < body_end) {
                        const std::uint64_t t = detail::attr_uleb(buf, body_end, a);
                        if (t == 0) break;   // Tag_NULL
                        if (t == 4) {        // Tag_compatibility: flag + NTBS
                            (void)detail::attr_uleb(buf, body_end, a);
                            a = detail::attr_ntbs_end(buf, a, body_end);
                        } else if (t == 5 || t == 65) { // CPU name / also-compatible
                            a = detail::attr_ntbs_end(buf, a, body_end);
                        } else {
                            const std::uint64_t v = detail::attr_uleb(buf, body_end, a);
                            switch (t) {
                            case 7:  out.cpu_profile = static_cast<char>(v); break;
                            case 8:  out.arm_isa = v != 0; break;
                            case 9:  out.thumb_isa = v != 0; break;
                            case 28: out.has_vfp_args = true;
                                     out.vfp_args = static_cast<std::uint8_t>(v); break;
                            default: break;
                            }
                        }
                    }
                }
                sub += slen;
            }
        }
        pos = start + len;
    }
    out.valid = true;
    return out;
}

} // namespace loader

#endif // LOADER_ARM_ATTRIBUTES_HPP
