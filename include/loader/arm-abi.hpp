/**
 * @file arm-abi.hpp
 * @brief ARM ABI compatibility checks for a parsed image.
 *
 * The reader cannot know the firmware's ABI, so the caller supplies whether it
 * is hard-float (AAPCS-VFP).  `check_arm_abi()` compares that with the image:
 *
 *   - ET_DYN/ET_EXEC: `e_flags` carries `EF_ARM_ABI_FLOAT_HARD/SOFT`.
 *   - ET_REL: `e_flags` has no float bits; read `.ARM.attributes`
 *     (`Tag_ABI_VFP_args`) instead.
 *
 * A mismatch is `error::ABI_MISMATCH`.  A missing `.ARM.attributes` section in
 * an ET_REL image is tolerated: the caller may choose to require it.
 */
#ifndef LOADER_ARM_ABI_HPP
#define LOADER_ARM_ABI_HPP

#include "loader/arm-attributes.hpp"
#include "loader/elf-image.hpp"
#include "loader/elf-types.hpp"

namespace loader {

[[nodiscard]] inline result<void>
check_arm_abi(const elf_image& img, bool hard_float) noexcept {
    const elf::Ehdr& h = img.header();
    if (h.e_type == elf::ET_REL) {
        const arm_attributes a = read_arm_attributes(img);
        if (a.valid && a.has_vfp_args) {
            const bool module_hard = (a.vfp_args == 1);   // VFP registers
            if (module_hard != hard_float)
                return unexpected(error::ABI_MISMATCH);
        }
        return {};
    }

    const elf::word f = h.e_flags & (elf::EF_ARM_ABI_FLOAT_HARD |
                                     elf::EF_ARM_ABI_FLOAT_SOFT);
    if (f != 0) {
        const bool module_hard = (f & elf::EF_ARM_ABI_FLOAT_HARD) != 0;
        if (module_hard != hard_float)
            return unexpected(error::ABI_MISMATCH);
    }
    return {};
}

} // namespace loader

#endif // LOADER_ARM_ABI_HPP
