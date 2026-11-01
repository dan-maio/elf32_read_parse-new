#include "loader/arm-reloc.hpp"
#include <cstdio>
#include <cstring>
#include <cstdint>
using namespace loader;
using namespace loader::arm;
static int ok=0, bad=0;
#define CHECK(x) do{ if(x)++ok; else {++bad; std::printf("FAIL %s:%d %s\n",__FILE__,__LINE__,#x);} }while(0)

int main(){
  std::byte b[16];
  auto put32=[&](uint32_t v){ std::memcpy(b,&v,4); };
  auto get32=[&](){ uint32_t v; std::memcpy(&v,b,4); return v; };
  auto put16=[&](uint32_t v){ uint16_t h=v; std::memcpy(b,&h,2); };
  auto get16=[&](){ uint16_t v; std::memcpy(&v,b,2); return v; };

  // ARM BL
  put32(0xEB000000);
  CHECK(apply((uint8_t)elf::rel_type::CALL,b,{0x1000,0,0x100,isa::arm})==error::OK);
  CHECK((get32() & 0x00ffffffu)<<2 == 0xF00u);
  CHECK((get32() & 0xff000000u)==0xEB000000u);

  // ARM BLX to Thumb
  put32(0xFA000000);
  CHECK(apply((uint8_t)elf::rel_type::CALL,b,{0x1001,0,0x100,isa::arm})==error::OK);
  CHECK((get32() & 0xff000000u)==0xFA000000u);
  CHECK((get32() & 0x00ffffffu)<<2 == 0xF00u);

  // ARM BLX with H bit
  put32(0xFA000000);
  CHECK(apply((uint8_t)elf::rel_type::CALL,b,{0x1003,0,0x100,isa::arm})==error::OK);
  CHECK((get32() & 0x01000000u)!=0); // H
  CHECK(((get32() & 0x00ffffffu)<<2) == 0xF00u);

  // JUMP24 interworking
  put32(0xEA000000);
  CHECK(apply((uint8_t)elf::rel_type::JUMP24,b,{0x1001,0,0x100,isa::arm})==error::RELOC_INTERWORK);

  // MOVW/MOVT
  put32(0xE3000000);
  CHECK(apply((uint8_t)elf::rel_type::MOVW_ABS_NC,b,{0x12345678,0,0,isa::arm})==error::OK);
  CHECK(arm_movw_imm16(b)==0x5678);
  put32(0xE3400000);
  CHECK(apply((uint8_t)elf::rel_type::MOVT_ABS,b,{0x12345678,0,0,isa::arm})==error::OK);
  CHECK(arm_movw_imm16(b)==0x1234);

  // Thumb BL
  put16(0xF000); put16(0xD000);
  CHECK(apply((uint8_t)elf::rel_type::THM_CALL,b,{0x1001,0,0x100,isa::thumb})==error::OK);
  CHECK(thumb_branch_addend(b)==0xF00u);

  // Thumb BLX (ARM target)
  put16(0xF000); put16(0xC000);
  CHECK(apply((uint8_t)elf::rel_type::THM_CALL,b,{0x1000,0,0x100,isa::thumb})==error::OK);
  CHECK((get16() & 0xF800u)==0xF000u);
  { uint16_t h2; std::memcpy(&h2,(std::byte*)b+2,2); CHECK((h2 & 0xD000u)==0xC000u); }
  CHECK(thumb_branch_addend(b)==0xF00u);

  // Thumb MOVW/MOVT
  put16(0xF240); put16(0x0000);
  CHECK(apply((uint8_t)elf::rel_type::THM_MOVW_ABS_NC,b,{0x1234,0,0,isa::thumb})==error::OK);
  CHECK(thumb_movw_imm16(b)==0x1234);
  put16(0xF2C0); put16(0x0000);
  CHECK(apply((uint8_t)elf::rel_type::THM_MOVT_ABS,b,{0x12345678,0,0,isa::thumb})==error::OK);
  CHECK(thumb_movw_imm16(b)==0x1234);

  // PREL31
  put32(0x80000000u);
  CHECK(apply((uint8_t)elf::rel_type::PREL31,b,{0x1000,0,0x100,isa::arm})==error::OK);
  CHECK((get32() & 0x80000000u)!=0);
  CHECK((get32() & 0x7fffffffu)==0xF00u);

  // ABS32/REL32
  put32(4);
  CHECK(apply((uint8_t)elf::rel_type::ABS32,b,{0x1000,4,0,isa::arm})==error::OK);
  CHECK(get32()==0x1004u);
  put32(4);
  CHECK(apply((uint8_t)elf::rel_type::REL32,b,{0x1000,4,0x100,isa::arm})==error::OK);
  CHECK(get32()==0xF04u);

  // decode addend for BL
  put32(0xEB0003C0); // imm24=0x3C0 -> addend 0xF00
  uint32_t a=0;
  CHECK(decode_addend((uint8_t)elf::rel_type::CALL,b,a));
  CHECK(a==0xF00u);

  std::printf("arm-reloc: %d passed, %d failed\n",ok,bad);
  return bad?1:0;
}
