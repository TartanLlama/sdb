#ifndef DEFINE_REGISTER
#error "This file is intended for textual inclusion with the\
DEFINE_REGISTER macro defined"
#endif

#define GPR_OFFSET(reg) (offsetof(user, regs) + offsetof(user_regs_struct, reg))
#define DEFINE_GPR_64(name,dwarf_id) \
    DEFINE_REGISTER(name, dwarf_id, 8, GPR_OFFSET(name),\
     register_type::gpr, register_format::uint)
#define DEFINE_GPR_32(name,super) \
    DEFINE_REGISTER(name, -1, 4, GPR_OFFSET(super),\
     register_type::sub_gpr, register_format::uint)
     
#define DEFINE_GPR_16(name,super) \
    DEFINE_REGISTER(name, -1, 2, GPR_OFFSET(super),\
     register_type::sub_gpr, register_format::uint)
     
#define DEFINE_GPR_8H(name,super) \
 DEFINE_REGISTER(name, -1, 1, GPR_OFFSET(super) + 1,\
     register_type::sub_gpr, register_format::uint)
     
#define DEFINE_GPR_8L(name,super) \
    DEFINE_REGISTER(name, -1, 1, GPR_OFFSET(super),\
     register_type::sub_gpr, register_format::uint)

DEFINE_GPR_64(rax, 0),
DEFINE_GPR_64(rdx, 1),
DEFINE_GPR_64(rcx, 2),
DEFINE_GPR_64(rbx, 3),
DEFINE_GPR_64(rsi, 4),
DEFINE_GPR_64(rdi, 5),
DEFINE_GPR_64(rbp, 6),
DEFINE_GPR_64(rsp, 7),
DEFINE_GPR_64(r8, 8),
DEFINE_GPR_64(r9, 9),
DEFINE_GPR_64(r10, 10),
DEFINE_GPR_64(r11, 11),
DEFINE_GPR_64(r12, 12),
DEFINE_GPR_64(r13, 13),
DEFINE_GPR_64(r14, 14),
DEFINE_GPR_64(r15, 15),
DEFINE_GPR_64(rip, 16),
DEFINE_GPR_64(eflags, 49),
DEFINE_GPR_64(cs, 51),
DEFINE_GPR_64(fs, 54),
DEFINE_GPR_64(gs, 55),
DEFINE_GPR_64(ss, 52),
DEFINE_GPR_64(ds, 53),
DEFINE_GPR_64(es, 50),
DEFINE_GPR_64(orig_rax, -1),

DEFINE_GPR_32(eax, rax), DEFINE_GPR_32(edx, rdx),
DEFINE_GPR_32(ecx, rcx), DEFINE_GPR_32(ebx, rbx),
DEFINE_GPR_32(esi, rsi), DEFINE_GPR_32(edi, rdi),
DEFINE_GPR_32(ebp, rbp), DEFINE_GPR_32(esp, rsp),
DEFINE_GPR_32(r8d, r8), DEFINE_GPR_32(r9d, r9),
DEFINE_GPR_32(r10d, r10), DEFINE_GPR_32(r11d, r11),
DEFINE_GPR_32(r12d, r12), DEFINE_GPR_32(r13d, r13),
DEFINE_GPR_32(r14d, r14), DEFINE_GPR_32(r15d, r15),

DEFINE_GPR_16(ax, rax), DEFINE_GPR_16(dx, rdx),
DEFINE_GPR_16(cx, rcx), DEFINE_GPR_16(bx, rbx),
DEFINE_GPR_16(si, rsi), DEFINE_GPR_16(di, rdi),
DEFINE_GPR_16(bp, rbp), DEFINE_GPR_16(sp, rsp),
DEFINE_GPR_16(r8w, r8), DEFINE_GPR_16(r9w, r9),
DEFINE_GPR_16(r10w, r10), DEFINE_GPR_16(r11w, r11),
DEFINE_GPR_16(r12w, r12), DEFINE_GPR_16(r13w, r13),
DEFINE_GPR_16(r14w, r14), DEFINE_GPR_16(r15w, r15),

DEFINE_GPR_8H(ah, rax), DEFINE_GPR_8H(dh, rdx),
DEFINE_GPR_8H(ch, rcx), DEFINE_GPR_8H(bh, rbx),

DEFINE_GPR_8L(al, rax), DEFINE_GPR_8L(dl, rdx),
DEFINE_GPR_8L(cl, rcx), DEFINE_GPR_8L(bl, rbx),
DEFINE_GPR_8L(sil, rsi), DEFINE_GPR_8L(dil, rsi),
DEFINE_GPR_8L(bpl, rbp), DEFINE_GPR_8L(spl, rsp),
DEFINE_GPR_8L(r8b, r8), DEFINE_GPR_8L(r9b, r9),
DEFINE_GPR_8L(r10b, r10), DEFINE_GPR_8L(r11b, r11),
DEFINE_GPR_8L(r12b, r12), DEFINE_GPR_8L(r13b, r13),
DEFINE_GPR_8L(r14b, r14), DEFINE_GPR_8L(r15b, r15),

#define FPR_OFFSET(reg) (offsetof(user, i387) + offsetof(user_fpregs_struct, reg))
#define FPR_SIZE(reg) (sizeof(user_fpregs_struct::reg))

#define DEFINE_FPR(name,dwarf_id,user_name) \
    DEFINE_REGISTER(name, dwarf_id, FPR_SIZE(user_name), FPR_OFFSET(user_name),\
    register_type::fpr, register_format::uint)

#define DEFINE_FP_ST(number) \
    DEFINE_REGISTER(st ## number, (33 + number), 16,\
     (FPR_OFFSET(st_space) + number*16), register_type::fpr,\
     register_format::long_double)

#define DEFINE_FP_MM(number) \
    DEFINE_REGISTER(mm ## number, (41 + number), 8,\
     (FPR_OFFSET(st_space) + number*16), register_type::fpr,\
     register_format::vector)

#define DEFINE_FP_XMM(number) \
    DEFINE_REGISTER(xmm ## number, (17 + number), 16,\
     (FPR_OFFSET(xmm_space) + number*16), register_type::fpr,\
     register_format::vector)

DEFINE_FPR(fcw, 65, cwd),
DEFINE_FPR(fsw, 66, swd),
DEFINE_FPR(ftw, -1, ftw),
DEFINE_FPR(fop, -1, fop),
DEFINE_FPR(frip, -1, rip),
DEFINE_FPR(frdp, -1, rdp),
DEFINE_FPR(mxcsr, 64, mxcsr),
DEFINE_FPR(mxcsrmask, -1, mxcr_mask),

DEFINE_FP_ST(0), DEFINE_FP_ST(1), DEFINE_FP_ST(2), DEFINE_FP_ST(3),
DEFINE_FP_ST(4), DEFINE_FP_ST(5), DEFINE_FP_ST(6), DEFINE_FP_ST(7),

DEFINE_FP_MM(0), DEFINE_FP_MM(1), DEFINE_FP_MM(2), DEFINE_FP_MM(3),
DEFINE_FP_MM(4), DEFINE_FP_MM(5), DEFINE_FP_MM(6), DEFINE_FP_MM(7),

DEFINE_FP_XMM(0), DEFINE_FP_XMM(1), DEFINE_FP_XMM(2), DEFINE_FP_XMM(3),
DEFINE_FP_XMM(4), DEFINE_FP_XMM(5), DEFINE_FP_XMM(6), DEFINE_FP_XMM(7),
DEFINE_FP_XMM(8), DEFINE_FP_XMM(9), DEFINE_FP_XMM(10), DEFINE_FP_XMM(11),
DEFINE_FP_XMM(12), DEFINE_FP_XMM(13), DEFINE_FP_XMM(14), DEFINE_FP_XMM(15),

#define DR_OFFSET(number) (offsetof(user, u_debugreg) + number * 8)
#define DEFINE_DR(number)\
    DEFINE_REGISTER(dr ## number, -1, 8, DR_OFFSET(number),\
     register_type::dr, register_format::uint)

DEFINE_DR(0), DEFINE_DR(1), DEFINE_DR(2), DEFINE_DR(3),
DEFINE_DR(4), DEFINE_DR(5), DEFINE_DR(6), DEFINE_DR(7)