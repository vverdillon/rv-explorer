import { batchTests, assertEq } from './test.js';
import { Instruction } from '../core/Instruction.js';

/*
 * RV32I
 */
// LUI
function enc_rv32i_lui_lui() {
    let inst = new Instruction('lui x17, 116088');
    let abiInst = new Instruction('lui a7, 0x1c578');
    assertEq(inst.hex, '1c5788b7');
    assertEq(abiInst.hex, inst.hex);
}

// AUIPC
function enc_rv32i_auipc_auipc() {
    let inst = new Instruction('auipc x3, -330097');
    let abiInst = new Instruction('auipc gp, 0xaf68f');
    assertEq(inst.bin, '10101111011010001111000110010111');
    assertEq(abiInst.bin, inst.bin);
}

// JAL
function enc_rv32i_jal_jal() {
    let inst = new Instruction('jal x5, 132');
    let abiInst = new Instruction('jal t0, 132');
    assertEq(inst.bin, '00001000010000000000001011101111');
    assertEq(abiInst.bin, inst.bin);
}

// JALR
function enc_rv32i_jalr_jalr() {
    let inst = new Instruction('jalr x16, 24(x5)');
    let abiInst = new Instruction('jalr a6, 24(t0)');
    assertEq(inst.bin, '00000001100000101000100001100111');
    assertEq(abiInst.bin, inst.bin);
}

// BRANCH
function enc_rv32i_branch_bne() {
    let inst = new Instruction('bne x19, x11, -3308');
    let abiInst = new Instruction('bne s3, a1, 0xf314');
    assertEq(inst.bin, '10110000101110011001101001100011');
    assertEq(abiInst.bin, inst.bin);
}

// LOAD
function enc_rv32i_load_lw() {
    let inst = new Instruction('lw x10, 12(x8)');
    let abiInst = new Instruction('lw a0, 12(fp)');
    assertEq(inst.bin, '00000000110001000010010100000011');
    assertEq(abiInst.bin, inst.bin);
}

// STORE
function enc_rv32i_store_sb() {
    let inst = new Instruction('sb x14, 8(x2)');
    let abiInst = new Instruction('sb a4, 8(sp)');
    assertEq(inst.bin, '00000000111000010000010000100011');
    assertEq(abiInst.bin, inst.bin);
}

// OP-IMM
function enc_rv23i_opimm_addi() {
    let inst = new Instruction('addi x15, x1, -50');
    let abiInst = new Instruction('addi a5, ra, -50');
    assertEq(inst.hex, 'fce08793');
    assertEq(abiInst.hex, inst.hex);
}

function enc_rv32i_opimm_srai () {
    let inst = new Instruction('srai x7, x1, 21');
    let abiInst = new Instruction('srai t2, ra, 21');
    assertEq(inst.bin, '01000001010100001101001110010011');
    assertEq(abiInst.bin, inst.bin);
}

// OP
function enc_rv32i_op_add() {
    let inst = new Instruction('add x5, x6, x7');
    let abiInst = new Instruction('add t0, t1, t2');
    assertEq(inst.bin, '00000000011100110000001010110011');
    assertEq(abiInst.bin, inst.bin);
}

// MISC-MEM
function enc_rv32i_miscmem_fence() {
    let inst = new Instruction('fence iorw, rw');
    assertEq(inst.hex, '0f30000f');
}

// SYSTEM
function enc_rv32i_system_ecall() {
    let inst = new Instruction('ecall');
    assertEq(inst.hex, '00000073');
}

/*
 * RV64I
 */
// OP-32
function enc_rv64i_op32_addw() {
    let inst = new Instruction('addw x5, x6, x7');
    let abiInst = new Instruction('addw t0, t1, t2');
    assertEq(inst.bin, '00000000011100110000001010111011');
    assertEq(abiInst.bin, inst.bin);
}

// OP-IMM
function enc_rv64i_opimm_srai_shamt43() {
    let inst = new Instruction('srai x7, x1, 43');
    assertEq(inst.bin, '01000010101100001101001110010011');
    assertEq(inst.isa, 'RV64I');
}

// OP-IMM-32
function enc_rv64i_opimm32_addiw() {
    let inst = new Instruction('addiw x15, x1, -50');
    let abiInst = new Instruction('addiw a5, ra, -50');
    assertEq(inst.hex, 'fce0879b');
    assertEq(abiInst.hex, inst.hex);
}

function enc_rv64i_opimm32_slliw() {
    let inst = new Instruction('slliw x4, x8, 21');
    assertEq(inst.hex, '0154121b');
    assertEq(inst.isa, 'RV64I');
}

/*
 * RV128I
 */
// MISC-MEM
function enc_rv128i_miscmem_lq() {
    let inst = new Instruction('lq x10, 12(x8)');
    let abiInst = new Instruction('lq a0, 12(fp)');
    assertEq(inst.bin, '00000000110001000010010100001111');
    assertEq(abiInst.bin, inst.bin);
}

// OP-64
function enc_rv128i_op64_subd() {
    let inst = new Instruction('subd x5, x6, x7');
    let abiInst = new Instruction('subd t0, t1, t2');
    assertEq(inst.bin, '01000000011100110000001011111011');
    assertEq(abiInst.bin, inst.bin);
}

// OP-IMM
function enc_rv128i_opimm_srli_shamt101() {
    let inst = new Instruction('srli x7, x1, 101');
    assertEq(inst.bin, '00000110010100001101001110010011');
    assertEq(inst.isa, 'RV128I');
}

// OP-IMM-64
function enc_rv128i_opimm64_addid() {
    let inst = new Instruction('addid x15, x1, -50');
    let abiInst = new Instruction('addid a5, ra, -50');
    assertEq(inst.hex, 'fce087db');
    assertEq(abiInst.hex, inst.hex);
}

function enc_rv128i_opimm64_sraid() {
    let inst = new Instruction('sraid x4, x8, 21');
    assertEq(inst.hex, '4154525b');
    assertEq(inst.isa, 'RV128I');
}

/*
 * Zifencei
 */
function enc_zifencei_miscmem_fencei() {
    let inst = new Instruction('fence.i');
    assertEq(inst.hex, '0000100f');
}

/*
 * Zicsr
 */
function enc_zicsr_system_csrrw() {
    let inst = new Instruction('csrrw x6, cycleh, x8');
    let abiInst = new Instruction('csrrw t1, cycleh, fp');
    assertEq(inst.bin, '11001000000001000001001101110011');
    assertEq(abiInst.bin, inst.bin);
}

function enc_zicsr_system_csrrci() {
    let inst = new Instruction('csrrci x15, pmpcfg13, 0b10101');
    let abiInst = new Instruction('csrrci a5, pmpcfg13, 0x15');
    assertEq(inst.bin, '00111010110110101111011111110011');
    assertEq(abiInst.bin, inst.bin);
}

/*
 * M extension
 */
// OP
function enc_rv32m_op_mulhsu() {
    let inst = new Instruction('mulhsu x9, x23, x8');
    let abiInst = new Instruction('mulhsu s1, s7, fp');
    assertEq(inst.bin, '00000010100010111010010010110011');
    assertEq(abiInst.bin, inst.bin);
}

// OP-32
function enc_rv64m_op32_remw() {
    let inst = new Instruction('remw x15, x7, x30');
    let abiInst = new Instruction('remw a5, t2, t5');
    assertEq(inst.bin, '00000011111000111110011110111011');
    assertEq(abiInst.bin, inst.bin);
}

// OP-64
function enc_rv128m_op64_divud() {
    let inst = new Instruction('remd x7, x19, x1');
    let abiInst = new Instruction('remd t2, s3, ra');
    assertEq(inst.bin, '00000010000110011110001111111011');
    assertEq(abiInst.bin, inst.bin);
}

/*
 * A extension
 */
function enc_rv32a_amo_lrw() {
    let inst = new Instruction('lr.w x6, (x10)');
    let abiInst = new Instruction('lr.w t1, (a0)');
    assertEq(inst.bin, '00010000000001010010001100101111');
    assertEq(abiInst.bin, inst.bin);
}

function enc_rv64a_amo_amoswapd() {
    let inst = new Instruction('amoswap.d x31, x30, (x12)');
    let abiInst = new Instruction('amoswap.d t6, t5, (a2)');
    assertEq(inst.bin, '00001001111001100011111110101111');
    assertEq(abiInst.bin, inst.bin);
}

function enc_rv128a_amo_amoorq() {
    let inst = new Instruction('amoor.q x29, x28, (x10)');
    let abiInst = new Instruction('amoor.q t4, t3, (a0)');
    assertEq(inst.bin, '01000001110001010100111010101111');
    assertEq(abiInst.bin, inst.bin);
}

/*
 * F extension
 */
function enc_rv32f_loadfp_flw() {
    let inst = new Instruction('flw f7, 100(x8)');
    let instAbi = new Instruction('flw ft7, 100(s0)');
    assertEq(inst.bin, '00000110010001000010001110000111');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv32f_storefp_fsw() {
    let inst = new Instruction('fsw f14, 100(x9)');
    let instAbi = new Instruction('fsw fa4, 100(s1)');
    assertEq(inst.bin, '00000110111001001010001000100111');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv32f_madd_fmadds() {
    let inst = new Instruction('fmadd.s f3, f7, f15, f31');
    assertEq(inst.bin, '11111000111100111111000111000011');
}

function enc_rv32f_nmsub_fnmsubs() {
    let inst = new Instruction('fnmsub.s f2, f4, f8, f16, rup');
    assertEq(inst.bin, '10000000100000100011000101001011');
}

function enc_rv32f_opfp_fadds() {
    let inst = new Instruction('fadd.s f5, f9, f17, dyn');
    assertEq(inst.bin, '00000001000101001111001011010011');
}

function enc_rv32f_opfp_fsgnjxs() {
    let inst = new Instruction('fsgnjx.s f6, f12, f24');
    assertEq(inst.bin, '00100001100001100010001101010011');
}

function enc_rv32f_opfp_flts() {
    let inst = new Instruction('flt.s x6, f4, f5');
    let instAbi = new Instruction('flt.s t1, ft4, ft5');
    assertEq(inst.bin, '10100000010100100001001101010011');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv32f_opfp_fmvwx() {
    let inst = new Instruction('fmv.w.x f11, x10');
    let instAbi = new Instruction('fmv.w.x fa1, a0');
    assertEq(inst.bin, '11110000000001010000010111010011');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv64f_opfp_fcvtlus() {
    let inst = new Instruction('fcvt.lu.s x14, f1, rmm');
    let instAbi = new Instruction('fcvt.lu.s a4, ft1, rmm');
    assertEq(inst.bin, '11000000001100001100011101010011');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv128f_opfp_fcvtst() {
    let inst = new Instruction('fcvt.s.t f2, x15');
    let instAbi = new Instruction('fcvt.s.t ft2, a5');
    assertEq(inst.bin, '11010000010001111111000101010011');
    assertEq(instAbi.bin, inst.bin);
}

/*
 * D extension
 */
function enc_rv32d_loadfp_fld() {
    let inst = new Instruction('fld f5, 101(x9)');
    let instAbi = new Instruction('fld f5, 101(s1)');
    assertEq(inst.bin, '00000110010101001011001010000111');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv32d_storefp_fsd() {
    let inst = new Instruction('fsd f13, 99(x8)');
    let instAbi = new Instruction('fsd fa3, 99(s0)');
    assertEq(inst.bin, '00000110110101000011000110100111');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv32d_msub_fmsubd() {
    let inst = new Instruction('fmsub.d f2, f6, f14, f30');
    assertEq(inst.bin, '11110010111000110111000101000111');
}

function enc_rv32d_opfp_fsubd() {
    let inst = new Instruction('fsub.d f4, f8, f16, rtz');
    assertEq(inst.bin, '00001011000001000001001001010011');
}

function enc_rv32d_opfp_fsgnjnd() {
    let inst = new Instruction('fsgnjn.d f7, f13, f25');
    assertEq(inst.bin, '00100011100101101001001111010011');
}

function enc_rv32d_opfp_feqd() {
    let inst = new Instruction('feq.d x7, f5, f4');
    let instAbi = new Instruction('feq.d t2, ft5, ft4');
    assertEq(inst.bin, '10100010010000101010001111010011');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv32d_opfp_fcvtdw() {
    let inst = new Instruction('fcvt.d.w f3, x20');
    let instAbi = new Instruction('fcvt.d.w ft3, s4');
    assertEq(inst.bin, '11010010000010100111000111010011');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv64d_opfp_fmvxd() {
    let inst = new Instruction('fmv.x.d x12, f9');
    let instAbi = new Instruction('fmv.x.d a2, f9');
    assertEq(inst.bin, '11100010000001001000011001010011');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv128d_opfp_fcvttud() {
    let inst = new Instruction('fcvt.tu.d x10, f8, RDN');
    let instAbi = new Instruction('fcvt.tu.d a0, fs0, RDN');
    assertEq(inst.bin, '11000010010101000010010101010011');
    assertEq(instAbi.bin, inst.bin);
}

/*
 * Q extension
 */
function enc_rv32q_loadfp_flq() {
    let inst = new Instruction('flq f4, 103(x10)');
    let instAbi = new Instruction('flq f4, 103(a0)');
    assertEq(inst.bin, '00000110011101010100001000000111');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv32q_storefp_fsq() {
    let inst = new Instruction('fsq f12, 96(x7)');
    let instAbi = new Instruction('fsq f12, 96(t2)');
    assertEq(inst.bin, '00000110110000111100000000100111');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv32q_nmadd_fnmaddq() {
    let inst = new Instruction('fnmadd.q f1, f5, f13, f29, rmm');
    assertEq(inst.bin, '11101110110100101100000011001111');
}

function enc_rv32q_opfp_fsqrtq() {
    let inst = new Instruction('fsqrt.q f11, f21');
    assertEq(inst.bin, '01011110000010101111010111010011');
}

function enc_rv32q_opfp_fmaxq() {
    let inst = new Instruction('fmax.q f15, f28, f30');
    assertEq(inst.bin, '00101111111011100001011111010011');
}

function enc_rv32q_opfp_fclassq() {
    let inst = new Instruction('fclass.q x19, f0');
    let instAbi = new Instruction('fclass.q s3, f0');
    assertEq(inst.bin, '11100110000000000001100111010011');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv32q_opfp_fcvtqd() {
    let inst = new Instruction('fcvt.q.d f7, f8, rne');
    assertEq(inst.bin, '01000110000101000000001111010011');
}

function enc_rv32q_opfp_fcvtsq() {
    let inst = new Instruction('fcvt.s.q f6, f9, dyn');
    assertEq(inst.bin, '01000000001101001111001101010011');
}

function enc_rv128q_opfp_fmvxq() {
    let inst = new Instruction('fmv.x.q x9, f19');
    let instAbi = new Instruction('fmv.x.q s1, fs3');
    assertEq(inst.bin, '11100110000010011000010011010011');
    assertEq(instAbi.bin, inst.bin);
}

/*
 * C0 quadrant
 */
function enc_rv32c_c0ciw_caddi4spn() {
    let inst = new Instruction('c.addi4spn x10, 420');
    let instAbi = new Instruction('c.addi4spn a0, 420');
    assertEq(inst.bin, '0001001101001000');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv32fc_c0cl_cflw() {
    let inst = new Instruction('c.flw f8, 88(x11)');
    let instAbi = new Instruction('c.flw fs0, 88(a1)');
    assertEq(inst.bin, '0110110110100000');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv128c_c0cl_clq() {
    let inst = new Instruction('c.lq x12, 400(x13)');
    let instAbi = new Instruction('c.lq a2, 400(a3)');
    assertEq(inst.bin, '0010111011010000');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv32dc_c0cs_cfsd() {
    let inst = new Instruction('c.fsd f15, 72(x13)');
    let instAbi = new Instruction('c.fsd fa5, 72(a3)');
    assertEq(inst.bin, '1010011010111100');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv32c_c0cs_csw() {
    let inst = new Instruction('c.sw x13, 84(x14)');
    let instAbi = new Instruction('c.sw a3, 84(a4)');
    assertEq(inst.bin, '1100101101110100');
    assertEq(instAbi.bin, inst.bin);
}

/*
 * C1 quadrant
 */
function enc_rv32c_c1ci_cnop() {
    let inst = new Instruction('c.nop');
    let instAbi = new Instruction('c.nop');
    assertEq(inst.bin, '0000000000000001');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv32c_c1ci_caddi() {
    let inst = new Instruction('c.addi x31, -7');
    let instAbi = new Instruction('c.addi t6, -7');
    assertEq(inst.bin, '0001111111100101');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv32c_c1cj_cjal() {
    let inst = new Instruction('c.jal -1420');
    assertEq(inst.bin, '0011110010010101');
}

function enc_rv64c_c1ci_caddiw() {
    let inst = new Instruction('c.addiw x20, 22');
    assertEq(inst.bin, '0010101001011001');
    assertEq(inst.isa, 'RV64C');
}

function enc_rv32c_c1ci_caddi16sp() {
    let inst = new Instruction('c.addi16sp 208');
    assertEq(inst.bin, '0110000101101001');
}

function enc_rv32c_c1ci_clui() {
    let inst = new Instruction('c.lui x1, -27');
    let instAbi = new Instruction('c.lui ra, 0b100101');
    assertEq(inst.bin, '0111000010010101');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv32c_c1cb_csrli() {
    let inst = new Instruction('c.srli x11, 27');
    let instAbi = new Instruction('c.srli a1, 27');
    assertEq(inst.bin, '1000000111101101');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv128c_c1cb_csrai64() {
    let inst = new Instruction('c.srai64 x10');
    assertEq(inst.bin, '1000010100000001');
    assertEq(inst.isa, 'RV128C');
}

function enc_rv32c_c1ca_cxor() {
    let inst = new Instruction('c.xor x15, x15');
    let instAbi = new Instruction('c.xor a5, a5');
    assertEq(inst.bin, '1000111110111101');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv64c_c1ca_csubw() {
    let inst = new Instruction('c.subw x13, x14');
    assertEq(inst.bin, '1001111010011001');
    assertEq(inst.isa, 'RV64C');
}

/*
 * C2 quadrant
 */
function enc_rv32c_c2cb_cbnez() {
    let inst = new Instruction('c.bnez x8, -152');
    let instAbi = new Instruction('c.bnez s0, -152');
    assertEq(inst.bin, '1111010000100101');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv64c_c2ci_cslli() {
    let inst = new Instruction('c.slli x7, 50');
    assertEq(inst.bin, '0001001111001010');
    assertEq(inst.isa, 'RV64C');
}

function enc_rv32fc_c2ci_cflwsp() {
    let inst = new Instruction('c.flwsp f6, 0');
    let instAbi = new Instruction('c.flwsp ft6, 0');
    assertEq(inst.bin, '0110001100000010');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv64c_c2css_csdsp() {
    let inst = new Instruction('c.sdsp x16, 88');
    let instAbi = new Instruction('c.sdsp a6, 88');
    assertEq(inst.bin, '1110110011000010');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv32c_c2cr_cjr() {
    let inst = new Instruction('c.jr x21');
    let instAbi = new Instruction('c.jr s5');
    assertEq(inst.bin, '1000101010000010');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv32c_c2cr_cmv() {
    let inst = new Instruction('c.mv x5, x6');
    let instAbi = new Instruction('c.mv t0, t1');
    assertEq(inst.bin, '1000001010011010');
    assertEq(instAbi.bin, inst.bin);
}

function enc_rv32c_c2cr_cebreak() {
    let inst = new Instruction('c.ebreak');
    assertEq(inst.bin, '1001000000000010');
}

function enc_rv32c_c2cr_cadd() {
    let inst = new Instruction('c.add x17, x18');
    let instAbi = new Instruction('c.add a7, s2');
    assertEq(inst.bin, '1001100011001010');
    assertEq(instAbi.bin, inst.bin);
}

/*
 * Zba extension
 */
function enc_zba_op_sh1add() {
    let inst = new Instruction('sh1add x5, x6, x7');
    assertEq(inst.hex, '207322b3');
    assertEq(inst.isa, 'Zba');
}

function enc_zba_op32_sh3adduw() {
    let inst = new Instruction('sh3add.uw x5, x6, x7');
    assertEq(inst.hex, '207362bb');
    assertEq(inst.isa, 'RV64Zba');
}

/*
 * Zbb extension
 */
function enc_zbb_op_orn() {
    let inst = new Instruction('orn x5, x6, x7');
    assertEq(inst.hex, '407362b3');
    assertEq(inst.isa, 'Zbb');
}

function enc_zbb_opimm_ctz() {
    let inst = new Instruction('ctz x5, x6');
    assertEq(inst.hex, '60131293');
}

/*
 * Zbc extension
 */
function enc_zbc_op_clmul() {
    let inst = new Instruction('clmul x5, x6, x7');
    assertEq(inst.hex, '0a7312b3');
    assertEq(inst.isa, 'Zbc');
}

/*
 * Zbs extension
 */
function enc_zbs_opimm_binvi() {
    let inst = new Instruction('binvi x5, x6, 15');
    assertEq(inst.hex, '68f31293');
    assertEq(inst.isa, 'Zbs');
}

/*
 * Zicond extension
 */
function enc_zicond_op_czeronez() {
    let inst = new Instruction('czero.nez x5, x6, x7');
    assertEq(inst.hex, '0e7372b3');
    assertEq(inst.isa, 'Zicond');
}

/*
 * Zawrs extension
 */
function enc_zawrs_system_wrssto() {
    let inst = new Instruction('wrs.sto');
    assertEq(inst.hex, '01d00073');
    assertEq(inst.isa, 'Zawrs');
}

/*
 * Zacas extension
 */
function enc_zacas_amo_amocasd() {
    let inst = new Instruction('amocas.d x6, x5, (x10)');
    assertEq(inst.hex, '2855332f');
    assertEq(inst.isa, 'Zacas');
}

/*
 * Zabha extension
 */
function enc_zabha_amo_amoaddh() {
    let inst = new Instruction('amoadd.h x6, x5, (x10)');
    assertEq(inst.hex, '0055132f');
    assertEq(inst.isa, 'Zabha');
}

/*
 * Zfh extension
 */
function enc_zfh_opfp_fsubh() {
    let inst = new Instruction('fsub.h f5, f6, f7');
    assertEq(inst.hex, '0c7372d3');
    assertEq(inst.isa, 'Zfh');
}

function enc_zfh_opfp_fclassh() {
    let inst = new Instruction('fclass.h x5, f6');
    let instAbi = new Instruction('fclass.h t0, ft6');
    assertEq(inst.hex, 'e40312d3');
    assertEq(instAbi.hex, inst.hex);
}

/*
 * Zfhmin extension
 */
function enc_zfhmin_storefp_fsh() {
    let inst = new Instruction('fsh f5, 8(x6)');
    assertEq(inst.hex, '00531427');
    assertEq(inst.isa, 'Zfhmin');
}

function enc_zfhmin_opfp_fmvhx() {
    let inst = new Instruction('fmv.h.x f5, x6');
    assertEq(inst.hex, 'f40302d3');
}

function enc_zfhmin_opfp_fcvtqh() {
    let inst = new Instruction('fcvt.q.h f5, f6');
    assertEq(inst.hex, '462372d3');
}

/*
 * Zbkx extension
 */
function enc_zbkx_op_xperm8() {
    let inst = new Instruction('xperm8 x5, x6, x7');
    assertEq(inst.hex, '287342b3');
    assertEq(inst.isa, 'Zbkx');
}

/*
 * Zbkb extension
 */
function enc_zbkb_op_pack() {
    let inst = new Instruction('pack x5, x6, x7');
    assertEq(inst.hex, '087342b3');
    assertEq(inst.isa, 'Zbkb');
}

function enc_zbkb_opimm_unzip() {
    let inst = new Instruction('unzip x5, x6');
    assertEq(inst.hex, '08f35293');
    assertEq(inst.isa, 'RV32Zbkb');
}

/*
 * Zknd/Zkne/Zknh extensions
 */
function enc_zknd_op_aes64ks2() {
    let inst = new Instruction('aes64ks2 x5, x6, x7');
    assertEq(inst.hex, '7e7302b3');
    assertEq(inst.isa, 'RV64Zknd');
}

function enc_zkne_op_aes32esi() {
    let inst = new Instruction('aes32esi x5, x6, x7, 1');
    assertEq(inst.hex, '627302b3');
    assertEq(inst.isa, 'RV32Zkne');
}

function enc_zknh_opimm_sha256sum0() {
    let inst = new Instruction('sha256sum0 x5, x6');
    assertEq(inst.hex, '10031293');
    assertEq(inst.isa, 'Zknh');
}

/*
 * Zksed/Zksh extensions
 */
function enc_zksed_op_sm4ks() {
    let inst = new Instruction('sm4ks x5, x6, x7, 2');
    assertEq(inst.hex, 'b47302b3');
    assertEq(inst.isa, 'Zksed');
}

function enc_zksh_opimm_sm3p1() {
    let inst = new Instruction('sm3p1 x5, x6');
    assertEq(inst.hex, '10931293');
    assertEq(inst.isa, 'Zksh');
}

/*
 * Zicbo extension
 */
function enc_zicbo_miscmem_cbozero() {
    let inst = new Instruction('cbo.zero (x10)');
    assertEq(inst.hex, '0045200f');
    assertEq(inst.isa, 'Zicbo');
}

function enc_zicbo_miscmem_cboflush() {
    let inst = new Instruction('cbo.flush (x10)');
    assertEq(inst.hex, '0025200f');
}

/*
 * Zfa extension
 */
function enc_zfa_opfp_flih() {
    let inst = new Instruction('fli.h f3, -1.0');
    assertEq(inst.hex, 'f41001d3');
    assertEq(inst.isa, 'Zfa');
}

function enc_zfa_opfp_fmaxmd() {
    let inst = new Instruction('fmaxm.d f5, f6, f7');
    assertEq(inst.hex, '2a7332d3');
}

function enc_zfa_opfp_froundnxs() {
    let inst = new Instruction('froundnx.s f5, f6');
    assertEq(inst.hex, '405372d3');
}

function enc_zfa_opfp_fmvhxd() {
    // RV32-only: splits a double across two 32-bit integer registers
    let inst = new Instruction('fmvh.x.d x5, f6');
    assertEq(inst.hex, 'e21302d3');
    assertEq(inst.isa, 'RV32Zfa');
}

/*
 * Zcb extension
 */
function enc_zcb_c0_clbu() {
    let inst = new Instruction('c.lbu x9, 3(x8)');
    let instAbi = new Instruction('c.lbu s1, 3(s0)');
    assertEq(inst.bin, '1000000001100100');
    assertEq(instAbi.bin, inst.bin);
}

function enc_zcb_c0_clh() {
    let inst = new Instruction('c.lh x10, 0(x11)');
    assertEq(inst.bin, '1000010111001000');
}

function enc_zcb_c0_csb() {
    let inst = new Instruction('c.sb x12, 1(x13)');
    assertEq(inst.bin, '1000101010110000');
}

function enc_zcb_c1_czextw() {
    let inst = new Instruction('c.zext.w x11');
    assertEq(inst.bin, '1001110111110001');
    assertEq(inst.isa, 'RV64Zcb');
}

function enc_zcb_c1_cnot() {
    let inst = new Instruction('c.not x14');
    assertEq(inst.bin, '1001111101110101');
}

function enc_zcb_c1_cmul() {
    let inst = new Instruction('c.mul x15, x8');
    assertEq(inst.bin, '1001111111000001');
}

/*
 * Zcmop extension
 */
function enc_zcmop_c1_cmop1() {
    let inst = new Instruction('c.mop.1');
    assertEq(inst.bin, '0110000010000001');
}

function enc_zcmop_c1_cmop15() {
    let inst = new Instruction('c.mop.15');
    assertEq(inst.bin, '0110011110000001');
}

/*
 * Zcmt extension
 */
function enc_zcmt_c2_cmjalt() {
    let inst = new Instruction('cm.jalt 200');
    assertEq(inst.bin, '1010001100100010');
}

batchTests('Encoder Tests', [
    ['Enc - RV32I    - LUI       - lui', enc_rv32i_lui_lui],
    ['Enc - RV32I    - AUIPC     - auipc', enc_rv32i_auipc_auipc],
    ['Enc - RV32I    - JAL       - jal', enc_rv32i_jal_jal],
    ['Enc - RV32I    - JALR      - jalr', enc_rv32i_jalr_jalr],
    ['Enc - RV32I    - BRANCH    - bne', enc_rv32i_branch_bne],
    ['Enc - RV32I    - LOAD      - lw', enc_rv32i_load_lw],
    ['Enc - RV32I    - STORE     - sb', enc_rv32i_store_sb],
    ['Enc - RV32I    - OP-IMM    - addi', enc_rv23i_opimm_addi],
    ['Enc - RV32I    - OP-IMM    - srai', enc_rv32i_opimm_srai],
    ['Enc - RV32I    - OP        - add', enc_rv32i_op_add],
    ['Enc - RV32I    - MISC-MEM  - fence', enc_rv32i_miscmem_fence],
    ['Enc - RV32I    - SYSTEM    - ecall', enc_rv32i_system_ecall],
    ['Enc - RV64I    - OP-32     - addw', enc_rv64i_op32_addw],
    ['Enc - RV64I    - OP-IMM    - srai - [shamt=43]', enc_rv64i_opimm_srai_shamt43],
    ['Enc - RV64I    - OP-IMM-32 - addiw', enc_rv64i_opimm32_addiw],
    ['Enc - RV64I    - OP-IMM-32 - slliw', enc_rv64i_opimm32_slliw],
    ['Enc - RV128I   - MISC-MEM  - lq', enc_rv128i_miscmem_lq],
    ['Enc - RV128I   - OP-64     - subd', enc_rv128i_op64_subd],
    ['Enc - RV128I   - OP-IMM    - srli - [shamt=101]', enc_rv128i_opimm_srli_shamt101],
    ['Enc - RV128I   - OP-IMM-64 - addid', enc_rv128i_opimm64_addid],
    ['Enc - RV128I   - OP-IMM-64 - sraid', enc_rv128i_opimm64_sraid],
    ['Enc - Zifencei - MISC-MEM  - fence.i', enc_zifencei_miscmem_fencei],
    ['Enc - Zicsr    - SYSTEM    - csrrw', enc_zicsr_system_csrrw],
    ['Enc - Zicsr    - SYSTEM    - csrrci', enc_zicsr_system_csrrci],
    ['Enc - RV32M    - OP        - mulhsu', enc_rv32m_op_mulhsu],
    ['Enc - RV64M    - OP-32     - remw', enc_rv64m_op32_remw],
    ['Enc - RV128M   - OP-64     - divud', enc_rv128m_op64_divud],
    ['Enc - RV32A    - AMO       - lr.w', enc_rv32a_amo_lrw],
    ['Enc - RV64A    - AMO       - amoswap.d', enc_rv64a_amo_amoswapd],
    ['Enc - RV128A   - AMO       - amoor.q', enc_rv128a_amo_amoorq],
    ['Enc - RV32F    - LOAD-FP   - flw', enc_rv32f_loadfp_flw],
    ['Enc - RV32F    - STORE-FP  - fsw', enc_rv32f_storefp_fsw],
    ['Enc - RV32F    - MADD      - fmadd.s', enc_rv32f_madd_fmadds],
    ['Enc - RV32F    - NMSUB     - fnmsub.s', enc_rv32f_nmsub_fnmsubs],
    ['Enc - RV32F    - OP-FP     - fadd.s', enc_rv32f_opfp_fadds],
    ['Enc - RV32F    - OP-FP     - fsgnjx.s', enc_rv32f_opfp_fsgnjxs],
    ['Enc - RV32F    - OP-FP     - flt.s', enc_rv32f_opfp_flts],
    ['Enc - RV32F    - OP-FP     - fmv.w.x', enc_rv32f_opfp_fmvwx],
    ['Enc - RV64F    - OP-FP     - fcvt.lu.s', enc_rv64f_opfp_fcvtlus],
    ['Enc - RV128F   - OP-FP     - fcvt.s.t', enc_rv128f_opfp_fcvtst],
    ['Enc - RV32D    - LOAD-FP   - fld', enc_rv32d_loadfp_fld],
    ['Enc - RV32D    - STORE-FP  - fsd', enc_rv32d_storefp_fsd],
    ['Enc - RV32D    - MSUB      - fmsub.d', enc_rv32d_msub_fmsubd],
    ['Enc - RV32D    - OP-FP     - fsub.d', enc_rv32d_opfp_fsubd],
    ['Enc - RV32D    - OP-FP     - fsgnjn.d', enc_rv32d_opfp_fsgnjnd],
    ['Enc - RV32D    - OP-FP     - feq.d', enc_rv32d_opfp_feqd],
    ['Enc - RV64D    - OP-FP     - fcvt.d.w', enc_rv32d_opfp_fcvtdw],
    ['Enc - RV128D   - OP-FP     - fcvt.tu.d', enc_rv128d_opfp_fcvttud],
    ['Enc - RV32D    - OP-FP     - fmv.x.d', enc_rv64d_opfp_fmvxd],
    ['Enc - RV32Q    - LOAD-FP   - flq', enc_rv32q_loadfp_flq],
    ['Enc - RV32Q    - STORE-FP  - fsq', enc_rv32q_storefp_fsq],
    ['Enc - RV32Q    - NMADD     - fnmadd.q', enc_rv32q_nmadd_fnmaddq],
    ['Enc - RV32Q    - OP-FP     - fsqrt.q', enc_rv32q_opfp_fsqrtq],
    ['Enc - RV32Q    - OP-FP     - fmax.q', enc_rv32q_opfp_fmaxq],
    ['Enc - RV32Q    - OP-FP     - fclass.q', enc_rv32q_opfp_fclassq],
    ['Enc - RV32Q    - OP-FP     - fcvt.q.d', enc_rv32q_opfp_fcvtqd],
    ['Enc - RV32Q    - OP-FP     - fcvt.s.q', enc_rv32q_opfp_fcvtsq],
    ['Enc - RV128Q   - OP-FP     - fmv.x.q', enc_rv128q_opfp_fmvxq],
    ['Enc - RV32C    - C0-CIW    - c.addi4spn', enc_rv32c_c0ciw_caddi4spn],
    ['Enc - RV32FC   - C0-CL     - c.flw', enc_rv32fc_c0cl_cflw],
    ['Enc - RV128C   - C0-CL     - c.lq', enc_rv128c_c0cl_clq],
    ['Enc - RV32DC   - C0-CS     - c.fsd', enc_rv32dc_c0cs_cfsd],
    ['Enc - RV32C    - C0-CS     - c.sw', enc_rv32c_c0cs_csw],
    ['Enc - RV32C    - C1-CI     - c.nop', enc_rv32c_c1ci_cnop],
    ['Enc - RV32C    - C1-CI     - c.addi', enc_rv32c_c1ci_caddi],
    ['Enc - RV32C    - C1-CJ     - c.jal', enc_rv32c_c1cj_cjal],
    ['Enc - RV64C    - C1-CI     - c.addiw', enc_rv64c_c1ci_caddiw],
    ['Enc - RV32C    - C1-CI     - c.addi16sp', enc_rv32c_c1ci_caddi16sp],
    ['Enc - RV32C    - C1-CI     - c.lui', enc_rv32c_c1ci_clui],
    ['Enc - RV32C    - C1-CB     - c.srli', enc_rv32c_c1cb_csrli],
    ['Enc - RV128C   - C1-CB     - c.srai64', enc_rv128c_c1cb_csrai64],
    ['Enc - RV32C    - C1-CA     - c.xor', enc_rv32c_c1ca_cxor],
    ['Enc - RV32C    - C1-CA     - c.subw', enc_rv64c_c1ca_csubw],
    ['Enc - RV32C    - C2-CB     - c.bnez', enc_rv32c_c2cb_cbnez],
    ['Enc - RV64C    - C2-CI     - c.slli', enc_rv64c_c2ci_cslli],
    ['Enc - RV32FC   - C2-CI     - c.flwsp', enc_rv32fc_c2ci_cflwsp],
    ['Enc - RV64C    - C2-CSS    - c.sdsp', enc_rv64c_c2css_csdsp],
    ['Enc - RV32C    - C2-CR     - c.jr', enc_rv32c_c2cr_cjr],
    ['Enc - RV32C    - C2-CR     - c.mv', enc_rv32c_c2cr_cmv],
    ['Enc - RV32C    - C2-CR     - c.ebreak', enc_rv32c_c2cr_cebreak],
    ['Enc - RV32C    - C2-CR     - c.add', enc_rv32c_c2cr_cadd],
    ['Enc - Zba      - OP        - sh1add', enc_zba_op_sh1add],
    ['Enc - Zba      - OP-32     - sh3add.uw', enc_zba_op32_sh3adduw],
    ['Enc - Zbb      - OP        - orn', enc_zbb_op_orn],
    ['Enc - Zbb      - OP-IMM    - ctz', enc_zbb_opimm_ctz],
    ['Enc - Zbc      - OP        - clmul', enc_zbc_op_clmul],
    ['Enc - Zbs      - OP-IMM    - binvi', enc_zbs_opimm_binvi],
    ['Enc - Zicond   - OP        - czero.nez', enc_zicond_op_czeronez],
    ['Enc - Zawrs    - SYSTEM    - wrs.sto', enc_zawrs_system_wrssto],
    ['Enc - Zacas    - AMO       - amocas.d', enc_zacas_amo_amocasd],
    ['Enc - Zabha    - AMO       - amoadd.h', enc_zabha_amo_amoaddh],
    ['Enc - Zfh      - OP-FP     - fsub.h', enc_zfh_opfp_fsubh],
    ['Enc - Zfh      - OP-FP     - fclass.h', enc_zfh_opfp_fclassh],
    ['Enc - Zfhmin   - STORE-FP  - fsh', enc_zfhmin_storefp_fsh],
    ['Enc - Zfhmin   - OP-FP     - fmv.h.x', enc_zfhmin_opfp_fmvhx],
    ['Enc - Zfhmin   - OP-FP     - fcvt.q.h', enc_zfhmin_opfp_fcvtqh],
    ['Enc - Zbkx     - OP        - xperm8', enc_zbkx_op_xperm8],
    ['Enc - Zbkb     - OP        - pack', enc_zbkb_op_pack],
    ['Enc - Zbkb     - OP-IMM    - unzip', enc_zbkb_opimm_unzip],
    ['Enc - Zknd     - OP        - aes64ks2', enc_zknd_op_aes64ks2],
    ['Enc - Zkne     - OP        - aes32esi', enc_zkne_op_aes32esi],
    ['Enc - Zknh     - OP-IMM    - sha256sum0', enc_zknh_opimm_sha256sum0],
    ['Enc - Zksed    - OP        - sm4ks', enc_zksed_op_sm4ks],
    ['Enc - Zksh     - OP-IMM    - sm3p1', enc_zksh_opimm_sm3p1],
    ['Enc - Zicbo    - MISC-MEM  - cbo.zero', enc_zicbo_miscmem_cbozero],
    ['Enc - Zicbo    - MISC-MEM  - cbo.flush', enc_zicbo_miscmem_cboflush],
    ['Enc - Zfa      - OP-FP     - fli.h', enc_zfa_opfp_flih],
    ['Enc - Zfa      - OP-FP     - fmaxm.d', enc_zfa_opfp_fmaxmd],
    ['Enc - Zfa      - OP-FP     - froundnx.s', enc_zfa_opfp_froundnxs],
    ['Enc - Zfa      - OP-FP     - fmvh.x.d', enc_zfa_opfp_fmvhxd],
    ['Enc - Zcb      - C0        - c.lbu', enc_zcb_c0_clbu],
    ['Enc - Zcb      - C0        - c.lh', enc_zcb_c0_clh],
    ['Enc - Zcb      - C0        - c.sb', enc_zcb_c0_csb],
    ['Enc - Zcb      - C1        - c.zext.w', enc_zcb_c1_czextw],
    ['Enc - Zcb      - C1        - c.not', enc_zcb_c1_cnot],
    ['Enc - Zcb      - C1        - c.mul', enc_zcb_c1_cmul],
    ['Enc - Zcmop    - C1        - c.mop.1', enc_zcmop_c1_cmop1],
    ['Enc - Zcmop    - C1        - c.mop.15', enc_zcmop_c1_cmop15],
    ['Enc - Zcmt     - C2        - cm.jalt', enc_zcmt_c2_cmjalt],
]);

// Newline
console.log('');
