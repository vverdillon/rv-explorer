// SPDX-License-Identifier: AGPL-3.0-or-later

/*
 * RISC-V Instruction Encoder/Decoder
 *
 * Copyright (c) 2021-2022 LupLab @ UC Davis
 */

import { BASE, XLEN_MASK, FLI_STRINGS, FIELDS, OPCODE, ISA,
  REGISTER, FLOAT_REGISTER, FLOAT_ROUNDING_MODE, CSR,
  V_SEW, V_LMUL, V_EEW, V_WHOLEREG_NF, vParseSegName, V_CAT,
  P_FIELD_POS, P_REGPAIR_FIELDS
} from './Constants.js'

import { COPTS_ISA } from './Config.js'

import { convertBase } from './Instruction.js'

export class Encoder {
  /**
   * Binary representation of instruction
   * @type String
   */
  bin;

  /**
   * Value from XLEN_MASK for passing the expected xlen to the decoder
   * - Only matters for C instructions,
   *   set to `XLEN_MASK.all` for all standard 32-bit instructions
   * @type Integer
   */
  xlens;

  /* Private members */
  #config;
  #inst;
  #mne;
  #opr;
  // Vector load/store segment count (nf field), when this.#mne was a
  // segmented mnemonic (e.g. vlseg3e8.v) resolved down to its base entry
  #vNf = 0;

  /**
   * Creates an Encoder to convert an assembly instruction to binary
   * @param {String} asm
   */
  constructor(asm, config) {
    this.#config = config;

    // Tokenize assembly instruction
    const tokens = asm.toLowerCase().split(/[ ,()]+/);

    // Convert assembly instruction to binary
    this.#convertAsmToBin(tokens);
  }

  /**
   * Convert assembly instruction to binary
   * @param {String[]} tokens
   */
  #convertAsmToBin(tokens) {
    // The first token is necessarily the instruction's mnemonic
    this.#mne = tokens[0];
    // The following tokens are its operands
    this.#opr = tokens.splice(1);

    // Find instruction based on given mnemonic
    this.#inst = ISA[this.#mne];
    if (this.#inst === undefined) {
      // Vector load/store segment mnemonics (vlseg3e8.v, vluxseg2ei16.v,
      // etc.) aren't pre-registered individually - resolve the "seg<N>"
      // infix back to a base mnemonic plus its nf field value
      const parsed = vParseSegName(this.#mne);
      const base = parsed && ISA[parsed.base];
      if (base?.fmt === 'V-mem' && base.seg) {
        this.#inst = base;
        this.#vNf = parsed.nf;
      }
    }
    if (this.#inst === undefined) {
      throw "Invalid mnemonic: " + this.#mne;
    }
    // Detect C instructions
    const cInst = this.#inst.opcode.length === 2;

    // Determine compatible ISA xlens
    let isa = this.#inst.isa;
    this.xlens = 0;
    if (cInst) {
      this.xlens = this.#inst.xlens;
      // Determine lowest-allowable ISA given instruction xlens
      //   Mainly for error messaging on encoding side
      if ((this.xlens & XLEN_MASK.rv32) !== 0) {
        isa = `RV32${isa}`;
      } else if ((this.xlens & XLEN_MASK.rv64) !== 0) {
        isa = `RV64${isa}`;
      } else if ((this.xlens & XLEN_MASK.rv128) !== 0) {
        isa = `RV128${isa}`;
      }
    } else {
      const isaXlen = parseInt(/^RV(\d+)/.exec(this.#inst.isa)?.[1]);
      switch (isaXlen) {
        // Build up xlens bit-mask to include lowest compatible xlen and all higher ones
        case 32:
          this.xlens |= XLEN_MASK.rv32;
        case 64:
          this.xlens |= XLEN_MASK.rv64;
        case 128:
          this.xlens |= XLEN_MASK.rv128;
          break;
        default:
          // All ISAs that do not have an explicit xlen are inferred to support all xlens
          //   Ex. Zicsr, Zifencei
          this.xlens = XLEN_MASK.all;
      }
      // Zilsd: ld/sd are additionally valid on RV32 (register-pair form) -
      // see the even-register check and isa relabeling in Decoder.js
      if (this.#mne === 'ld' || this.#mne === 'sd') {
        this.xlens |= XLEN_MASK.rv32;
      }
    }

    // Detect mismatch between ISA and configuration
    if (this.#config.ISA !== COPTS_ISA.AUTO) {
      if (this.#config.ISA === COPTS_ISA.RV32I && (this.xlens & XLEN_MASK.rv32) === 0) {
        throw `Detected ${isa} instruction incompatible with configuration ISA: RV32I`;
      } else if (this.#config.ISA === COPTS_ISA.RV64I && (this.xlens & XLEN_MASK.rv64) === 0) {
        throw `Detected ${isa} instruction incompatible with configuration ISA: RV64I`;
      } else if (this.#config.ISA === COPTS_ISA.RV128I && (this.xlens & XLEN_MASK.rv128) === 0) {
        throw `Detected ${isa} instruction incompatible with configuration ISA: RV128I`;
      }
    }

    // Encode instruction
    if (cInst) {
      // 16-bit C instructions
      //   Encode according to instruction format
      const fmt = /^([^-]+)-/.exec(this.#inst.fmt)?.[1];
      switch (fmt) {
        case 'CR':
          this.#encodeCR();
          break;
        case 'CI':
          this.#encodeCI();
          break;
        case 'CSS':
          this.#encodeCSS();
          break;
        case 'CIW':
          this.#encodeCIW();
          break;
        case 'CL':
          this.#encodeCL();
          break;
        case 'CS':
          this.#encodeCS();
          break;
        case 'CA':
          this.#encodeCA();
          break;
        case 'CB':
          this.#encodeCB();
          break;
        case 'CJ':
          this.#encodeCJ();
          break;
        case 'CMJT':
          this.#encodeCMJT();
          break;
        case 'CMPP':
          this.#encodeCMPP();
          break;
        case 'CMMV':
          this.#encodeCMMV();
          break;
        default:
          throw `Unsupported C instruction format: ${this.#inst.fmt}`;
      }
    } else {
      // Standard 32-bit instructions
      //   Encode according to opcode
      switch (this.#inst.opcode) {
          // R-type
        case OPCODE.OP:
        case OPCODE.OP_32:
        case OPCODE.OP_64:
          this.#encodeOP();
          break;
        case OPCODE.OP_FP:
          this.#encodeOP_FP();
          break;
        case OPCODE.OP_V:
          this.#encodeOP_V();
          break;
        case OPCODE.OP_V_CRYPTO:
          this.#encodeVCrypto();
          break;
        case OPCODE.AMO:
          if (this.#inst.fmt === 'Zalasr') {
            this.#encodeZalasr();
          } else {
            this.#encodeAMO();
          }
          break;

          // I-type
        case OPCODE.JALR:
          this.#encodeJALR();
          break;
        case OPCODE.LOAD:
        case OPCODE.LOAD_FP:
          this.#encodeLOAD();
          break;
        case OPCODE.OP_IMM:
        case OPCODE.OP_IMM_64:
          this.#encodeOP_IMM();
          break;
        case OPCODE.OP_IMM_32:
          if (this.#inst.fmt === 'P-mixed') {
            this.#encodeP();
          } else {
            this.#encodeOP_IMM();
          }
          break;
        case OPCODE.MISC_MEM:
          this.#encodeMISC_MEM();
          break;
        case OPCODE.SYSTEM:
          this.#encodeSYSTEM();
          break;

          // S-type
        case OPCODE.STORE:
        case OPCODE.STORE_FP:
          this.#encodeSTORE();
          break;

          // B-type
        case OPCODE.BRANCH:
          this.#encodeBRANCH();
          break;

          // U-type
        case OPCODE.LUI:
        case OPCODE.AUIPC:
          this.#encodeUType();
          break;

          // J-type:
        case OPCODE.JAL:
          this.#encodeJAL();
          break;

          // R4-type
        case OPCODE.MADD:
        case OPCODE.MSUB:
        case OPCODE.NMADD:
        case OPCODE.NMSUB:
          this.#encodeR4();
          break;

          // Invalid opcode
        default:
          throw "Unsupported opcode: " + this.#inst.opcode;
      }
    }
  }

  /**
   * Encodes OP instruction
   */
  #encodeOP() {
    // Get operands
    const dest = this.#opr[0], src1 = this.#opr[1], src2 = this.#opr[2];

    // Convert to binary representation
    const rd = encReg(dest), rs1 = encReg(src1), rs2 = encReg(src2);

    let funct7 = this.#inst.funct7;
    if (funct7 === undefined) {
      // Zksed: 2-bit "byte select" immediate occupies the top of funct7
      const bs = this.#opr[3];
      if (bs < 0 || bs > 3) {
        throw 'Invalid bs field (out of range): "' + bs + '"';
      }
      funct7 = encImm(bs, 2) + this.#inst.funct7base;
    }

    // Construct binary instruction
    this.bin = funct7 + rs2 + rs1 + this.#inst.funct3 + rd +
      this.#inst.opcode;
  }

  /**
   * Encodes OP-FP instruction
   */
  #encodeOP_FP() {
    // Get operands
    const dest = this.#opr[0],
          src1 = this.#opr[1],
          src2 = this.#opr[2],
          frm  = this.#inst.rs2 !== undefined ? this.#opr[2] : this.#opr[3];

    // Convert to binary representation
    let floatRd = true;
    let floatRs1 = true;
    let floatRs2 = this.#inst.rs2Int !== true;
    if (this.#inst.funct5[0] === '1') {
      // Conditionally encode rd or rs1 as an int register, based on funct7
      if (this.#inst.funct5[3] === '1') {
        floatRs1 = false;
      } else {
        floatRd = false;
      }
    }
    const rd = encReg(dest, floatRd),
      rs1 = this.#inst.rs1Fli ? encFli(src1) : encReg(src1, floatRs1),
      rs2 = this.#inst.rs2 ?? encReg(src2, floatRs2),
      funct3 = this.#inst.funct3 ?? encFrm(frm) ?? '111' /* dyn rm */;

    // Construct binary instruction
    this.bin = this.#inst.funct5 + this.#inst.fp_fmt + rs2 + rs1 + funct3 + rd +
      this.#inst.opcode;
  }

  /**
   * Encodes JALR instruction
   */
  #encodeJALR() {
    // Get operands
    const dest = this.#opr[0], offset = this.#opr[1], base = this.#opr[2];

    // Convert to binary representation
    const rd = encReg(dest), rs1 = encReg(base),
      imm = encImm(offset, FIELDS.i_imm_11_0.pos[1]);

    // Construct binary instruction
    this.bin = imm + rs1 + this.#inst.funct3 + rd + this.#inst.opcode;
  }

  /**
   * Encodes LOAD instruction
   */
  #encodeLOAD() {
    if (this.#inst.fmt === 'V-mem') {
      this.#encodeVMem(true);
      return;
    }

    // Get operands
    const dest = this.#opr[0], offset = this.#opr[1], base = this.#opr[2];

    // Convert to binary representation
    const floatInst = this.#inst.opcode === OPCODE.LOAD_FP;
    const rd = encReg(dest, floatInst),
      rs1 = encReg(base),
      imm = encImm(offset, FIELDS.i_imm_11_0.pos[1]);

    // Construct binary instruction
    this.bin = imm + rs1 + this.#inst.funct3 + rd + this.#inst.opcode;
  }

  // P (unratified draft): mirrors Decoder.js's #decodeP - starts from the
  // instruction's fixed match template (already zero at every operand bit
  // position) and overwrites each operand's bit range in place
  #encodeP() {
    const inst = this.#inst;
    const bin = inst.match.split('');
    inst.operands.forEach((opType, i) => {
      const [hi, lo] = P_FIELD_POS[opType];
      let raw;
      if (opType === 'rd' || opType === 'rs1' || opType === 'rs2') {
        raw = encReg(this.#opr[i]);
      } else if (P_REGPAIR_FIELDS.has(opType)) {
        const regBits = encReg(this.#opr[i]);
        if (regBits[4] !== '0') {
          throw `Detected ${this.#mne} with register pair operand "${this.#opr[i]}" - odd registers cannot start a pair`;
        }
        raw = regBits.substring(0, 4);
      } else {
        raw = encImm(this.#opr[i], hi - lo + 1);
      }
      for (let b = 0; b < raw.length; b++) {
        bin[31 - hi + b] = raw[b];
      }
    });
    this.bin = bin.join('');
  }

  /**
   * Encodes OP_IMM instruction
   */
  #encodeOP_IMM() {
    // Get fields
    const dest = this.#opr[0], src = this.#opr[1], immediate = this.#opr[2];

    // Convert to binary representation
    const rd = encReg(dest), rs1 = encReg(src);

    let imm = ''.padStart('0', FIELDS.i_imm_11_0.pos[1]);

    if (this.#inst.funct12 !== undefined) {
      // Fully-fixed immediate instructions (clz, ctz, cpop, sext.b/h, orc.b, rev8, ...)
      //   imm[11:0] carries no user-supplied value
      imm = (this.#config.ISA === COPTS_ISA.RV32I && this.#inst.funct12Rv32 !== undefined)
        ? this.#inst.funct12Rv32
        : this.#inst.funct12;

    } else if (this.#inst.funct6 !== undefined) {
      // Bit-manipulation shift-amount instructions (Zba/Zbb/Zbs): fixed 6-bit
      //   prefix plus a 6-bit shift amount
      const maxShamt = (this.#config.ISA === COPTS_ISA.RV32I) ? 32 : 64;
      if (immediate < 0 || immediate >= maxShamt) {
        throw 'Invalid shamt field (out of range): "' + immediate + '"';
      }
      imm = this.#inst.funct6 + encImm(immediate, 6);

    } else if (this.#inst.funct7 !== undefined) {
      // Bit-manipulation word shift-amount instructions (roriw): fixed 7-bit
      //   prefix plus a 5-bit shift amount
      if (immediate < 0 || immediate >= 32) {
        throw 'Invalid shamt field (out of range): "' + immediate + '"';
      }
      imm = this.#inst.funct7 + encImm(immediate, 5);

    } else if (this.#inst.funct8 !== undefined) {
      // Round-number instructions (aes64ks1i): fixed 8-bit prefix plus a
      //   4-bit round-number immediate, valid range 0-10
      if (immediate < 0 || immediate > 10) {
        throw 'Invalid rnum field (out of range): "' + immediate + '"';
      }
      imm = this.#inst.funct8 + encImm(immediate, 4);

    // Shift instruction
    } else if (this.#inst.shtyp !== undefined) {
      // Determine shift-amount width based on opcode or config ISA
      //   For encoding, default to the widest shamt possible with the given parameters
      let shamtWidth;
      if (this.#config.isa === COPTS_ISA.RV32I || this.#inst.opcode === OPCODE.OP_IMM_32) {
        shamtWidth = FIELDS.i_shamt.pos[1];     // 5bit width (RV32I)
      } else if (this.#config.isa === COPTS_ISA.RV64I || this.#inst.opcode === OPCODE.OP_IMM_64) {
        shamtWidth = FIELDS.i_shamt_5_0.pos[1]; // 6bit width (RV64I)
      } else {
        shamtWidth = FIELDS.i_shamt_6_0.pos[1]; // 7bit width (RV128I)
      }

      // Construct immediate field from shift type and shift amount
      if (immediate < 0 || immediate >= (1 << shamtWidth)) {
        throw 'Invalid shamt field (out of range): "' + immediate + '"';
      }
      const imm_11_7 = '0' + this.#inst.shtyp + '000';
      const imm_6_0 = encImm(immediate, FIELDS.i_shamt_6_0.pos[1]);

      imm = imm_11_7 + imm_6_0;

    } else {
      // Non-shift instructions
      imm = encImm(immediate, FIELDS.i_imm_11_0.pos[1]);
    }

    // Construct binary instruction
    this.bin = imm + rs1 + this.#inst.funct3 + rd + this.#inst.opcode;
  }

  /**
   * Encodes MISC_MEM instruction
   */
  #encodeMISC_MEM() {
    // Default values
    let rs1 = ''.padStart(FIELDS.rs1.pos[1], '0'),
      rd = ''.padStart(FIELDS.rd.pos[1], '0'),
      imm = ''.padStart(FIELDS.i_imm_11_0.pos[1], '0');

    // Signals when MISC-MEM used as extended encoding space for load operations
    const loadExt = this.#mne === 'lq';

    if (loadExt) {
      // Get operands
      const dest = this.#opr[0], offset = this.#opr[1], base = this.#opr[2];

      // Convert to binary representation
      rd = encReg(dest);
      if (rd === '00000') {
        // rd=x0 in this encoding space is reserved for Zicbo cache-block
        // instructions (defined or not), so lq requires a real destination
        throw `Detected lq with rd=x0 - this encoding is reserved for Zicbo cache-block instructions`;
      }
      imm = encImm(offset, FIELDS.i_imm_11_0.pos[1]);
      rs1 = encReg(base);

    } else if (this.#mne === 'fence') {
      // Get operands
      const predecessor = this.#opr[0], successor = this.#opr[1];

      // Convert to binary representation
      const pred = encMem(predecessor), succ = encMem(successor);

      imm = '0000' + pred + succ;

    } else if (this.#mne.startsWith('cbo.')) {
      // Zicbo cache-block instructions: fixed imm, rs1 is the only operand
      const base = this.#opr[0];

      rs1 = encReg(base);
      imm = this.#inst.funct12;
    }

    // Construct binary instruction
    this.bin = imm + rs1 + this.#inst.funct3 + rd + this.#inst.opcode;
  }

  /**
   * Encodes SYSTEM instruction
   */
  #encodeSYSTEM() {
    // Declare operands
    let rs1, rd, imm;

    // Zicsr Instructions
    if (this.#inst.isa == 'Zicsr') {
      // Get operands
      const dest = this.#opr[0], csr = this.#opr[1], src = this.#opr[2];

      // Convert to binary representation
      rd = encReg(dest);
      imm = encCSR(csr);

      // Convert src to register or immediate
      //   based off high bit of funct3 (0:reg, 1:imm)
      rs1 = (this.#inst.funct3[0] === '0')
        ? encReg(src)
        : encImm(src, FIELDS.rs1.pos[1]);

    } else if (this.#inst.funct7 !== undefined) {
      if (this.#inst.realRd) {
        // mop.rr.N: rd is a real register, unlike the other R-type-like
        // forms below (sinval.vma/hinval.*/hsv.*/hfence.*)
        const dest = this.#opr[0], src1 = this.#opr[1], src2 = this.#opr[2];
        rd = encReg(dest);
        rs1 = encReg(src1);
        imm = this.#inst.funct7 + encReg(src2);
      } else if (this.#inst.mem) {
        // hsv.*: store-like ("hsv.b rs2, (rs1)"), operands reversed
        // relative to the plain rs1,rs2 pair below
        const src2 = this.#opr[0], src1 = this.#opr[1];
        rs1 = encReg(src1);
        rd = ''.padStart(FIELDS.rd.pos[1], '0');
        imm = this.#inst.funct7 + encReg(src2);
      } else {
        // R-type-like instructions with rd fixed to 0
        // (sinval.vma/hinval.*/hfence.*): fixed funct7, rs1/rs2 real
        const src1 = this.#opr[0], src2 = this.#opr[1];
        rs1 = encReg(src1);
        rd = ''.padStart(FIELDS.rd.pos[1], '0');
        imm = this.#inst.funct7 + encReg(src2);
      }

    } else if (this.#inst.realRd) {
      // mop.r.N / H's hlv.*: rd/rs1 are real registers, unlike the
      // fixed-zero trap forms
      const dest = this.#opr[0], src = this.#opr[1];
      rd = encReg(dest);
      rs1 = encReg(src);
      imm = this.#inst.funct12;

    } else {
      // Trap instructions
      rs1 = ''.padStart(FIELDS.rs1.pos[1], '0');
      rd = ''.padStart(FIELDS.rd.pos[1], '0');
      imm = this.#inst.funct12;
    }

    // Construct binary instruction
    this.bin = imm + rs1 + this.#inst.funct3 + rd + this.#inst.opcode;
  }

  /**
   * Encodes STORE instruction
   */
  #encodeSTORE() {
    if (this.#inst.fmt === 'V-mem') {
      this.#encodeVMem(false);
      return;
    }

    // Get operands
    const src = this.#opr[0], offset = this.#opr[1], base = this.#opr[2];

    // Immediate len
    const len_11_5 = FIELDS.s_imm_11_5.pos[1],
      len_4_0 = FIELDS.s_imm_4_0.pos[1];

    // Convert to binary representation
    const floatInst = this.#inst.opcode === OPCODE.STORE_FP;
    const rs2 = encReg(src, floatInst),
      rs1 = encReg(base),
      imm = encImm(offset, len_11_5 + len_4_0),
      imm_11_5 = imm.substring(0, len_11_5),
      imm_4_0 = imm.substring(len_11_5, len_11_5 + len_4_0);

    // Construct binary instruction
    this.bin = imm_11_5 + rs2 + rs1 + this.#inst.funct3 + imm_4_0 +
      this.#inst.opcode;
  }

  /**
   * Encodes BRANCH instruction
   */
  #encodeBRANCH() {
    // Get operands
    const src1 = this.#opr[0], src2 = this.#opr[1], offset = this.#opr[2];

    // Immediate len
    const len_12 = FIELDS.b_imm_12.pos[1],
      len_11 = FIELDS.b_imm_11.pos[1],
      len_10_5 = FIELDS.b_imm_10_5.pos[1],
      len_4_1 = FIELDS.b_imm_4_1.pos[1];

    // Convert to binary representation
    const rs1 = encReg(src1), rs2 = encReg(src2),
      imm = encImm(offset, len_12 + len_11 + len_10_5 + len_4_1 + 1);

    const imm_12 = imm.substring(0, len_12),
      imm_11 = imm.substring(len_12, len_12 + len_11),
      imm_10_5 = imm.substring(len_12 + len_11, len_12 + len_11 + len_10_5),
      imm_4_1 = imm.substring(len_12 + len_11 + len_10_5,
        len_12 + len_11 + len_10_5 + len_4_1);

    // Construct binary instruction
    this.bin = imm_12 + imm_10_5 + rs2 + rs1 + this.#inst.funct3 +
      imm_4_1 + imm_11 + this.#inst.opcode;
  }

  /**
   * Encodes U-type instruction
   */
  #encodeUType() {
    // Get operands
    const dest = this.#opr[0], immediate = this.#opr[1];

    // Convert to binary representation
    const rd = encReg(dest);
    // Construct immediate field
    const imm_31_12 = encImm(immediate, FIELDS.u_imm_31_12.pos[1]);

    // Construct binary instruction
    this.bin = imm_31_12 + rd + this.#inst.opcode;
  }

  /**
   * Encodes J-type instruction
   */
  #encodeJAL() {
    // Get operands
    const dest = this.#opr[0],
      offset = this.#opr[1];

    // Immediate len
    const len_20 = FIELDS.j_imm_20.pos[1],
      len_10_1 = FIELDS.j_imm_10_1.pos[1],
      len_11 = FIELDS.j_imm_11.pos[1],
      len_19_12 = FIELDS.j_imm_19_12.pos[1];

    // Convert to binary representation
    const rd = encReg(dest),
      imm = encImm(offset, len_20 + len_19_12 + len_11 + len_10_1 + 1);

    const imm_20 = imm.substring(0, len_20),
      imm_19_12 = imm.substring(len_20, len_20 + len_19_12),
      imm_11 = imm.substring(len_20 + len_19_12, len_20 + len_19_12 + len_11),
      imm_10_1 = imm.substring(len_20 + len_19_12 + len_11,
        len_20 + len_19_12 + len_11 + len_10_1);

    // Construct binary instruction
    this.bin = imm_20 + imm_10_1 + imm_11 + imm_19_12 + rd + this.#inst.opcode;
  }

  /**
   * Encodes OP-V (vector) instructions
   */
  #encodeOP_V() {
    if (this.#inst.fmt === 'V-cfg') {
      this.#encodeVCFG();
      return;
    }
    if (this.#inst.fmt === 'V-arith') {
      this.#encodeVArith();
      return;
    }
    throw 'Unsupported OP-V instruction (vector arithmetic instructions ' +
      'not yet supported): ' + this.#mne;
  }

  // vsetvli rd, rs1, vtypei / vsetivli rd, uimm, vtypei / vsetvl rd, rs1, rs2
  #encodeVCFG() {
    const rd = encReg(this.#opr[0]);

    if (this.#mne === 'vsetvl') {
      const rs1 = encReg(this.#opr[1]), rs2 = encReg(this.#opr[2]);
      this.bin = this.#inst.funct7 + rs2 + rs1 + this.#inst.funct3 + rd + this.#inst.opcode;
      return;
    }

    // Both vsetvli and vsetivli take the vtype tokens starting at opr[2]:
    // sew (required), lmul/ta/ma (optional, default m1/tu/mu)
    const vtype = encVtype(this.#opr[2], this.#opr[3], this.#opr[4], this.#opr[5]);

    if (this.#mne === 'vsetvli') {
      const rs1 = encReg(this.#opr[1]);
      // bit31=0, zimm11[10:8]=reserved(0), zimm11[7:0]=vtype
      this.bin = '0' + '000' + vtype + rs1 + this.#inst.funct3 + rd + this.#inst.opcode;
    } else {
      // vsetivli: bit31:30='11', zimm10[9:8]=reserved(0), zimm10[7:0]=vtype
      const uimm = encImm(this.#opr[1], 5);
      this.bin = '11' + '00' + vtype + uimm + this.#inst.funct3 + rd + this.#inst.opcode;
    }
  }

  // V vector arithmetic: mirrors Decoder.js's #decodeVArith field layout.
  #encodeVArith() {
    const inst = this.#inst;
    const vd = inst.vdType === 'x' ? encReg(this.#opr[0])
      : inst.vdType === 'f' ? encReg(this.#opr[0], true)
      : encVReg(this.#opr[0]);
    let next = 1;

    // vror.vi's 6-bit immediate splits across the funct6 LSB ("zimm6hi")
    // and the usual 5-bit field ("zimm6lo") - readSrc1 reports the lo bits
    // and stashes the hi bit here to fold into funct6 below
    let zimm6hi;
    const readVs2 = () => inst.vs2Fixed !== undefined ? inst.vs2Fixed : encVReg(this.#opr[next++]);
    const readSrc1 = () => {
      if (inst.vs1Fixed !== undefined) {
        return inst.vs1Fixed;
      } else if (inst.funct3 === V_CAT.IVV || inst.funct3 === V_CAT.MVV || inst.funct3 === V_CAT.FVV) {
        return encVReg(this.#opr[next++]);
      } else if (inst.funct3 === V_CAT.IVX || inst.funct3 === V_CAT.MVX) {
        return encReg(this.#opr[next++]);
      } else if (inst.funct3 === V_CAT.FVF) {
        return encReg(this.#opr[next++], true);
      } else if (inst.immType === 'zi6') {
        const imm6 = encImm(this.#opr[next++], 6);
        zimm6hi = imm6[0];
        return imm6.slice(1);
      }
      return encImm(this.#opr[next++], 5);
    };

    // Operand order: (vd, vs2, src1) normally, but the multiply-accumulate
    // family is typed as (vd, src1, vs2) per the RVV spec
    let vs2, src1;
    if (inst.swap) {
      src1 = readSrc1();
      vs2 = readVs2();
    } else {
      vs2 = readVs2();
      src1 = readSrc1();
    }

    const vm = inst.vmFixed ?? (this.#opr[next] === 'v0.t' ? '0' : '1');
    const funct6 = zimm6hi === undefined ? inst.funct6 : inst.funct6.slice(0, 5) + zimm6hi;

    this.bin = funct6 + vm + vs2 + src1 + inst.funct3 + vd + inst.opcode;
  }

  // Vector-crypto instructions: mirrors Decoder.js's #decodeVCrypto field
  // layout - always-unmasked (vm=1), single-shape (funct3=0x2)
  #encodeVCrypto() {
    const inst = this.#inst;
    const vd = encVReg(this.#opr[0]);
    const vs2 = encVReg(this.#opr[1]);
    const src1 = inst.vs1Fixed !== undefined ? inst.vs1Fixed
      : inst.immType === 'zi' ? encImm(this.#opr[2], 5)
      : encVReg(this.#opr[2]);
    const numOperands = inst.vs1Fixed !== undefined ? 2 : 3;
    const vm = inst.vmFixed ?? (this.#opr[numOperands] === 'v0.t' ? '0' : '1');

    this.bin = inst.funct6 + vm + vs2 + src1 + inst.funct3 + vd + inst.opcode;
  }

  // V vector loads/stores: mirrors Decoder.js's #decodeVMem field layout.
  // this.#inst is always the base (nf=0) ISA entry - segment mnemonics were
  // already resolved to it (with this.#vNf set) back in the constructor.
  #encodeVMem(isLoad) {
    const inst = this.#inst;
    const vdOrVs3 = encVReg(this.#opr[0]);
    const rs1 = encReg(this.#opr[1]);

    let reg24_20, vm, nf;
    if (inst.vCat === 'mask') {
      reg24_20 = inst.lumop;
      vm = '1';
      nf = '000';
    } else if (inst.vCat === 'wholereg') {
      reg24_20 = inst.lumop;
      vm = '1';
      nf = inst.nf;
    } else {
      nf = encImm(this.#vNf, 3);
      let next = 2;
      if (inst.mop === '10') {
        reg24_20 = encReg(this.#opr[next++]);
      } else if (inst.mop === '01' || inst.mop === '11') {
        reg24_20 = encVReg(this.#opr[next++]);
      } else {
        reg24_20 = inst.lumop;
      }
      vm = this.#opr[next] === 'v0.t' ? '0' : '1';
    }

    this.bin = nf + '0' + inst.mop + vm + reg24_20 + rs1 + inst.width + vdOrVs3 + inst.opcode;
  }

  /**
   * Encodes AMO instruction
   */
  #encodeAMO() {
    // Declare operands
    let dest, addr, src;

    // Get operands, separately for 'lr' instruction
    if (/^lr\./.test(this.#mne)) {
      dest = this.#opr[0];
      addr = this.#opr[1];
      src  = 'x0'; // converts to '00000'
    }
    else {
      dest = this.#opr[0];
      addr = this.#opr[2];
      src  = this.#opr[1];
    }

    // Convert to binary representation
    const rd = encReg(dest), rs1 = encReg(addr), rs2 = encReg(src),
      aq = '0', rl = '0';

    // Construct binary instruction
    this.bin = this.#inst.funct5 + aq + rl + rs2 + rs1 +
      this.#inst.funct3 + rd + this.#inst.opcode;
  }

  /**
   * Encodes Zalasr (unratified load-acquire/store-release) instructions:
   * mirrors Decoder.js's #decodeZalasr field layout
   */
  #encodeZalasr() {
    const inst = this.#inst;
    let rd, rs1, rs2, aq, rl;
    if (inst.isLoad) {
      rd = encReg(this.#opr[0]);
      rs1 = encReg(this.#opr[1]);
      rs2 = '00000';
      aq = '1';
      rl = '0';
    } else {
      rd = '00000';
      rs2 = encReg(this.#opr[0]);
      rs1 = encReg(this.#opr[1]);
      aq = '0';
      rl = '1';
    }

    this.bin = inst.funct5 + aq + rl + rs2 + rs1 + inst.funct3 + rd + inst.opcode;
  }

  /**
   * Encodes R4 instruction
   */
  #encodeR4() {
    // Get operands
    const dest = this.#opr[0], src1 = this.#opr[1],
      src2 = this.#opr[2], src3 = this.#opr[3],
      frm = this.#opr[4];

    // Convert to binary representation
    const rd = encReg(dest, true), rs1 = encReg(src1, true),
      rs2 = encReg(src2, true), rs3 = encReg(src3, true),
      fmt = this.#inst.fp_fmt, funct3 = encFrm(frm) ?? '111' /* dyn rm */;

    // Construct binary instruction
    this.bin = rs3 + fmt + rs2 + rs1 + funct3 + rd +
      this.#inst.opcode;
  }

  /**
   * Encodes CR-type instruction
   */
  #encodeCR() {
    // Get operands
    const destSrc1 = this.#opr[0], src2 = this.#opr[1];

    // Encode registers, but overwite with static values if present
    const rdRs1 = this.#inst.rdRs1Val !== undefined
      ? encImm(this.#inst.rdRs1Val, FIELDS.c_rd_rs1.pos[1])
      : (destSrc1 === undefined ? '01000' : encReg(destSrc1));
    const rs2 = this.#inst.rs2Val !== undefined
      ? encImm(this.#inst.rs2Val, FIELDS.c_rs2.pos[1])
      : (src2 === undefined ? '01000' : encReg(src2));

    // Validate operands
    if (this.#inst.rdRs1Excl !== undefined) {
      const val = parseInt(rdRs1, BASE.bin);
      for (const excl of this.#inst.rdRs1Excl) {
        if (val === excl) {
          throw `Illegal value "${destSrc1}" in rd/rs1 field for instruction ${this.#mne}`;
        }
      }
    }
    if (this.#inst.rs2Excl !== undefined) {
      const val = parseInt(rs2, BASE.bin);
      for (const excl of this.#inst.rs2Excl) {
        if (val === excl) {
          throw `Illegal value "${src2}" in rs2 field for instruction ${this.#mne}`;
        }
      }
    }

    // Construct binary instruction
    this.bin = this.#inst.funct4 + rdRs1 + rs2 + this.#inst.opcode;
  }

  /**
   * Encodes CI-type instruction
   */
  #encodeCI() {
    // Determine operand order
    const skipRdRs1 = this.#inst.rdRs1Val !== undefined;

    // Get operands
    const destSrc1 = this.#opr[0];
    const immediate = this.#opr[skipRdRs1 ? 0 : 1];

    // Determine if rdRs1 should be float register from mnemonic
    const floatRdRs1 = /^c\.f/.test(this.#mne);

    // Encode operands, but overwite with static values if present
    const rdRs1 = skipRdRs1
      ? encImm(this.#inst.rdRs1Val, FIELDS.c_rd_rs1.pos[1])
      : (destSrc1 === undefined ? '01000' : encReg(destSrc1, floatRdRs1));
    let immVal = this.#inst.immVal ?? Number(immediate);

    // Validate operands
    if (this.#inst.rdRs1Excl !== undefined) {
      const val = parseInt(rdRs1, BASE.bin);
      for (const excl of this.#inst.rdRs1Excl) {
        if (val === excl) {
          throw `Illegal value "${destSrc1}" in rd/rs1 field for instruction ${this.#mne}`;
        }
      }
    }
    if (this.#inst.nzimm && (immVal === 0 || isNaN(immVal))) {
      // If missing immediate, generate lowest non-zero immediate value
      if (immediate === undefined) {
        immVal = minImmFromBits(this.#inst.immBits);
      } else {
        throw `Invalid immediate "${immediate}", ${this.#mne} instruction expects non-zero value`;
      }
    }
    if (this.#inst.uimm && immVal < 0) {
      throw `Invalid immediate "${immediate}", ${this.#mne} instruction expects non-negative value`;
    }

    // Construct immediate fields
    const imm0 = encImmBits(immVal, this.#inst.immBits[0]);
    const imm1 = encImmBits(immVal, this.#inst.immBits[1]);

    // Construct binary instruction
    this.bin = this.#inst.funct3 + imm0 + rdRs1 + imm1 + this.#inst.opcode;
  }

  /**
   * Encodes CSS-type instruction
   */
  #encodeCSS() {
    // Get operands
    const src = this.#opr[0], offset = this.#opr[1];

    // Determine if rs2 should be float register from mnemonic
    const floatRs2 = /^c\.f/.test(this.#mne);

    // Encode operands and parse immediate for validation
    const rs2 = encReg(src, floatRs2);
    let immVal = Number(offset);

    // Validate operands
    if (this.#inst.uimm && immVal < 0) {
      throw `Invalid immediate "${offset}", ${this.#mne} instruction expects non-negative value`;
    }

    // Construct immediate field
    const imm = encImmBits(immVal, this.#inst.immBits);

    // Construct binary instruction
    this.bin = this.#inst.funct3 + imm + rs2 + this.#inst.opcode;
  }

  /**
   * Encodes CIW-type instruction
   */
  #encodeCIW() {
    // Get operands
    const dest = this.#opr[0], immediate = this.#opr[1];

    // Encode operands and parse immediate for validation
    const rdPrime = encRegPrime(dest);
    let immVal = Number(immediate);

    // Validate operands
    if (this.#inst.nzimm && (immVal === 0 || isNaN(immVal))) {
      // If missing immediate, generate lowest non-zero immediate value
      if (immediate === undefined) {
        immVal = minImmFromBits(this.#inst.immBits);
      } else {
        throw `Invalid immediate "${immediate}", ${this.#mne} instruction expects non-zero value`;
      }
    }
    if (this.#inst.uimm && immVal < 0) {
      throw `Invalid immediate "${immediate}", ${this.#mne} instruction expects non-negative value`;
    }

    // Construct immediate field
    const imm = encImmBits(immVal, this.#inst.immBits);

    // Construct binary instruction
    this.bin = this.#inst.funct3 + imm + rdPrime + this.#inst.opcode;
  }

  /**
   * Encodes CL-type instruction
   */
  #encodeCL() {
    if (this.#inst.subop !== undefined) {
      return this.#encodeZcbMem();
    }

    // Get operands
    const dest = this.#opr[0], offset = this.#opr[1], base = this.#opr[2];

    // Determine if rd' should be float register from mnemonic
    const floatRd = /^c\.f/.test(this.#mne);

    // Encode operands and parse immediate for validation
    const rdPrime = encRegPrime(dest, floatRd);
    const rs1Prime = encRegPrime(base);
    let immVal = Number(offset);

    // Validate operands
    if (this.#inst.uimm && immVal < 0) {
      throw `Invalid immediate "${offset}", ${this.#mne} instruction expects non-negative value`;
    }

    // Construct immediate fields
    const imm0 = encImmBits(immVal, this.#inst.immBits[0]);
    const imm1 = encImmBits(immVal, this.#inst.immBits[1]);

    // Construct binary instruction
    this.bin = this.#inst.funct3 + imm0 + rs1Prime + imm1 + rdPrime + this.#inst.opcode;
  }

  /**
   * Encodes CS-type instruction
   */
  #encodeCS() {
    if (this.#inst.subop !== undefined) {
      return this.#encodeZcbMem();
    }

    // Get operands
    const src = this.#opr[0], immediate = this.#opr[1], base = this.#opr[2];

    // Determine if rd' should be float register from mnemonic
    const floatRs2 = /^c\.f/.test(this.#mne);

    // Encode operands and parse immediate for validation
    const rs2Prime = encRegPrime(src, floatRs2);
    const rs1Prime = encRegPrime(base);
    let immVal = Number(immediate);

    // Validate operands
    if (this.#inst.uimm && immVal < 0) {
      throw `Invalid immediate "${immediate}", ${this.#mne} instruction expects non-negative value`;
    }

    // Construct immediate fields
    const imm0 = encImmBits(immVal, this.#inst.immBits[0]);
    const imm1 = encImmBits(immVal, this.#inst.immBits[1]);

    // Construct binary instruction
    this.bin = this.#inst.funct3 + imm0 + rs1Prime + imm1 + rs2Prime + this.#inst.opcode;
  }

  /**
   * Encodes Zcb byte/halfword loads (c.lbu/c.lhu/c.lh) and stores
   * (c.sb/c.sh)
   */
  #encodeZcbMem() {
    // Get operands
    const reg = this.#opr[0], offset = this.#opr[1], base = this.#opr[2];

    // Encode operands and parse immediate for validation
    const regPrime = encRegPrime(reg);
    const rs1Prime = encRegPrime(base);
    const immVal = Number(offset);

    if (immVal < 0) {
      throw `Invalid immediate "${offset}", ${this.#mne} instruction expects non-negative value`;
    }

    let uimm;
    if (this.#inst.subop2 !== undefined) {
      // Halfword offset: 0 or 2 (2-byte aligned)
      if (immVal !== 0 && immVal !== 2) {
        throw `Invalid immediate "${offset}", ${this.#mne} instruction expects 0 or 2`;
      }
      uimm = this.#inst.subop2 + encImm(immVal / 2, 1);
    } else {
      // Byte offset: 0-3
      if (immVal > 3) {
        throw `Invalid immediate "${offset}", ${this.#mne} instruction expects 0-3`;
      }
      uimm = encImm(immVal, 2);
    }

    // Construct binary instruction
    this.bin = this.#inst.funct3 + this.#inst.subop + rs1Prime + uimm + regPrime +
      this.#inst.opcode;
  }

  /**
   * Encodes CA-type instruction
   */
  #encodeCA() {
    // Get operands
    const destSrc1 = this.#opr[0], src2 = this.#opr[1];

    // Encode operands and parse immediate for validation
    const rdRs1Prime = encRegPrime(destSrc1);
    // Zcb single-operand instructions (c.zext.b/h/w, c.sext.b/h, c.not):
    // rs2' bits are a fixed sub-opcode selector, not a register
    const rs2Prime = this.#inst.subfunct3 ?? encRegPrime(src2);

    // Construct binary instruction
    this.bin = this.#inst.funct6 + rdRs1Prime + this.#inst.funct2 + rs2Prime + this.#inst.opcode;
  }

  /**
   * Encodes CB-type instruction
   */
  #encodeCB() {
    // Get operands
    const destSrc1 = this.#opr[0], immediate = this.#opr[1];

    // Encode operands, but overwite with static values if present
    const rdRs1Prime = encRegPrime(destSrc1);
    let immVal = this.#inst.immVal ?? Number(immediate);

    // Validate operands
    if (this.#inst.nzimm && (immVal === 0 || isNaN(immVal))) {
      // If missing immediate, generate lowest non-zero immediate value
      if (immediate === undefined) {
        immVal = minImmFromBits(this.#inst.immBits);
      } else {
        throw `Invalid immediate "${immediate}", ${this.#mne} instruction expects non-zero value`;
      }
    }
    if (this.#inst.uimm && immVal < 0) {
      throw `Invalid immediate "${immediate}", ${this.#mne} instruction expects non-negative value`;
    }

    // Construct immediate fields
    const imm0 = encImmBits(immVal, this.#inst.immBits[0]);
    const imm1 = encImmBits(immVal, this.#inst.immBits[1]);

    // Conditionally construct funct2 field, if present
    const funct2 = this.#inst.funct2 ?? '';

    // Construct binary instruction
    this.bin = this.#inst.funct3 + imm0 + funct2 + rdRs1Prime + imm1 + this.#inst.opcode;
  }

  /**
   * Encodes CJ-type instruction
   */
  #encodeCJ() {
    // Get operands
    const immediate = this.#opr[0];

    // Construct immediate fields
    const jumpTarget = encImmBits(immediate, this.#inst.immBits);

    // Construct binary instruction
    this.bin = this.#inst.funct3 + jumpTarget + this.#inst.opcode;
  }

  /**
   * Encodes CMJT-type instruction (Zcmt cm.jalt)
   */
  #encodeCMJT() {
    // Get operands
    const index = this.#opr[0];

    if (index < 0 || index > 255) {
      throw `Invalid index field (out of range): "${index}"`;
    }

    // Construct binary instruction
    this.bin = this.#inst.funct3 + this.#inst.subop + encImm(index, FIELDS.c_index.pos[1]) +
      this.#inst.opcode;
  }

  /**
   * Encodes CMPP-type instruction
   *   (Zcmp cm.push/cm.pop/cm.popretz/cm.popret)
   */
  #encodeCMPP() {
    // Get operands - the register list's internal comma splits it into two
    // tokens unless it holds a single register (just "{ra}")
    let listStr, immediate;
    if (this.#opr.length >= 3) {
      listStr = this.#opr[0] + ',' + this.#opr[1];
      immediate = this.#opr[2];
    } else {
      listStr = this.#opr[0];
      immediate = this.#opr[1];
    }

    const rlist = encRlist(listStr);
    const rlistVal = parseInt(rlist, BASE.bin);
    const xlenBytes = this.#config.ISA === COPTS_ISA.RV64I ? 8
      : this.#config.ISA === COPTS_ISA.RV128I ? 16 : 4;
    const spimm = encStackAdj(rlistVal, immediate, xlenBytes, this.#inst.signNeg === true);

    // Construct binary instruction
    this.bin = this.#inst.funct3 + this.#inst.subop + this.#inst.bit9 + rlist + spimm +
      this.#inst.opcode;
  }

  /**
   * Encodes CMMV-type instruction (Zcmp cm.mvsa01/cm.mva01s)
   */
  #encodeCMMV() {
    // Get operands
    const reg1 = this.#opr[0], reg2 = this.#opr[1];

    // Encode operands
    const sreg1 = encSreg(reg1);
    const sreg2 = encSreg(reg2);

    // Construct binary instruction
    this.bin = this.#inst.funct3 + this.#inst.subop + sreg1 + this.#inst.funct2 + sreg2 +
      this.#inst.opcode;
  }
}

// Parse given immediate to binary
function encImm(immediate, len) {
  let bin = (Number(immediate) >>> 0).toString(BASE.bin);
  // Extend or reduce binary representation to `len` bits
  return bin.padStart(len, '0').slice(-len);
}

// Encode immediate value using the given immBits configuration
function encImmBits(immediate, immBits) {
  // Full length is 18 as no C instruction immediate will be longer
  const len = 18;
  let binFull = encImm(immediate, len);
  let bin = '';
  for (let b of immBits) {
    // Detect singular bit vs bit span
    if (typeof b === 'number') {
      bin += binFull[len - 1 - b];
    } else {
      bin += binFull.substring(len - 1 - b[0], len - b[1]);
    }
  }
  return bin;
}

// Get the lowest possible non-zero value from an immBits configuration
function minImmFromBits(immBits) {
  // Local recursive function for finding mininum value from arbitrarily nested arrays
  function deepMin(numOrArr) {
    let minVal = Infinity;
    if (typeof numOrArr === 'number') {
      return numOrArr;
    }
    for (let e of numOrArr) {
      minVal = Math.min(minVal, deepMin(e));
    }
    return minVal;
  }
  return Number('0b1' + ''.padStart(deepMin(immBits), '0'));
}

// Convert register numbers to binary
function encReg(reg, floatReg=false) {
  // Attempt to convert from ABI name to x<num> or f<num>, depending on `floatReg`
  reg = (floatReg ? FLOAT_REGISTER[reg] : REGISTER[reg]) ?? reg;
  // Validate using register file prefix determined from `floatReg` parameter
  let regFile = floatReg ? 'f' : 'x';
  if (reg === undefined || reg.length === 0) {
    // Missing operand, helpfully return 'x0' or 'f0' by default
    return '00000';
  } else if (reg[0] !== regFile || !(/^[fx]\d+/.test(reg))) {
    throw `Invalid or unknown ${floatReg ? 'float ' : ''}register format: "${reg}"`;
  }
  // Attempt to parse the decimal register address, set to 0 on failed parse
  let dec = parseInt(reg.substring(1));
  if (isNaN(dec)) {
    dec = 0;
  } else if (dec < 0 || dec > 31) {
    throw `Register address out of range: "${reg}"`;
  }
  return convertBase(dec, BASE.dec, BASE.bin, 5);
}

// Zfa fli.*: encodes rs1 from one of the 32 standard floating-point constants
function encFli(value) {
  const idx = FLI_STRINGS.indexOf(value);
  if (idx === -1) {
    throw `Invalid fli constant: "${value}"`;
  }
  return convertBase(idx, BASE.dec, BASE.bin, 5);
}

// V register: v0-v31, no ABI aliases
function encVReg(reg) {
  if (reg === undefined || reg.length === 0) {
    return '00000';
  }
  const match = /^v(\d+)$/.exec(reg);
  if (match === null) {
    throw `Invalid or unknown vector register format: "${reg}"`;
  }
  const dec = parseInt(match[1]);
  if (dec < 0 || dec > 31) {
    throw `Register address out of range: "${reg}"`;
  }
  return convertBase(dec, BASE.dec, BASE.bin, 5);
}

// vsetvli/vsetivli's vtypei immediate: encodes the 4 canonical assembly
// tokens (sew required, lmul/ta/ma optional, defaulting to m1/tu/mu) into
// the 8-bit vma/vta/vsew/vlmul value
function encVtype(sew, lmul = 'm1', ta = 'tu', ma = 'mu') {
  const vsew = Object.entries(V_SEW).find(e => e[1] === sew)?.[0];
  const vlmul = Object.entries(V_LMUL).find(e => e[1] === lmul)?.[0];
  if (vsew === undefined) {
    throw `Invalid vtype SEW: "${sew}"`;
  }
  if (vlmul === undefined) {
    throw `Invalid vtype LMUL: "${lmul}"`;
  }
  if (ta !== 'ta' && ta !== 'tu') {
    throw `Invalid vtype tail policy: "${ta}"`;
  }
  if (ma !== 'ma' && ma !== 'mu') {
    throw `Invalid vtype mask policy: "${ma}"`;
  }
  return (ma === 'ma' ? '1' : '0') + (ta === 'ta' ? '1' : '0') + vsew + vlmul;
}

// Zcmp cm.mvsa01/cm.mva01s: encodes a restricted s-register (s0-s1 or
// s2-s7) into the 3-bit sreg field
function encSreg(regName) {
  const reg = REGISTER[regName] ?? regName;
  const match = /^x(\d+)$/.exec(reg);
  if (match === null) {
    throw `Invalid or unknown register format: "${regName}"`;
  }
  const regNum = parseInt(match[1]);
  let idx;
  if (regNum === 8 || regNum === 9) {
    idx = regNum - 8;
  } else if (regNum >= 18 && regNum <= 23) {
    idx = regNum - 16;
  } else {
    throw `Invalid register for sreg field: "${regName}" (expected s0, s1, or s2-s7)`;
  }
  return convertBase(idx, BASE.dec, BASE.bin, 3);
}

// Zcmp cm.push/cm.pop/cm.popretz/cm.popret: encodes the {ra[, s0[-sN]]}
// register-list operand into the 4-bit rlist value (see decRlist in
// Decoder.js for the reverse mapping and the rlist=15 special case)
function encRlist(str) {
  const m = /^\{ra(?:,\s*s0(?:-s(\d+))?)?\}$/.exec(str.trim());
  if (m === null) {
    throw `Invalid register list: "${str}"`;
  }
  let n;
  if (m[1] !== undefined) {
    n = parseInt(m[1]) + 2;
  } else if (str.includes('s0')) {
    n = 2;
  } else {
    n = 1;
  }
  if (n === 13) {
    return '1111';
  }
  if (n < 1 || n > 11) {
    throw `Invalid register list: "${str}" (unsupported register count)`;
  }
  return convertBase(n + 3, BASE.dec, BASE.bin, 4);
}

// Zcmp: derives the 2-bit spimm value from the requested total stack
// adjustment, the register list's own byte requirement, and XLEN
function encStackAdj(rlistVal, immediate, xlenBytes, expectNeg) {
  const val = Number(immediate);
  if (expectNeg ? val > 0 : val < 0) {
    throw `Invalid immediate "${immediate}", expected ${expectNeg ? 'non-positive' : 'non-negative'} value`;
  }

  const n = rlistVal === 15 ? 13 : rlistVal - 3;
  const base = Math.ceil(n * xlenBytes / 16) * 16;
  const spimmVal = (Math.abs(val) - base) / 16;
  if (!Number.isInteger(spimmVal) || spimmVal < 0 || spimmVal > 3) {
    const opts = [0, 1, 2, 3].map(s => base + s * 16).join(', ');
    throw `Invalid immediate "${immediate}" for this register list (expected one of: ${opts})`;
  }
  return convertBase(spimmVal, BASE.dec, BASE.bin, 2);
}

// Convert compressed register numbers to binary
function encRegPrime(reg, floatReg=false) {
  // Missing operand, use x8 or f8
  if (reg === undefined) {
    return '000';
  }

  // Encode register
  const encoded = encReg(reg, floatReg);
  // Make sure that compressed register belongs to x8-x15/f8-15 range
  // - Full 5-bit encoded register should conform to '01xxx', use the 'xxx' in the encoded instruction
  if (encoded.substring(0, 2) !== '01') {
    const regFile = floatReg ? 'f' : 'x';
    throw `Invalid register "${reg}", rd' field expects compressable register from ${regFile}8 to ${regFile}15`;
  }
  return encoded.substring(2);
}

// Convert memory ordering to binary
function encMem(input) {
  // Default input to 'iorw'
  input = input ?? 'iorw';

  // I: Device input, O: device output, R: memory reads, W: memory writes
  const access = ['i', 'o', 'r', 'w'];

  // Construct bits from input character flags
  let bits = '';
  let one_count = 0;
  for (let i = 0; i < access.length; i++) {
    if (input.includes(access[i])) {
      bits += '1';
      one_count++;
    } else {
      bits += '0';
    }
  }

  if (one_count !== input.length || bits === '0000') {
    throw `Invalid IO/Mem field '${input}', expected some combination of 'iorw'`
  }

  return bits;
}

// Convert CSR (name or imm) to binary
function encCSR(csr) {
  // Attempt to find CSR value from CSR name map
  // - If `csr` is undefined, default to `cycle`
  let csrVal = CSR[csr ?? 'cycle'];

  // If failed, attempt to parse as immediate
  if (csrVal === undefined) {
    csrVal = Number(csr) >>> 0;

    // If parse failed, neither number nor valid CSR name
    if (csrVal === 0 && csr != 0) {
      throw `Invalid or unknown CSR name: "${csr}"`;
    }
  }

  return encImm(csrVal, FIELDS.i_csr.pos[1]);
}

// Convert float rounding mode name to binary
function encFrm(frm) {
  // Default input to 'dyn'
  frm = frm ?? 'dyn';

  // Lookup name in frm table
  const frmVal = FLOAT_ROUNDING_MODE[frm];
  if (frmVal === undefined) {
    throw `Invalid float rounding mode field '${frm}'`
  }

  return encImm(frmVal, FIELDS.r_fp_rm.pos[1]);
}
