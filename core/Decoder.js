// SPDX-License-Identifier: AGPL-3.0-or-later

/*
 * RISC-V Instruction Encoder/Decoder
 *
 * Copyright (c) 2021-2022 LupLab @ UC Davis
 */

import { BASE, XLEN_MASK, FLI_STRINGS,
  FIELDS, OPCODE, C_OPCODE, REGISTER, FLOAT_REGISTER, FLOAT_ROUNDING_MODE, CSR,
  ISA_OP, ISA_OP_32, ISA_OP_64, ISA_OP_BS, ISA_OP_IMM, ISA_OP_IMM_32, ISA_OP_IMM_64,
  ISA_LOAD, ISA_STORE, ISA_BRANCH, ISA_MISC_MEM, ISA_SYSTEM, ISA_AMO,
  ISA_LOAD_FP, ISA_STORE_FP, ISA_OP_FP,
  ISA_MADD, ISA_MSUB, ISA_NMADD, ISA_NMSUB,
  ISA_C0, ISA_C1, ISA_C2, ISA_C1_MOP, ISA_C2_ZCMP,
  V_SEW, V_LMUL, V_EEW, V_WHOLEREG_NF, vSegName, vParseSegName,
  V_CAT, ISA_OP_V_ARITH, ISA_OP_V_CRYPTO,
  ISA, FRAG
} from './Constants.js'

import { COPTS_ISA } from './Config.js'

import { Frag, convertRegToAbi } from './Instruction.js'

export class Decoder {
  /**
   * Assembly representation of instruction
   * @type String
   */
  asm;
  /**
   * ISA of instruction: 'RV32I', 'RV64I', 'EXT_M', 'EXT_A', etc.
   * @type String
   */
  isa;
  /**
   * Format of instruction: 'R-type', 'I-type', etc.
   * @type String
   */
  fmt;
  /**
   * Fragments for binary instruction rendering
   * @type {Frag[]}
   */
  binFrags;
  /**
   * Fragments for assembly instruction rendering
   * @type {Frag[]}
   */
  asmfrags;

  /* Private members */
  #bin;
  #config;
  #mne;
  #opcode;
  #xlens;


  /**
   * Creates an Decoder to convert a binary instruction to assembly
   * @param {String} bin
   */
  constructor(bin, config, xlens = undefined) {
    this.#bin = bin;
    this.#config = config;
    this.#xlens = xlens;

    // Create an array of assembly fragments
    this.binFrags = [];
    this.asmFrags = [];

    // Convert instruction to assembly
    this.#convertBinToAsm();
  }

  // Convert binary instruction to assembly
  #convertBinToAsm() {
    // Use opcode to determine instruction type
    this.#opcode = getBits(this.#bin, FIELDS.opcode.pos);
    // Test for standard 32-bit instruction (i.e., the 2 LSBs of the opcode are '11')
    if (this.#opcode.substring(this.#opcode.length - 2) === '11') {
      switch (this.#opcode) {
          // R-type
        case OPCODE.OP:
        case OPCODE.OP_32:
        case OPCODE.OP_64:
          this.#decodeOP();
          break;
        case OPCODE.OP_FP:
          this.#decodeOP_FP();
          break;
        case OPCODE.OP_V:
          this.#decodeOP_V();
          break;
        case OPCODE.OP_V_CRYPTO:
          this.#decodeVCrypto();
          break;
        case OPCODE.AMO:
          this.#decodeAMO();
          break;

          // I-type
        case OPCODE.JALR:
          this.#decodeJALR();
          break;
        case OPCODE.LOAD:
        case OPCODE.LOAD_FP:
          this.#decodeLOAD();
          break;
        case OPCODE.OP_IMM:
        case OPCODE.OP_IMM_32:
        case OPCODE.OP_IMM_64:
          this.#decodeOP_IMM();
          break;
        case OPCODE.MISC_MEM:
          this.#decodeMISC_MEM();
          break;
        case OPCODE.SYSTEM:
          this.#decodeSYSTEM();
          break;

          // S-type
        case OPCODE.STORE:
        case OPCODE.STORE_FP:
          this.#decodeSTORE();
          break;

          // B-type
        case OPCODE.BRANCH:
          this.#decodeBRANCH();
          break;

          // U-type:
        case OPCODE.LUI:
        case OPCODE.AUIPC:
          this.#decodeUType();
          break;

          // J-type:
        case OPCODE.JAL:
          this.#decodeJAL();
          break;

          // R4-type
        case OPCODE.MADD:
        case OPCODE.MSUB:
        case OPCODE.NMADD:
        case OPCODE.NMSUB:
          this.#decodeR4();
          break;

          // Invalid opcode
        default:
          throw "Invalid opcode: " + this.#opcode;
      }

    } else {
      // Otherwise, it's a compressed instruction

      // Get single xlens value for mne lookup
      if (this.#xlens === undefined) {
        // If no xlens value from Encoder, use config to determine
        switch (this.#config.ISA) {
          case COPTS_ISA.RV128I:
            this.#xlens = XLEN_MASK.rv128;
            break;
          case COPTS_ISA.RV64I:
            this.#xlens = XLEN_MASK.rv64;
            break;
          default:
            this.#xlens = XLEN_MASK.rv32;
        }
      } else {
        // Otherwise, reduce xlens to lowest allowed ISA
        for (let b = 1; b < XLEN_MASK.all; b <<= 1) {
          if (b & this.#xlens) {
            this.#xlens = b;
            break;
          }
        }
      }

      // Use opcode to determine C quadrant
      let inst, quadrant;
      this.#opcode = getBits(this.#bin, FIELDS.c_opcode.pos);
      switch (this.#opcode) {
        case C_OPCODE.C0:
          inst = this.#mneLookupC0();
          quadrant = 'C0';
          break;
        case C_OPCODE.C1:
          inst = this.#mneLookupC1();
          quadrant = 'C1';
          break;
        case C_OPCODE.C2:
          inst = this.#mneLookupC2();
          quadrant = 'C2';
          break;
        default:
          throw `Cannot decode binary instruction: ${this.bin}`;
      }
      if (inst === undefined) {
        throw `Detected quadrant ${quadrant} but could not determine instruction, potentially HINT or reserved`;
      }

      // Build ISA string from found instruction
      if (inst.xlens & XLEN_MASK.rv32) {
        this.isa = 'RV32';
      } else if (inst.xlens & XLEN_MASK.rv64) {
        this.isa = 'RV64';
      } else {
        this.isa = 'RV128';
      }
      this.isa += inst.isa;

      // Decode instruction by format
      const fmt = /^([^-]+)-/.exec(inst?.fmt)?.[1];
      switch (fmt) {
        case 'CR':
          this.#decodeCR(inst);
          break;
        case 'CI':
          this.#decodeCI(inst);
          break;
        case 'CSS':
          this.#decodeCSS(inst);
          break;
        case 'CIW':
          this.#decodeCIW(inst);
          break;
        case 'CL':
          this.#decodeCL(inst);
          break;
        case 'CS':
          this.#decodeCS(inst);
          break;
        case 'CA':
          this.#decodeCA(inst);
          break;
        case 'CB':
          this.#decodeCB(inst);
          break;
        case 'CJ':
          this.#decodeCJ(inst);
          break;
        case 'CMJT':
          this.#decodeCMJT(inst);
          break;
        case 'CMPP':
          this.#decodeCMPP(inst);
          break;
        case 'CMMV':
          this.#decodeCMMV(inst);
          break;
        default:
          throw `Internal error: Detected ${this.#mne} in quadrant ${quadrant} but could not match instruction format`;
      }
    }

    if (typeof this.#mne === undefined) {
        throw "Decoder internal error";
    }

    // Set instruction's format and ISA - vector load/store segment
    // mnemonics (vlseg3e8.v, etc.) aren't registered in ISA directly;
    // fall back to their base (nf=0) entry
    const mneInst = ISA[this.#mne] ?? ISA[vParseSegName(this.#mne)?.base];
    this.fmt = mneInst.fmt;
    this.isa = this.isa ?? mneInst.isa;

    // Detect mismatch between ISA and configuration
    if (this.#config.ISA === COPTS_ISA.RV32I && /^RV(?:64|128)/.test(this.isa)) {
      throw `Detected ${this.isa} instruction but configuration ISA set to RV32I`;
    } else if ((this.#config.ISA === COPTS_ISA.RV64I && /^RV128/.test(this.isa))) {
      throw `Detected ${this.isa} instruction but configuration ISA set to RV64I`;
    }

    // Render ASM insturction string (mainly for testing)
    this.asm = renderAsm(this.asmFrags, this.#config.ABI);
  }

  /**
   * Decodes OP instructions
   */
  #decodeOP() {
    // Get each field
    const fields = extractRFields(this.#bin);
    const funct7 = fields['funct7'],
      funct3 = fields['funct3'],
      rs2 = fields['rs2'],
      rs1 = fields['rs1'],
      rd = fields['rd'];

    // Find instruction - check opcode for RV32I vs RV64I
    let opcodeName;
    if (this.#opcode === OPCODE.OP_64) {
      // RV128I double-word-sized instructions
      this.#mne = ISA_OP_64[funct7 + funct3];
      opcodeName = "OP-64";
    } else if (this.#opcode === OPCODE.OP_32) {
      // RV64I word-sized instructions
      this.#mne = ISA_OP_32[funct7 + funct3];
      opcodeName = "OP-32";
    } else {
      // All other OP instructions
      this.#mne = ISA_OP[funct7 + funct3];
      opcodeName = "OP";
    }

    // Some crypto instructions (Zksed) carve a 2-bit "byte select" immediate
    // out of the top of funct7 (bits[31:30]), leaving only its lower 5 bits
    // (funct7base) fixed
    let bs;
    if (this.#mne === undefined && this.#opcode === OPCODE.OP) {
      this.#mne = ISA_OP_BS[funct7.substring(2) + funct3];
      bs = funct7.substring(0, 2);
    }
    if (this.#mne === undefined) {
      throw `Detected ${opcodeName} instruction but invalid funct7 and funct3 fields`;
    }

    // Convert fields to string representations
    const src1 = decReg(rs1),
          src2 = decReg(rs2),
          dest = decReg(rd);

    // Create fragments
    const f = {
      opcode: new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.opcode.name),
      funct3: new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.funct3.name),
      funct7: new Frag(FRAG.OPC, this.#mne, bs !== undefined ? funct7.substring(2) : funct7,
        FIELDS.r_funct7.name),
      rd:     new Frag(FRAG.RD, dest, rd, FIELDS.rd.name),
      rs1:    new Frag(FRAG.RS1, src1, rs1, FIELDS.rs1.name),
      rs2:    new Frag(FRAG.RS2, src2, rs2, FIELDS.rs2.name),
    };

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['rd'], f['rs1'], f['rs2']);

    if (bs !== undefined) {
      const bsVal = decImm(bs, false);
      f['bs'] = new Frag(FRAG.IMM, bsVal, bs, FIELDS.r_bs.name);
      this.asmFrags.push(f['bs']);

      this.binFrags.push(f['bs'], f['funct7'], f['rs2'], f['rs1'], f['funct3'],
        f['rd'], f['opcode']);
      return;
    }

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['funct7'], f['rs2'], f['rs1'], f['funct3'], f['rd'],
      f['opcode']);
  }

  /**
   * Decodes OP-FP instructions
   */
  #decodeOP_FP() {
    // Get each field
    const fields = extractRFields(this.#bin);
    const funct5 = fields['funct5'],
      funct3 = fields['funct3'],
      fmt = fields['fmt'],
      rs2 = fields['rs2'],
      rs1 = fields['rs1'],
      rd = fields['rd'];

    // Find instruction - check opcode for RV32I vs RV64I
    let opcodeName;
    this.#mne = ISA_OP_FP[funct5]?.[fmt];
    if (this.#mne !== undefined && typeof this.#mne !== 'string') {
      if (this.#mne[rs2] !== undefined) {
        // fcvt instructions - use rs2 as lookup
        this.#mne = this.#mne[rs2];
      } else {
        // others - use funct3 as lookup
        this.#mne = this.#mne[funct3];
      }
    }
    if (this.#mne === undefined) {
      throw 'Detected OP-FP instruction but invalid funct and fmt fields';
    }

    // Convert fields to string representations
    const inst = ISA[this.#mne];
    const useRs2 = inst.rs2 === undefined;
    const useFli = inst.rs1Fli === true;
    let floatRd = true;
    let floatRs1 = true;
    let floatRs2 = inst.rs2Int !== true;
    if (funct5[0] === '1') {
      // Conditionally decode rd or rs1 as an int register, based on funct7
      if (funct5[3] === '1') {
        floatRs1 = false;
      } else {
        floatRd = false;
      }
    }
    const src1 = useFli ? decFli(rs1) : decReg(rs1, floatRs1),
          src2 = decReg(rs2, floatRs2),
          dest = decReg(rd, floatRd);

    // Create fragments
    const useRm = inst.funct3 === undefined;
    const f = {
      opcode: new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.opcode.name),
      funct3: new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.funct3.name),
      funct5: new Frag(FRAG.OPC, this.#mne, funct5, FIELDS.r_funct5.name),
      fmt:    new Frag(FRAG.OPC, this.#mne, fmt, FIELDS.r_fp_fmt.name),
      rd:     new Frag(FRAG.RD, dest, rd, FIELDS.rd.name),
      rs1:    new Frag(FRAG.RS1, src1, rs1, useFli ? FIELDS.r_fli.name : FIELDS.rs1.name),
      rs2:    new Frag(FRAG.OPC, src2, rs2, FIELDS.rs2.name),
    };

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['rd'], f['rs1']);
    if (useRs2) {
      f['rs2'].id = FRAG.RS2;
      this.asmFrags.push(f['rs2']);
    }
    if (useRm) {
      f['funct3'].field = FIELDS.r_fp_rm.name;
      const frm = decFrm(funct3);
      // Push frm assembly operand unless using "dyn" dynamic mode
      if (frm !== 'dyn') {
        f['funct3'].id = FRAG.FRM;
        f['funct3'].asm = frm;
        this.asmFrags.push(f['funct3']);
      }
    }

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['funct5'], f['fmt'], f['rs2'], f['rs1'], f['funct3'], f['rd'],
      f['opcode']);
  }

  /**
   * Decodes JALR instructions
   */
  #decodeJALR() {
    // Get fields
    const fields = extractIFields(this.#bin);
    const imm = fields['imm'],
      rs1 = fields['rs1'],
      funct3 = fields['funct3'],
      rd = fields['rd'];

    this.#mne = 'jalr';

    // Convert fields to string representations
    const base = decReg(rs1),
          dest = decReg(rd),
          offset = decImm(imm);

    // Create fragments
    const f = {
      opcode: new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.opcode.name),
      funct3: new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.funct3.name),
      rd:     new Frag(FRAG.RD, dest, rd, FIELDS.rd.name),
      rs1:    new Frag(FRAG.RS1, base, rs1, FIELDS.rs1.name, true),
      imm:    new Frag(FRAG.IMM, offset, imm, FIELDS.i_imm_11_0.name),
    };

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['rd'], f['imm'], f['rs1']);

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['imm'], f['rs1'], f['funct3'], f['rd'], f['opcode']);
  }

  /**
   * Decodes LOAD instructions
   */
  #decodeLOAD() {
    // Get fields
    const fields = extractIFields(this.#bin);
    const imm = fields['imm'],
      rs1 = fields['rs1'],
      funct3 = fields['funct3'],
      rd = fields['rd'];

    // Vector loads share this opcode but use width codes disjoint from
    // FP_WIDTH's H/S/D/Q (001-100), so funct3 alone disambiguates them
    if (this.#opcode === OPCODE.LOAD_FP && V_EEW[funct3] !== undefined) {
      this.#decodeVMem(true);
      return;
    }

    // Find instruction
    const floatInst = this.#opcode === OPCODE.LOAD_FP;
    this.#mne = floatInst ? ISA_LOAD_FP[funct3] : ISA_LOAD[funct3];
    if (this.#mne === undefined) {
      throw `Detected LOAD${floatInst ? '-FP' : ''} `
        + 'instruction but invalid funct3 field';
    }

    // Zilsd: under explicit RV32I config, 'ld' loads a 64-bit value into
    // an even/odd register pair (rd, rd+1) instead of RV64I's single
    // 64-bit register - bit-identical encoding, so this can only be
    // resolved from the active config, not the bits themselves
    if (this.#mne === 'ld' && this.#config.ISA === COPTS_ISA.RV32I) {
      if (parseInt(rd, BASE.bin) % 2 !== 0) {
        throw `Detected ld instruction with odd destination register x${parseInt(rd, BASE.bin)}: `
          + 'register pair (Zilsd) requires an even register, odd is reserved';
      }
      this.isa = 'RV32Zilsd';
    }

    // Convert fields to string representations
    const base = decReg(rs1),
          dest = decReg(rd, floatInst),
          offset = decImm(imm);

    // Create fragments
    const f = {
      opcode: new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.opcode.name),
      funct3: new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.funct3.name),
      rd:     new Frag(FRAG.RD, dest, rd, FIELDS.rd.name),
      rs1:    new Frag(FRAG.RS1, base, rs1, FIELDS.rs1.name, true),
      imm:    new Frag(FRAG.IMM, offset, imm, FIELDS.i_imm_11_0.name),
    };

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['rd'], f['imm'], f['rs1']);

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['imm'], f['rs1'], f['funct3'], f['rd'], f['opcode']);
  }

  /**
   * Decodes OP_IMM instructions
   */
  #decodeOP_IMM() {
    // Get fields
    const fields = extractIFields(this.#bin);
    const imm = fields['imm'],
      rs1 = fields['rs1'],
      funct3 = fields['funct3'],
      rd = fields['rd'];

    // Find instruction - check opcode for RV32I vs RV64I
    let opcodeName, table;
    const op_imm_32 = this.#opcode === OPCODE.OP_IMM_32;
    const op_imm_64 = this.#opcode === OPCODE.OP_IMM_64;
    if(op_imm_64) {
      // RV128I double-word-sized instructions
      table = ISA_OP_IMM_64[funct3];
      opcodeName = "OP-IMM-64";
    } else if(op_imm_32) {
      // RV64I word-sized instructions
      table = ISA_OP_IMM_32[funct3];
      opcodeName = "OP-IMM-32";
    } else {
      // All other OP-IMM instructions
      table = ISA_OP_IMM[funct3];
      opcodeName = "OP-IMM";
    }
    if (table === undefined) {
      throw `Detected ${opcodeName} instruction but invalid funct3 field`;
    }

    if (typeof table === 'string') {
      this.#mne = table;
    } else {
      // Instructions sharing a funct3 are disambiguated by a fixed-width prefix
      // of imm[11:0] (width implied by the table's own key length), possibly
      // nested further for instructions sharing that same prefix too (e.g.
      // aes64im/aes64ks1i, which share a 6-bit prefix but need a further
      // 2-bit split before aes64ks1i's variable rnum bits are reached)
      let entry = table, consumed = 0;
      while (typeof entry !== 'string') {
        const width = Object.keys(entry)[0].length;
        const next = entry[imm.substring(consumed, consumed + width)];
        if (next === undefined) {
          throw `Detected ${opcodeName} instruction but invalid funct6/funct7/funct12 field`;
        }
        entry = next;
        consumed += width;
      }
      this.#mne = entry;
    }
    const inst = ISA[this.#mne];

    // Convert fields to string representations
    const src = decReg(rs1),
          dest = decReg(rd);

    // Create fragments
    const f = {
      opcode: new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.opcode.name),
      funct3: new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.funct3.name),
      rd:     new Frag(FRAG.RD, dest, rd, FIELDS.rd.name),
      rs1:    new Frag(FRAG.RS1, src, rs1, FIELDS.rs1.name),
    };

    if (inst.funct12 !== undefined) {
      // Fully-fixed immediate instructions (clz, ctz, cpop, sext.b/h, orc.b, rev8, ...)
      //   imm[11:0] carries no user-supplied value; rd/rs1 are the only operands
      f['imm'] = new Frag(FRAG.OPC, this.#mne, imm, FIELDS.i_funct12.name);

      this.asmFrags.push(f['opcode'], f['rd'], f['rs1']);
      this.binFrags.push(f['imm'], f['rs1'], f['funct3'], f['rd'], f['opcode']);
      return;

    } else if (inst.funct6 !== undefined) {
      // Bit-manipulation shift-amount instructions (Zba/Zbb/Zbs): fixed 6-bit
      //   prefix (imm[11:6]) plus a 6-bit shift amount (imm[5:0])
      const funct6 = imm.substring(0, 6);
      const shamtBits = imm.substring(6);
      if (funct6 !== inst.funct6) {
        throw `Detected ${this.#mne} instruction but invalid funct6 field`;
      }
      const shamt = decImm(shamtBits, false);

      f['imm'] = new Frag(FRAG.IMM, shamt, shamtBits, FIELDS.i_shamt_5_0.name);
      f['shift'] = new Frag(FRAG.OPC, this.#mne, funct6, FIELDS.i_funct6.name);

      this.asmFrags.push(f['opcode'], f['rd'], f['rs1'], f['imm']);
      this.binFrags.push(f['shift'], f['imm'], f['rs1'], f['funct3'], f['rd'], f['opcode']);
      return;

    } else if (inst.funct7 !== undefined) {
      // Bit-manipulation word shift-amount instructions (roriw): fixed 7-bit
      //   prefix (imm[11:5]) plus a 5-bit shift amount (imm[4:0])
      const funct7 = imm.substring(0, 7);
      const shamtBits = imm.substring(7);
      if (funct7 !== inst.funct7) {
        throw `Detected ${this.#mne} instruction but invalid funct7 field`;
      }
      const shamt = decImm(shamtBits, false);

      f['imm'] = new Frag(FRAG.IMM, shamt, shamtBits, FIELDS.i_shamt.name);
      f['shift'] = new Frag(FRAG.OPC, this.#mne, funct7, FIELDS.r_funct7.name);

      this.asmFrags.push(f['opcode'], f['rd'], f['rs1'], f['imm']);
      this.binFrags.push(f['shift'], f['imm'], f['rs1'], f['funct3'], f['rd'], f['opcode']);
      return;

    } else if (inst.funct8 !== undefined) {
      // Round-number instructions (aes64ks1i): fixed 8-bit prefix (imm[11:4])
      //   plus a 4-bit round-number immediate (imm[3:0])
      const funct8 = imm.substring(0, 8);
      const rnumBits = imm.substring(8);
      if (funct8 !== inst.funct8) {
        throw `Detected ${this.#mne} instruction but invalid funct8 field`;
      }
      const rnum = decImm(rnumBits, false);

      f['imm'] = new Frag(FRAG.IMM, rnum, rnumBits, FIELDS.i_rnum.name);
      f['shift'] = new Frag(FRAG.OPC, this.#mne, funct8, FIELDS.i_funct8.name);

      this.asmFrags.push(f['opcode'], f['rd'], f['rs1'], f['imm']);
      this.binFrags.push(f['shift'], f['imm'], f['rs1'], f['funct3'], f['rd'], f['opcode']);
      return;
    }

    // Shift instructions
    const shift = (inst.shtyp !== undefined);

    if (shift) {
      const shtyp = fields['shtyp'];
      const shamt_6 = fields['shamt_6'];
      const shamt_5 = fields['shamt_5'];
      const shamt_4_0 = fields['shamt'];
      const shamt_5_0 = shamt_5 + shamt_4_0;
      const shamt_6_0 = shamt_6 + shamt_5_0;


      const imm_11_7 = '0' + shtyp + '000';
      const imm_11_6 = imm_11_7 + '0';
      const imm_11_5 = imm_11_6 + '0';

      // Decode shamt
      const shamt = decImm(shamt_6_0, false);

      // Determine shamtWidth (5, 6, or 7 bits) based on opcode, ISA, and value
      // - First, opcode based determination
      // - Then, ISA and value based determination
      let shamtWidth;
      if (op_imm_32) {
        shamtWidth = 5;
      } else if (op_imm_64) {
        shamtWidth = 6;
        this.isa = 'RV128I';  // Set ISA here to avoid assumed ISA of RV64I below
      } else if (this.#config.ISA === COPTS_ISA.RV32I ||
                (this.#config.ISA === COPTS_ISA.AUTO && shamt_6 === '0' && shamt_5 === '0')) {
        shamtWidth = 5;
      } else if (this.#config.ISA === COPTS_ISA.RV64I ||
                (this.#config.ISA === COPTS_ISA.AUTO && shamt_6 === '0')) {
        shamtWidth = 6;
      } else {
        shamtWidth = 7;
      }

      // Detect shamt out of range
      if (shamt >= 32 && shamtWidth === 5) {
        throw `Invalid shamt field: ${shamt} (out of range for opcode or ISA config)`;
      } else if (shamt >= 64 && shamtWidth === 6) {
        throw `Invalid shamt field: ${shamt} (out of range for opcode or ISA config)`;
      }

      // Create frags for shamt and shtyp
      if (shamtWidth === 7) {
        // Create frags for 7bit shamt with shtyp
        const shamt_6_0 = shamt_6 + shamt_5 + shamt_4_0;

        // Create frags for shamt and shtyp
        f['imm'] = new Frag(FRAG.IMM, shamt, shamt_6_0, FIELDS.i_shamt_6_0.name);
        f['shift'] = new Frag(FRAG.OPC, this.#mne, imm_11_7, FIELDS.i_shtyp_11_7.name);

        // Set output ISA to RV64I
        this.isa = 'RV128I';

      } else if (shamtWidth === 6) {
        // Create frags for 6bit shamt with shtyp
        const shamt_5_0 = shamt_5 + shamt_4_0;

        // Create frags for shamt and shtyp
        f['imm'] = new Frag(FRAG.IMM, shamt, shamt_5_0, FIELDS.i_shamt_5_0.name);
        f['shift'] = new Frag(FRAG.OPC, this.#mne, imm_11_6, FIELDS.i_shtyp_11_6.name);

        // Set output ISA to RV64I
        this.isa = this.isa ?? 'RV64I';

      } else {
        // Create frags for 5bit shamt with shtyp
        f['imm'] = new Frag(FRAG.IMM, shamt, shamt_4_0, FIELDS.i_shamt.name);
        f['shift'] = new Frag(FRAG.OPC, this.#mne, imm_11_5, FIELDS.i_shtyp_11_5.name);
      }

      // Validate upper bits of immediate field to ensure
      //   they match expected value for shift type
      if((shamtWidth === 5 && imm_11_5 !== imm.substring(0,7))
          || (shamtWidth === 6 && imm_11_6 !== imm.substring(0,6))
          || (shamtWidth === 7 && imm_11_7 !== imm.substring(0,5))) {
        throw `Detected ${this.isa} shift immediate instruction but invalid shtyp field`;
      }

      // Binary fragments from MSB to LSB
      this.binFrags.push(f['shift'], f['imm'], f['rs1'],
        f['funct3'], f['rd'], f['opcode']);

    } else {
      const imm = fields['imm'];
      const immediate = decImm(imm);

      f['imm'] = new Frag(FRAG.IMM, immediate, imm, FIELDS.i_imm_11_0.name);

      // Binary fragments from MSB to LSB
      this.binFrags.push(f['imm'], f['rs1'], f['funct3'], f['rd'], f['opcode']);
    }

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['rd'], f['rs1'], f['imm']);
  }

  /**
   * Decode MISC_MEM instructions
   */
  #decodeMISC_MEM() {
    // Get fields
    const fields = extractIFields(this.#bin);
    const imm = fields['imm'],
      fm = fields['fm'],
      pred = fields['pred'],
      succ = fields['succ'],
      rs1 = fields['rs1'],
      funct3 = fields['funct3'],
      rd = fields['rd'];

    // Find instruction
    this.#mne = ISA_MISC_MEM[funct3];
    if (this.#mne === undefined) {
      throw "Detected MISC-MEM instruction but invalid funct3 field";
    }
    if (typeof this.#mne !== 'string') {
      // This funct3 is shared between RV128I's lq (variable imm, rd can be
      // any register) and the Zicbo cache-block instructions (fixed imm,
      // rd fixed to 0, rs1-only). rd=0 is required for Zicbo, so any
      // non-zero rd is unambiguously lq; only consult the imm-keyed Zicbo
      // table when rd=0, and still default to lq if nothing matches there
      this.#mne = rd === '00000' ? (this.#mne[imm] ?? 'lq') : 'lq';
    }
    // Signals when MISC-MEM used as extended encoding space for load operations
    let loadExt = this.#mne === 'lq';
    // Signals a Zicbo cache-block instruction (fixed imm, rs1-only)
    let cbo = this.#mne.startsWith('cbo.');

    // Check registers
    if (!loadExt && !cbo && (rd !== '00000' || rs1 !== '00000')) {
      throw "Registers rd and rs1 should be 0";
    }
    if (cbo && rd !== '00000') {
      throw "Register rd should be 0";
    }

    // Create common fragments
    const f = {
      opcode: new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.opcode.name),
      funct3: new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.funct3.name),
    };

    // Create specific fragments
    if (loadExt) {
      // Load extension instructions

      // Convert fields to string representations
      const offset = decImm(imm),
            base = decReg(rs1),
            dest = decReg(rd);


      f['imm'] = new Frag(FRAG.IMM, offset, imm, FIELDS.i_imm_11_0.name);
      f['rs1'] = new Frag(FRAG.RS1, base, rs1, FIELDS.rs1.name, true);
      f['rd']  = new Frag(FRAG.RD, dest, rd, FIELDS.rd.name);

      // Assembly fragments in order of instruction
      this.asmFrags.push(f['opcode'], f['rd'], f['imm'], f['rs1']);

      // Binary fragments from MSB to LSB
      this.binFrags.push(f['imm'], f['rs1'], f['funct3'], f['rd'], f['opcode']);

    } else if (cbo) {
      // Zicbo cache-block instructions: fixed imm, rs1 is the only operand

      const base = decReg(rs1);

      f['imm'] = new Frag(FRAG.UNSD, this.#mne, imm, FIELDS.i_imm_11_0.name);
      f['rs1'] = new Frag(FRAG.RS1, base, rs1, FIELDS.rs1.name, true);
      f['rd']  = new Frag(FRAG.UNSD, this.#mne, rd, FIELDS.rd.name);

      // Assembly fragments in order of instruction
      this.asmFrags.push(f['opcode'], f['rs1']);

      // Binary fragments from MSB to LSB
      this.binFrags.push(f['imm'], f['rs1'], f['funct3'], f['rd'], f['opcode']);

    } else if (this.#mne === 'fence') {
      // FENCE instruction

      // Convert fields to string representations
      let predecessor = decMem(pred);
      let successor = decMem(succ);

      f['fm']   = new Frag(FRAG.OPC, this.#mne, fm, FIELDS.i_fm.name);
      f['pred'] = new Frag(FRAG.PRED, predecessor, pred, FIELDS.i_pred.name);
      f['succ'] = new Frag(FRAG.SUCC, successor, succ, FIELDS.i_succ.name);
      f['rd']  = new Frag(FRAG.OPC, this.#mne, rd, FIELDS.rd.name);
      f['rs1'] = new Frag(FRAG.OPC, this.#mne, rs1, FIELDS.rs1.name, loadExt);

      // Assembly fragments in order of instruction
      this.asmFrags.push(f['opcode'], f['pred'], f['succ']);

      // Binary fragments from MSB to LSB
      this.binFrags.push(f['fm'], f['pred'], f['succ'], f['rs1'], f['funct3'],
        f['rd'], f['opcode']);

    } else if (this.#mne === 'fence.i') {
      // FENCE.I instruction

      f['imm'] = new Frag(FRAG.UNSD, this.#mne, imm, FIELDS.i_imm_11_0.name);
      f['rs1'] = new Frag(FRAG.UNSD, this.#mne, rs1, FIELDS.rs1.name);
      f['rd']  = new Frag(FRAG.UNSD, this.#mne, rd, FIELDS.rd.name);

      // Assembly fragments in order of instruction
      this.asmFrags.push(f['opcode']);

      // Binary fragments from MSB to LSB
      this.binFrags.push(f['imm'], f['rs1'], f['funct3'], f['rd'], f['opcode']);
    }
  }

  /**
   * Decode SYSTEM instructions
   */
  #decodeSYSTEM() {
    // Get fields
    const fields = extractIFields(this.#bin);
    const funct12 = fields['imm'],
      rs1 = fields['rs1'],
      funct3 = fields['funct3'],
      rd = fields['rd'];

    // Find instruction
    this.#mne = ISA_SYSTEM[funct3];
    if (this.#mne === undefined) {
      throw "Detected SYSTEM instruction but invalid funct3 field";
    }

    // Trap instructions - determine mnemonic from funct12
    let trap = (typeof this.#mne !== 'string');
    // R-type-like instructions (Svinval's sinval.vma/hinval.vvma/
    // hinval.gvma, H's hsv.*/hfence.vvma/hfence.gvma, Zimop's mop.rr.N):
    // fixed 7-bit funct7 (the top of what would otherwise be funct12), with
    // rs1/rs2 as real registers; rd is fixed to 0 unless ISA[mne].realRd
    let rTypeLike = false;
    // Marks mnemonics whose rd (and, for the funct12-exact shape, rs1 too)
    // are real registers rather than fixed to 0 - Zimop's mop.r.N/mop.rr.N
    // and H's hlv.*
    let realRd = false;
    if (trap) {
      this.#mne = this.#mne[funct12];
      if (this.#mne === undefined) {
        this.#mne = ISA_SYSTEM[funct3][funct12.substring(0, 7)];
        rTypeLike = this.#mne !== undefined;
      }
      if (this.#mne === undefined) {
        throw "Detected SYSTEM instruction but invalid funct12 field";
      }
      realRd = ISA[this.#mne].realRd === true;
      // Check registers
      if (!realRd &&
          (rTypeLike ? rd !== '00000' : (rd !== '00000' || rs1 !== '00000'))) {
        throw "Register rd should be 0 for mne " + this.#mne;
      }
    }

    // Create common fragments
    const f = {
      opcode: new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.opcode.name),
      funct3: new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.funct3.name),
    };

    // Zimop mop.rr.N - full R-type, rd/rs1/rs2 all real registers
    if (rTypeLike && realRd) {
      const funct7 = funct12.substring(0, 7),
        rs2 = funct12.substring(7);
      const dest = decReg(rd), src1 = decReg(rs1), src2 = decReg(rs2);

      f['funct7'] = new Frag(FRAG.OPC, this.#mne, funct7, FIELDS.r_funct7.name);
      f['rs2'] = new Frag(FRAG.RS2, src2, rs2, FIELDS.rs2.name);
      f['rs1'] = new Frag(FRAG.RS1, src1, rs1, FIELDS.rs1.name);
      f['rd']  = new Frag(FRAG.RD, dest, rd, FIELDS.rd.name);

      // Assembly fragments in order of instruction
      this.asmFrags.push(f['opcode'], f['rd'], f['rs1'], f['rs2']);

      // Binary fragments from MSB to LSB
      this.binFrags.push(f['funct7'], f['rs2'], f['rs1'], f['funct3'], f['rd'],
        f['opcode']);

    // Svinval-like instructions / H's hsv.* - create specific fragments and render
    } else if (rTypeLike) {
      const funct7 = funct12.substring(0, 7),
        rs2 = funct12.substring(7);
      const src1 = decReg(rs1), src2 = decReg(rs2);
      const mem = ISA[this.#mne].mem === true;

      f['funct7'] = new Frag(FRAG.OPC, this.#mne, funct7, FIELDS.r_funct7.name);
      f['rs2'] = new Frag(FRAG.RS2, src2, rs2, FIELDS.rs2.name);
      f['rs1'] = new Frag(FRAG.RS1, src1, rs1, FIELDS.rs1.name, mem);
      f['rd']  = new Frag(FRAG.UNSD, this.#mne, rd, FIELDS.rd.name);

      // Assembly fragments in order of instruction - hsv.* is store-like
      // ("hsv.b rs2, (rs1)"), the others take a plain "rs1, rs2" pair
      if (mem) {
        this.asmFrags.push(f['opcode'], f['rs2'], f['rs1']);
      } else {
        this.asmFrags.push(f['opcode'], f['rs1'], f['rs2']);
      }

      // Binary fragments from MSB to LSB
      this.binFrags.push(f['funct7'], f['rs2'], f['rs1'], f['funct3'], f['rd'],
        f['opcode']);

    // Zimop mop.r.N / H's hlv.* - I-type, funct12 fixed, rd/rs1 real registers
    } else if (realRd) {
      const dest = decReg(rd), src = decReg(rs1);
      const mem = ISA[this.#mne].mem === true;

      f['rd'] = new Frag(FRAG.RD, dest, rd, FIELDS.rd.name);
      f['rs1'] = new Frag(FRAG.RS1, src, rs1, FIELDS.rs1.name, mem);
      f['funct12'] = new Frag(FRAG.OPC, this.#mne, funct12, FIELDS.i_funct12.name);

      // Assembly fragments in order of instruction
      this.asmFrags.push(f['opcode'], f['rd'], f['rs1']);

      // Binary fragments from MSB to LSB
      this.binFrags.push(f['funct12'], f['rs1'], f['funct3'], f['rd'],
        f['opcode']);

    // Trap instructions - create specific fragments and render
    } else if (trap) {
      // Create remaining fragments
      f['rd'] = new Frag(FRAG.OPC, this.#mne, rd, FIELDS.rd.name);
      f['rs1'] = new Frag(FRAG.OPC, this.#mne, rs1, FIELDS.rs1.name);
      f['funct12'] = new Frag(FRAG.OPC, this.#mne, funct12, FIELDS.i_funct12.name);

      // Assembly fragments in order of instruction
      this.asmFrags.push(f['opcode']);

      // Binary fragments from MSB to LSB
      this.binFrags.push(f['funct12'], f['rs1'], f['funct3'], f['rd'],
        f['opcode']);

    } else {
      // Zicsr instructions

      // Alias already extracted field for clarity
      const csrBin = funct12;

      // Convert fields to string types
      const dest = decReg(rd),
            csr = decCSR(csrBin);

      // Convert rs1 to register or immediate
      //   based off high bit of funct3 (0:reg, 1:imm)
      let src, srcFieldName;
      if (funct3[0] === '0') {
        src = decReg(rs1);
        srcFieldName = FIELDS.rs1.name;
      } else {
        src = decImm(rs1, false);
        srcFieldName = FIELDS.i_imm_4_0.name;
      }

      // Create remaining fragments
      f['rd'] = new Frag(FRAG.RD, dest, rd, FIELDS.rd.name);
      f['csr'] = new Frag(FRAG.CSR, csr, csrBin, FIELDS.i_csr.name);
      f['rs1'] = new Frag(FRAG.RS1, src, rs1, srcFieldName);

      // Assembly fragments in order of instruction
      this.asmFrags.push(f['opcode'], f['rd'], f['csr'], f['rs1']);

      // Binary fragments from MSB to LSB
      this.binFrags.push(f['csr'], f['rs1'], f['funct3'], f['rd'],
        f['opcode']);
    }
  }

  /**
   * Decodes STORE instruction
   */
  #decodeSTORE() {
    // Vector stores share this opcode but use width codes disjoint from
    // FP_WIDTH's H/S/D/Q (001-100), so funct3 alone disambiguates them
    const vFunct3 = getBits(this.#bin, FIELDS.funct3.pos);
    if (this.#opcode === OPCODE.STORE_FP && V_EEW[vFunct3] !== undefined) {
      this.#decodeVMem(false);
      return;
    }

    // Get fields
    const fields = extractSFields(this.#bin);
    const imm_11_5 = fields['imm_11_5'],
      rs2 = fields['rs2'],
      rs1 = fields['rs1'],
      funct3 = fields['funct3'],
      imm_4_0 = fields['imm_4_0'],
      imm = imm_11_5 + imm_4_0;

    // Find instruction
    const floatInst = this.#opcode === OPCODE.STORE_FP;
    this.#mne = floatInst ? ISA_STORE_FP[funct3] : ISA_STORE[funct3];
    if (this.#mne === undefined) {
      throw `Detected STORE${floatInst ? '-FP' : ''} `
        + 'instruction but invalid funct3 field';
    }

    // Zilsd: under explicit RV32I config, 'sd' stores a 64-bit value from
    // an even/odd register pair (rs2, rs2+1) instead of RV64I's single
    // 64-bit register - see the matching note in #decodeLOAD
    if (this.#mne === 'sd' && this.#config.ISA === COPTS_ISA.RV32I) {
      if (parseInt(rs2, BASE.bin) % 2 !== 0) {
        throw `Detected sd instruction with odd source register x${parseInt(rs2, BASE.bin)}: `
          + 'register pair (Zilsd) requires an even register, odd is reserved';
      }
      this.isa = 'RV32Zilsd';
    }

    // Convert fields to string representations
    const offset = decImm(imm);
    const base = decReg(rs1);
    const src = decReg(rs2, floatInst);

    // Create common fragments
    const f = {
      opcode:   new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.opcode.name),
      funct3:   new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.funct3.name),
      rs1:      new Frag(FRAG.RS1, base, rs1, FIELDS.rs1.name, true),
      rs2:      new Frag(FRAG.RS2, src, rs2, FIELDS.rs2.name),
      imm_4_0:  new Frag(FRAG.IMM, offset, imm_4_0, FIELDS.s_imm_4_0.name),
      imm_11_5: new Frag(FRAG.IMM, offset, imm_11_5, FIELDS.s_imm_11_5.name),
      imm:      new Frag(FRAG.IMM, offset, imm, 'imm'),
    };

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['rs2'], f['imm'], f['rs1']);

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['imm_11_5'], f['rs2'], f['rs1'], f['funct3'],
      f['imm_4_0'], f['opcode']);
  }

  /**
   * Decodes BRANCH instruction
   */
  #decodeBRANCH() {
    // Get fields
    const fields = extractBFields(this.#bin);
    const imm_12 = fields['imm_12'],
      imm_10_5 = fields['imm_10_5'],
      rs2 = fields['rs2'],
      rs1 = fields['rs1'],
      funct3 = fields['funct3'],
      imm_4_1 = fields['imm_4_1'],
      imm_11 = fields['imm_11'];

    // Reconstitute immediate
    const imm = imm_12 + imm_11 + imm_10_5 + imm_4_1 + '0';

    // Find instruction
    this.#mne = ISA_BRANCH[funct3];
    if (this.#mne === undefined) {
      throw "Detected BRANCH instruction but invalid funct3 field";
    }

    // Convert fields to string representations
    const offset = decImm(imm),
          src2 = decReg(rs2),
          src1 = decReg(rs1);

    // Create fragments
    const f = {
      opcode:   new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.opcode.name),
      funct3:   new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.funct3.name),
      rs1:      new Frag(FRAG.RS1, src1, rs1, FIELDS.rs1.name),
      rs2:      new Frag(FRAG.RS2, src2, rs2, FIELDS.rs2.name),
      imm_12:   new Frag(FRAG.IMM, offset, imm_12, FIELDS.b_imm_12.name),
      imm_11:   new Frag(FRAG.IMM, offset, imm_11, FIELDS.b_imm_11.name),
      imm_10_5: new Frag(FRAG.IMM, offset, imm_10_5, FIELDS.b_imm_10_5.name),
      imm_4_1:  new Frag(FRAG.IMM, offset, imm_4_1, FIELDS.b_imm_4_1.name),
      imm:      new Frag(FRAG.IMM, offset, imm, 'imm'),
    };

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['rs1'], f['rs2'], f['imm']);

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['imm_12'], f['imm_10_5'], f['rs2'], f['rs1'],
      f['funct3'], f['imm_4_1'], f['imm_11'], f['opcode']);
  }

  /**
   * Decodes U-type instruction
   */
  #decodeUType() {
    // Get fields
    const imm_31_12 = getBits(this.#bin, FIELDS.u_imm_31_12.pos);
    const rd = getBits(this.#bin, FIELDS.rd.pos);

    // Convert fields to string representations
    const immediate = decImm(imm_31_12), dest = decReg(rd);

    // Determine operation
    this.#mne = (this.#opcode === OPCODE.AUIPC) ? 'auipc' : 'lui';

    // Create fragments
    const f = {
      opcode:     new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.opcode.name),
      rd:         new Frag(FRAG.RD, dest, rd, FIELDS.rd.name),
      imm_31_12:  new Frag(FRAG.IMM, immediate, imm_31_12, FIELDS.u_imm_31_12.name),
    };

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['rd'], f['imm_31_12']);

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['imm_31_12'], f['rd'], f['opcode']);
  }

  /**
   * Decodes JAL instruction
   */
  #decodeJAL() {
    // Get fields
    const imm_20 = getBits(this.#bin, FIELDS.j_imm_20.pos);
    const imm_10_1 = getBits(this.#bin, FIELDS.j_imm_10_1.pos);
    const imm_11 = getBits(this.#bin, FIELDS.j_imm_11.pos);
    const imm_19_12 = getBits(this.#bin, FIELDS.j_imm_19_12.pos);
    const rd = getBits(this.#bin, FIELDS.rd.pos);

    // Reconstitute immediate
    const imm = imm_20 + imm_19_12 + imm_11 + imm_10_1 + '0';

    this.#mne = 'jal';

    // Convert fields to string representations
    const offset = decImm(imm);
    const dest = decReg(rd);

    // Create fragments
    const f = {
      opcode:     new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.opcode.name),
      rd:         new Frag(FRAG.RD, dest, rd, FIELDS.rd.name),
      imm_20:     new Frag(FRAG.IMM, offset, imm_20, FIELDS.j_imm_20.name),
      imm_10_1:   new Frag(FRAG.IMM, offset, imm_10_1, FIELDS.j_imm_10_1.name),
      imm_11:     new Frag(FRAG.IMM, offset, imm_11, FIELDS.j_imm_11.name),
      imm_19_12:  new Frag(FRAG.IMM, offset, imm_19_12, FIELDS.j_imm_19_12.name),
      imm:        new Frag(FRAG.IMM, offset, imm, 'imm'),
    };

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['rd'], f['imm']);

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['imm_20'], f['imm_10_1'], f['imm_11'], f['imm_19_12'],
      f['rd'], f['opcode']);
  }

  /**
   * Decodes OP-V (vector) instructions
   */
  #decodeOP_V() {
    const funct3 = getBits(this.#bin, FIELDS.funct3.pos);

    if (funct3 === '111') {
      this.#decodeVCFG();
      return;
    }
    if (ISA_OP_V_ARITH[funct3] !== undefined) {
      this.#decodeVArith(funct3);
      return;
    }

    throw 'Detected OP-V instruction with unsupported funct3 (vector ' +
      'arithmetic instructions not yet supported)';
  }

  // vsetvli/vsetivli/vsetvl: distinguished by bit31 (and bit30 for
  // vsetivli vs vsetvli), each with its own field layout
  #decodeVCFG() {
    const rd = getBits(this.#bin, FIELDS.rd.pos);
    const funct3 = getBits(this.#bin, FIELDS.funct3.pos);
    const bit31 = this.#bin[0];
    const dest = decReg(rd);

    const f = {
      opcode: new Frag(FRAG.OPC, '', this.#opcode, FIELDS.opcode.name),
      funct3: new Frag(FRAG.OPC, '', funct3, FIELDS.funct3.name),
      rd:     new Frag(FRAG.RD, dest, rd, FIELDS.rd.name),
    };

    if (bit31 === '0') {
      // vsetvli rd, rs1, vtypei
      this.#mne = 'vsetvli';
      const zimm11 = getBits(this.#bin, FIELDS.v_zimm11.pos);
      const rs1 = getBits(this.#bin, FIELDS.rs1.pos);
      const src = decReg(rs1);
      const vtype = decVtype(zimm11);

      f['opcode'].asm = f['funct3'].asm = this.#mne;
      f['bit31'] = new Frag(FRAG.OPC, this.#mne, bit31, 'bit31');
      f['zimm11'] = new Frag(FRAG.IMM, vtype.join(','), zimm11, FIELDS.v_zimm11.name);
      f['rs1'] = new Frag(FRAG.RS1, src, rs1, FIELDS.rs1.name);

      this.asmFrags.push(f['opcode'], f['rd'], f['rs1']);
      for (const tok of vtype) {
        this.asmFrags.push(new Frag(FRAG.IMM, tok, zimm11, FIELDS.v_zimm11.name));
      }
      this.binFrags.push(f['bit31'], f['zimm11'], f['rs1'], f['funct3'],
        f['rd'], f['opcode']);
    } else if (this.#bin[1] === '1') {
      // vsetivli rd, uimm, vtypei
      this.#mne = 'vsetivli';
      const zimm10 = getBits(this.#bin, FIELDS.v_zimm10.pos);
      const zimm5 = getBits(this.#bin, FIELDS.v_zimm5.pos);
      const uimm = decImm(zimm5, false);
      const vtype = decVtype(zimm10);

      f['opcode'].asm = f['funct3'].asm = this.#mne;
      f['bit31_30'] = new Frag(FRAG.OPC, this.#mne, this.#bin.substring(0, 2), 'bit31:30');
      f['zimm10'] = new Frag(FRAG.IMM, vtype.join(','), zimm10, FIELDS.v_zimm10.name);
      f['zimm5'] = new Frag(FRAG.IMM, uimm, zimm5, FIELDS.v_zimm5.name);

      this.asmFrags.push(f['opcode'], f['rd'], f['zimm5']);
      for (const tok of vtype) {
        this.asmFrags.push(new Frag(FRAG.IMM, tok, zimm10, FIELDS.v_zimm10.name));
      }
      this.binFrags.push(f['bit31_30'], f['zimm10'], f['zimm5'], f['funct3'],
        f['rd'], f['opcode']);
    } else {
      // vsetvl rd, rs1, rs2
      const funct7 = getBits(this.#bin, FIELDS.r_funct7.pos);
      if (funct7 !== ISA['vsetvl'].funct7) {
        throw 'Detected OP-V vset* instruction but invalid funct7 field';
      }
      this.#mne = 'vsetvl';
      const rs1 = getBits(this.#bin, FIELDS.rs1.pos);
      const rs2 = getBits(this.#bin, FIELDS.rs2.pos);
      const src1 = decReg(rs1), src2 = decReg(rs2);

      f['opcode'].asm = f['funct3'].asm = this.#mne;
      f['funct7'] = new Frag(FRAG.OPC, this.#mne, funct7, FIELDS.r_funct7.name);
      f['rs1'] = new Frag(FRAG.RS1, src1, rs1, FIELDS.rs1.name);
      f['rs2'] = new Frag(FRAG.RS2, src2, rs2, FIELDS.rs2.name);

      this.asmFrags.push(f['opcode'], f['rd'], f['rs1'], f['rs2']);
      this.binFrags.push(f['funct7'], f['rs2'], f['rs1'], f['funct3'],
        f['rd'], f['opcode']);
    }
  }

  // V vector arithmetic (OPIVV/OPIVX/OPIVI/OPMVV/OPMVX/OPFVV/OPFVF): all 7
  // categories share this field layout (funct6, vm, vs2, vs1/rs1/imm, vd),
  // differing only in how vs1's position is interpreted (real vector
  // register, real scalar register, or an immediate) and a handful of
  // funct6 codes needing vm or the vs1 field itself for disambiguation -
  // see ISA_OP_V_ARITH in Constants.js.
  #decodeVArith(funct3) {
    const funct6 = getBits(this.#bin, FIELDS.v_funct6.pos),
      vm = getBits(this.#bin, FIELDS.v_vm.pos),
      vs2raw = getBits(this.#bin, FIELDS.rs2.pos),
      src1raw = getBits(this.#bin, FIELDS.rs1.pos),
      vd = getBits(this.#bin, FIELDS.rd.pos);

    let entry = ISA_OP_V_ARITH[funct3][funct6];
    if (entry === undefined) {
      throw 'Detected OP-V arithmetic instruction but invalid funct6 field';
    }
    if (typeof entry !== 'string') {
      // Disambiguated by whichever field resolves it: 1-bit keys index by
      // vm, 5-bit keys by the raw vs1/simm5 field (vmv*r.v's count selector)
      const key = Object.keys(entry)[0].length === 1 ? vm : src1raw;
      entry = entry[key];
      if (entry === undefined) {
        throw 'Detected OP-V arithmetic instruction but invalid vm/vs1 field';
      }
    }
    this.#mne = entry;
    const inst = ISA[this.#mne];

    // vd: a real vector register, unless this mnemonic writes a scalar
    // register instead - integer (vmv.x.s/vcpop.m/vfirst.m) or float
    // (vfmv.f.s)
    const dest = inst.vdType === 'x' ? decReg(vd)
      : inst.vdType === 'f' ? decReg(vd, true)
      : decVReg(vd);
    const vdField = inst.vdType === 'x' ? FIELDS.rd.name : inst.vdType === 'f' ? 'fd' : 'vd';
    const f = {
      opcode: new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.opcode.name),
      funct6: new Frag(FRAG.OPC, this.#mne, funct6, FIELDS.v_funct6.name),
      vm:     new Frag(FRAG.OPC, this.#mne, vm, FIELDS.v_vm.name),
      funct3: new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.funct3.name),
      vd:     new Frag(FRAG.RD, dest, vd, vdField),
    };
    this.asmFrags.push(f['opcode'], f['vd']);

    // vs2: a real vector register, unless this mnemonic fixes it to 0
    // (vmv.v.*/vmv.s.x/vid.v, which have only one or zero real source
    // operands)
    if (inst.vs2Fixed !== undefined) {
      if (vs2raw !== inst.vs2Fixed) {
        throw `Detected ${this.#mne} with invalid vs2 field`;
      }
      f['vs2'] = new Frag(FRAG.UNSD, this.#mne, vs2raw, 'vs2');
    } else {
      const vs2 = decVReg(vs2raw);
      f['vs2'] = new Frag(FRAG.RS2, vs2, vs2raw, 'vs2');
    }

    // vs1/rs1/imm: a real operand, unless this mnemonic fixes it to a
    // selector value (vmv1r.v/.../vmv8r.v's register count, or
    // vzext.vf8/.../vid.v's opcode-within-funct6 selector)
    if (inst.vs1Fixed !== undefined) {
      f['src1'] = new Frag(FRAG.UNSD, this.#mne, src1raw, 'vs1');
    } else if (funct3 === V_CAT.IVV || funct3 === V_CAT.MVV || funct3 === V_CAT.FVV) {
      const src1 = decVReg(src1raw);
      f['src1'] = new Frag(FRAG.RS1, src1, src1raw, 'vs1');
    } else if (funct3 === V_CAT.IVX || funct3 === V_CAT.MVX) {
      const src1 = decReg(src1raw);
      f['src1'] = new Frag(FRAG.RS1, src1, src1raw, FIELDS.rs1.name);
    } else if (funct3 === V_CAT.FVF) {
      const src1 = decReg(src1raw, true);
      f['src1'] = new Frag(FRAG.RS1, src1, src1raw, 'fs1');
    } else if (inst.immType === 'zi6') {
      // vror.vi: 6-bit zero-extended immediate, split across the funct6
      // LSB ("zimm6hi", bit 26) and this 5-bit field ("zimm6lo")
      const imm = decImm(funct6[5] + src1raw, false);
      f['src1'] = new Frag(FRAG.IMM, imm, src1raw, 'zimm6lo');
    } else {
      // IVI: sign- or zero-extended 5-bit immediate, depending on this
      // mnemonic (shift amounts/gather index are zero-extended)
      const imm = decImm(src1raw, inst.immType !== 'zi');
      f['src1'] = new Frag(FRAG.IMM, imm, src1raw, inst.immType === 'zi' ? 'zimm5' : 'simm5');
    }

    // Assembly operand order: (vd, vs2, src1) normally, but the
    // multiply-accumulate family lists (vd, src1, vs2) per the RVV spec
    const vs2Real = inst.vs2Fixed === undefined;
    const src1Real = inst.vs1Fixed === undefined;
    if (inst.swap) {
      if (src1Real) this.asmFrags.push(f['src1']);
      if (vs2Real) this.asmFrags.push(f['vs2']);
    } else {
      if (vs2Real) this.asmFrags.push(f['vs2']);
      if (src1Real) this.asmFrags.push(f['src1']);
    }

    // vm suffix: only shown when vm is a real, user-controlled bit (not
    // one of the vm-disambiguated mnemonic pairs, which fix it already)
    if (inst.vmFixed === undefined && vm === '0') {
      this.asmFrags.push(new Frag(FRAG.UNSD, 'v0.t', vm, FIELDS.v_vm.name));
    }

    this.binFrags.push(f['funct6'], f['vm'], f['vs2'], f['src1'], f['funct3'],
      f['vd'], f['opcode']);
  }

  // Vector-crypto instructions (Zvkg/Zvkned/Zvknha/Zvknhb/Zvksed/Zvksh):
  // OP_V_CRYPTO's own opcode (0x77), always-unmasked (vm=1) and single-shape
  // (funct3=0x2) - see ISA_OP_V_CRYPTO in Constants.js
  #decodeVCrypto() {
    const funct6 = getBits(this.#bin, FIELDS.v_funct6.pos),
      vm = getBits(this.#bin, FIELDS.v_vm.pos),
      vs2raw = getBits(this.#bin, FIELDS.rs2.pos),
      src1raw = getBits(this.#bin, FIELDS.rs1.pos),
      funct3 = getBits(this.#bin, FIELDS.funct3.pos),
      vd = getBits(this.#bin, FIELDS.rd.pos);

    if (vm !== '1') {
      throw 'Detected OP-V-CRYPTO instruction with invalid vm field';
    }

    let entry = ISA_OP_V_CRYPTO[funct6];
    if (entry === undefined) {
      throw 'Detected OP-V-CRYPTO instruction but invalid funct6 field';
    }
    if (typeof entry !== 'string') {
      entry = entry[src1raw];
      if (entry === undefined) {
        throw 'Detected OP-V-CRYPTO instruction but invalid vs1 field';
      }
    }
    this.#mne = entry;
    const inst = ISA[this.#mne];

    const vd_ = decVReg(vd);
    const vs2 = decVReg(vs2raw);
    const f = {
      opcode: new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.opcode.name),
      funct6: new Frag(FRAG.OPC, this.#mne, funct6, FIELDS.v_funct6.name),
      vm:     new Frag(FRAG.OPC, this.#mne, vm, FIELDS.v_vm.name),
      vs2:    new Frag(FRAG.RS2, vs2, vs2raw, 'vs2'),
      funct3: new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.funct3.name),
      vd:     new Frag(FRAG.RD, vd_, vd, 'vd'),
    };
    this.asmFrags.push(f['opcode'], f['vd'], f['vs2']);

    if (inst.vs1Fixed !== undefined) {
      f['src1'] = new Frag(FRAG.UNSD, this.#mne, src1raw, 'vs1');
    } else if (inst.immType === 'zi') {
      const imm = decImm(src1raw, false);
      f['src1'] = new Frag(FRAG.IMM, imm, src1raw, 'zimm5');
      this.asmFrags.push(f['src1']);
    } else {
      const src1 = decVReg(src1raw);
      f['src1'] = new Frag(FRAG.RS1, src1, src1raw, 'vs1');
      this.asmFrags.push(f['src1']);
    }

    this.binFrags.push(f['funct6'], f['vm'], f['vs2'], f['src1'], f['funct3'],
      f['vd'], f['opcode']);
  }

  // V vector loads/stores: unit-stride, strided, indexed, fault-only-first,
  // whole-register, and mask forms, all sharing this field layout. The
  // mnemonic is entirely mechanical from (mop, the fixed selector normally
  // occupying the vs2/rs2 position, width, nf), so it's built directly
  // rather than via a lookup table - see the ISA_V vector-memory entries
  // in Constants.js for the naming convention.
  #decodeVMem(isLoad) {
    const nf = getBits(this.#bin, FIELDS.v_nf.pos),
      mew = getBits(this.#bin, FIELDS.v_mew.pos),
      mop = getBits(this.#bin, FIELDS.v_mop.pos),
      vm = getBits(this.#bin, FIELDS.v_vm.pos),
      reg24_20 = getBits(this.#bin, FIELDS.rs2.pos),
      rs1 = getBits(this.#bin, FIELDS.rs1.pos),
      width = getBits(this.#bin, FIELDS.v_width.pos),
      vdOrVs3 = getBits(this.#bin, FIELDS.rd.pos);

    if (mew !== '0') {
      throw 'Detected vector load/store with unsupported mew field';
    }
    const eew = V_EEW[width];

    // regKind: what the 24:20 field holds - undefined when it's a fixed
    // selector (no operand rendered there), 'x' for a real stride register
    // (strided), or 'v' for a real index-vector register (indexed)
    let regKind, baseName, noVm = false;
    if (mop === '10') {
      regKind = 'x';
      baseName = isLoad ? `vlse${eew}.v` : `vsse${eew}.v`;
    } else if (mop === '01' || mop === '11') {
      regKind = 'v';
      const ordered = mop === '11';
      baseName = isLoad
        ? (ordered ? `vloxei${eew}.v` : `vluxei${eew}.v`)
        : (ordered ? `vsoxei${eew}.v` : `vsuxei${eew}.v`);
    } else if (reg24_20 === '00000') {
      baseName = isLoad ? `vle${eew}.v` : `vse${eew}.v`;
    } else if (reg24_20 === '10000') {
      if (!isLoad) {
        throw 'Detected vector store with invalid sumop field';
      }
      baseName = `vle${eew}ff.v`;
    } else if (reg24_20 === '01011') {
      noVm = true;
      if (vm !== '1' || width !== '000' || nf !== '000') {
        throw 'Detected vector mask load/store with invalid vm/width/nf field';
      }
      this.#mne = isLoad ? 'vlm.v' : 'vsm.v';
    } else if (reg24_20 === '01000') {
      noVm = true;
      if (vm !== '1') {
        throw 'Detected vector whole-register load/store with invalid vm field';
      }
      const count = Object.entries(V_WHOLEREG_NF).find(e => e[1] === nf)?.[0];
      if (count === undefined) {
        throw 'Detected vector whole-register load/store with invalid nf field';
      }
      if (isLoad) {
        if (eew === undefined || ISA[`vl${count}re${eew}.v`] === undefined) {
          throw 'Detected vector whole-register load with invalid width field';
        }
        this.#mne = `vl${count}re${eew}.v`;
      } else {
        if (width !== '000') {
          throw 'Detected vector whole-register store with invalid width field';
        }
        this.#mne = `vs${count}r.v`;
      }
    } else {
      throw 'Detected vector load/store with invalid lumop/sumop field';
    }

    if (this.#mne === undefined) {
      if (eew === undefined || ISA[baseName] === undefined) {
        throw 'Detected vector load/store with invalid width field';
      }
      this.#mne = vSegName(baseName, parseInt(nf, BASE.bin));
    }

    // Convert fields to string representations
    const base = decReg(rs1);
    const operand = decVReg(vdOrVs3);

    const f = {
      opcode: new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.opcode.name),
      nf:     new Frag(FRAG.OPC, this.#mne, nf, FIELDS.v_nf.name),
      mew:    new Frag(FRAG.UNSD, this.#mne, mew, FIELDS.v_mew.name),
      mop:    new Frag(FRAG.OPC, this.#mne, mop, FIELDS.v_mop.name),
      vm:     new Frag(FRAG.OPC, this.#mne, vm, FIELDS.v_vm.name),
      width:  new Frag(FRAG.OPC, this.#mne, width, FIELDS.v_width.name),
      rs1:    new Frag(FRAG.RS1, base, rs1, FIELDS.rs1.name, true),
      reg:    isLoad
        ? new Frag(FRAG.RD, operand, vdOrVs3, 'vd')
        : new Frag(FRAG.RS2, operand, vdOrVs3, FIELDS.v_vs3.name),
    };

    this.asmFrags.push(f['opcode'], f['reg'], f['rs1']);

    if (regKind !== undefined) {
      const regAsm = regKind === 'x' ? decReg(reg24_20) : decVReg(reg24_20);
      f['reg24_20'] = new Frag(FRAG.RS2, regAsm, reg24_20, regKind === 'x' ? FIELDS.rs2.name : 'vs2');
      this.asmFrags.push(f['reg24_20']);
    } else {
      f['reg24_20'] = new Frag(FRAG.UNSD, this.#mne, reg24_20, isLoad ? FIELDS.v_lumop.name : FIELDS.v_sumop.name);
    }
    if (!noVm && vm === '0') {
      this.asmFrags.push(new Frag(FRAG.UNSD, 'v0.t', vm, FIELDS.v_vm.name));
    }

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['nf'], f['mew'], f['mop'], f['vm'], f['reg24_20'],
      f['rs1'], f['width'], f['reg'], f['opcode']);
  }

  /**
   * Decodes AMO instruction
   */
  #decodeAMO() {
    // Get fields
    const fields = extractRFields(this.#bin);
    const funct5 = fields['funct5'],
      aq = fields['aq'],
      rl = fields['rl'],
      rs2 = fields['rs2'],
      rs1 = fields['rs1'],
      funct3 = fields['funct3'],
      rd = fields['rd'];

    // Find instruction
    this.#mne = ISA_AMO[funct5+funct3];
    if (this.#mne === undefined) {
      throw "Detected AMO instruction but invalid funct5 and funct3 fields";
    }

    // Check if 'lr' instruction
    const lr = /^lr\./.test(this.#mne);

    // Convert fields to string representations
    const dest = decReg(rd);
    const addr = decReg(rs1);
    const src  = lr ? 'n/a' : decReg(rs2);

    // Create fragments
    const f = {
      opcode:   new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.opcode.name),
      rd:       new Frag(FRAG.RD, dest, rd, FIELDS.rd.name),
      funct3:   new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.funct3.name),
      rs1:      new Frag(FRAG.RS1, addr, rs1, FIELDS.rs1.name, true),
      rs2:      new Frag(FRAG.OPC, src, rs2, FIELDS.rs2.name),
      rl:       new Frag(FRAG.OPC, this.#mne, rl, FIELDS.r_rl.name),
      aq:       new Frag(FRAG.OPC, this.#mne, aq, FIELDS.r_aq.name),
      funct5:   new Frag(FRAG.OPC, this.#mne, funct5, FIELDS.r_funct5.name),
    };

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['rd']);
    if (!lr) {
      f['rs2'].id = FRAG.RS2;
      this.asmFrags.push(f['rs2']);
    }
    this.asmFrags.push(f['rs1']);

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['funct5'], f['aq'], f['rl'], f['rs2'],
      f['rs1'], f['funct3'], f['rd'], f['opcode']);
  }

  /**
   * Decodes R4 instructions
   */
  #decodeR4() {
    // Get each field
    const fields = extractRFields(this.#bin);
    const rs3 = fields['funct5'],
      fmt = fields['fmt'],
      rs2 = fields['rs2'],
      rs1 = fields['rs1'],
      funct3 = fields['funct3'],
      rd = fields['rd'];

    // Find instruction
    switch (this.#opcode) {
      case OPCODE.MADD:
        this.#mne = ISA_MADD[fmt];
        break;
      case OPCODE.MSUB:
        this.#mne = ISA_MSUB[fmt];
        break;
      case OPCODE.NMADD:
        this.#mne = ISA_NMADD[fmt];
        break;
      case OPCODE.NMSUB:
        this.#mne = ISA_NMSUB[fmt];
        break;
    }
    if (this.#mne === undefined) {
      throw `Detected fused multiply-add instruction but invalid fmt field`;
    }

    // Convert fields to string representations
    const src1 = decReg(rs1, true),
          src2 = decReg(rs2, true),
          src3 = decReg(rs3, true),
          frm  = decFrm(funct3),
          dest = decReg(rd, true);

    // Create fragments
    const f = {
      opcode: new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.opcode.name),
      fmt:    new Frag(FRAG.OPC, this.#mne, fmt, FIELDS.r_fp_fmt.name),
      funct3: new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.r_fp_rm.name),
      rd:     new Frag(FRAG.RD, dest, rd, FIELDS.rd.name),
      rs1:    new Frag(FRAG.RS1, src1, rs1, FIELDS.rs1.name),
      rs2:    new Frag(FRAG.RS2, src2, rs2, FIELDS.rs2.name),
      rs3:    new Frag(FRAG.RS3, src3, rs3, 'rs3'),
    };

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['rd'], f['rs1'], f['rs2'], f['rs3']);
    if (frm !== 'dyn') {
      f['funct3'].id = FRAG.FRM;
      f['funct3'].asm = frm;
      this.asmFrags.push(f['funct3']);
    }

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['rs3'], f['fmt'], f['rs2'], f['rs1'], f['funct3'],
      f['rd'], f['opcode']);
  }

  /**
   * Looks up C0 instruction mnemonics
   */
  #mneLookupC0() {
    // Get fields required for mne lookup
    const fields = extractCLookupFields(this.#bin);

    // C0 Instruction order of lookup
    // - funct3
    // - xlen
    this.#mne = ISA_C0[fields['funct3']];
    if (fields['funct3'] === '100') {
      // Zcb byte/halfword loads and stores: this funct3 was unused in base
      // C, so it's repurposed as a 3-bit sub-selector (subop) instead of
      // the usual xlen dispatch; c.lhu/c.lh/c.sh need one more bit (subop2)
      this.#mne = this.#mne[fields['zcb_subop']];
      if (typeof this.#mne === 'object') {
        this.#mne = this.#mne[fields['zcb_subop2']];
      }
    } else if (typeof this.#mne === 'object') {
      this.#mne = this.#mne[this.#xlens] ?? this.#mne[XLEN_MASK.all];
    }

    // Find and return instruction
    return ISA[this.#mne];
  }

  /**
   * Looks up C1 instruction mnemonics
   */
  #mneLookupC1() {
    // Get fields required for mne lookup
    const fields = extractCLookupFields(this.#bin);

    // C1 Instruction order of lookup
    // - funct3
    // - xlen
    // - rdRs1Val
    // - funct2_cb
    // - funct6[3]+funct2
    this.#mne = ISA_C1[fields['funct3']];
    if (typeof this.#mne === 'object') {
      this.#mne = this.#mne[this.#xlens] ?? this.#mne[XLEN_MASK.all];
      if (typeof this.#mne === 'object') {
        const rdRs1Val = decImm(fields['rd_rs1'], false);
        this.#mne = this.#mne[rdRs1Val] ?? this.#mne['default'];
        if (typeof this.#mne === 'object') {
          this.#mne = this.#mne[fields['funct2_cb']];
          if (typeof this.#mne === 'object') {
            this.#mne = this.#mne[fields['funct6'][3] + fields['funct2']];
            if (typeof this.#mne === 'object') {
              // Zcb single-operand pseudo-CA instructions: one more level,
              // keyed by the fixed sub-opcode occupying the rs2' position
              this.#mne = this.#mne[fields['zcb_subfunct3']];
            }
          }
        }
        // Zcmop: c.lui's reserved nzimm=0 encoding space is repurposed for
        // 8 specific rd/rs1 field values (c.mop.1/3/5/7/9/11/13/15);
        // anything else with a zero immediate there remains reserved c.lui
        if (this.#mne === 'c.lui' && fields['imm_ci_0'] === '0' && fields['imm_ci_1'] === '00000') {
          this.#mne = ISA_C1_MOP[rdRs1Val] ?? this.#mne;
        }
      }
    }

    // Find and return instruction
    return ISA[this.#mne];
  }

  /**
   * Looks up C2 instruction mnemonics
   */
  #mneLookupC2() {
    // Get fields required for mne lookup
    const fields = extractCLookupFields(this.#bin);

    // C2 Instruction order of lookup
    // - funct3
    // - xlen
    // - funct4[3]
    // - rs2Val
    // - rdRs1Val
    this.#mne = ISA_C2[fields['funct3']];
    if (fields['funct3'] === '101') {
      // Zcmt/Zcmp claim specific bit patterns within this space (mutually
      // exclusive with the D extension's c.fsdsp/c.sqsp on real hardware,
      // but this tool has no extension-exclusivity mechanism); try those
      // first and fall back to the usual xlen dispatch otherwise
      const zcmp = ISA_C2_ZCMP[fields['c2_subop']];
      if (typeof zcmp === 'string') {
        this.#mne = zcmp;
      } else if (typeof zcmp === 'object') {
        // cm.mvsa01/cm.mva01s (subop='011') split by funct2 (bits[6:5]);
        // cm.push/cm.pop and cm.popretz/cm.popret (subop='110'/'111') split
        // by one more bit (bit9) instead - bits[6:5] there are just the
        // middle of rlist and must not be used for dispatch
        this.#mne = fields['c2_subop'] === '011'
          ? zcmp[fields['funct2']]
          : zcmp[fields['c2_bit9']];
      } else if (typeof this.#mne === 'object') {
        this.#mne = this.#mne[this.#xlens] ?? this.#mne[XLEN_MASK.all];
      }
    } else if (typeof this.#mne === 'object') {
      this.#mne = this.#mne[this.#xlens] ?? this.#mne[XLEN_MASK.all];
      if (typeof this.#mne === 'object') {
        this.#mne = this.#mne[fields['funct4'][3]];
        if (typeof this.#mne === 'object') {
          const rs2Val = decImm(fields['rs2'], false);
          this.#mne = this.#mne[rs2Val] ?? this.#mne['default'];
          if (typeof this.#mne === 'object') {
            const rdRs1Val = decImm(fields['rd_rs1'], false);
            this.#mne = this.#mne[rdRs1Val] ?? this.#mne['default'];
          }
        }
      }
    }

    // Find and return instruction
    return ISA[this.#mne];
  }

  /**
   * Decodes CR-type instruction
   */
  #decodeCR(inst) {
    // Get fields
    const funct4 = getBits(this.#bin, FIELDS.c_funct4.pos);
    const rdRs1  = getBits(this.#bin, FIELDS.c_rd_rs1.pos);
    const rs2    = getBits(this.#bin, FIELDS.c_rs2.pos);
    const opcode = getBits(this.#bin, FIELDS.c_opcode.pos);

    // Convert fields to string representations
    const destSrc1 = decReg(rdRs1);
    const src2     = decReg(rs2);

    // Validate operands
    const destSrc1Val = decImm(rdRs1, false);
    if (inst.rdRs1Excl?.includes(destSrc1Val)) {
      throw `Detected ${this.#mne} instruction, but illegal value "${destSrc1}" in rd/rs1 field`;
    }
    const src2Val = decImm(rs2, false);
    if (inst.rs2Excl?.includes(src2Val)) {
      throw `Detected ${this.#mne} instruction, but illegal value "${src2}" in rs2 field`;
    }

    // Determine name for destSrc1
    let destSrc1Name;
    switch (inst.rdRs1Mask) {
      case 0b01:
        destSrc1Name = FIELDS.c_rs1.name;
        break;
      case 0b10:
        destSrc1Name = FIELDS.c_rd.name;
        break;
      default:
        destSrc1Name = FIELDS.c_rd_rs1.name;
    }
    if (inst.rdRs1Excl !== undefined) {
      destSrc1Name += '≠' + regExclToString(inst.rdRs1Excl);
    }

    // Determine name for src2
    let src2Name = FIELDS.c_rs2.name;
    if (inst.rs2Excl !== undefined) {
      src2Name += '≠' + regExclToString(inst.rs2Excl);
    }

    // Create fragments
    const f = {
      opcode: new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.c_opcode.name),
      funct4: new Frag(FRAG.OPC, this.#mne, funct4, FIELDS.c_funct4.name),
    };

    // Create custom fragments
    const dynamicRdRs1 = inst.rdRs1Val === undefined;
    if (dynamicRdRs1) {
      f['rd_rs1'] = new Frag(FRAG.RD, destSrc1, rdRs1, destSrc1Name);
    } else {
      f['rd_rs1'] = new Frag(FRAG.OPC, this.#mne, rdRs1, 'static-' + destSrc1Name);
    }
    const dynamicRs2 = inst.rs2Val === undefined;
    if (dynamicRs2) {
      f['rs2'] = new Frag(FRAG.RS2, src2, rs2, src2Name);
    } else {
      f['rs2'] = new Frag(FRAG.OPC, this.#mne, rs2, 'static-' + src2Name);
    }

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode']);
    if (dynamicRdRs1) {
      this.asmFrags.push(f['rd_rs1']);
      if (dynamicRs2) {
        this.asmFrags.push(f['rs2']);
      }
    }

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['funct4'], f['rd_rs1'], f['rs2'], f['opcode']);
  }

  /**
   * Decodes CI-type instruction
   */
  #decodeCI(inst) {
    // Get fields
    const funct3 = getBits(this.#bin, FIELDS.c_funct3.pos);
    const imm0   = getBits(this.#bin, FIELDS.c_imm_ci_0.pos);
    const rdRs1  = getBits(this.#bin, FIELDS.c_rd_rs1.pos);
    const imm1   = getBits(this.#bin, FIELDS.c_imm_ci_1.pos);
    const opcode = getBits(this.#bin, FIELDS.c_opcode.pos);

    // Determine instruction type, for special cases
    const shiftInst = /^c\.slli/.test(this.#mne);

    // Check if floating-point load instruction
    const floatRdRs1 = /^c\.fl/.test(this.#mne);

    // Convert fields to string representations
    const destSrc1 = decReg(rdRs1, floatRdRs1);
    const immVal = decImmBits([imm0, imm1], inst.immBits, inst.uimm);

    // Perform shift-specific special cases
    if (shiftInst) {
      if (immVal === 0) {
        // Determine if shift is a shift64 function
        this.#mne += '64';
        inst = ISA[this.#mne];
        if (inst === undefined) {
          throw `Internal error when converting shift-immediate instruction into ${this.#mne}`;
        }
        // Overwrite ISA
        this.isa = 'RV128' + inst.isa;

      } else if (imm0 === '1' && /^RV32/.test(this.isa)) {
        // Force RV32C -> RV64C isa if imm[5] is set (shamt > 31)
        this.isa = 'RV64' + inst.isa;
      }
    }

    // Validate operand values
    const destSrc1Val = decImm(rdRs1, false);
    if (inst.rdRs1Excl?.includes(destSrc1Val)) {
      throw `Detected ${this.#mne} instruction, but illegal value "${destSrc1}" in rd/rs1 field`;
    }
    if (inst.nzimm && immVal === 0) {
      throw `Detected ${this.#mne}, but instruction expects non-zero immediate value (encoding reserved)`
    }

    // Determine name for destSrc1
    let destSrc1Name;
    switch (inst.rdRs1Mask) {
      case 0b01:
        destSrc1Name = FIELDS.c_rs1.name;
        break;
      case 0b10:
        destSrc1Name = FIELDS.c_rd.name;
        break;
      default:
        destSrc1Name = FIELDS.c_rd_rs1.name;
    }
    if (inst.rdRs1Excl !== undefined) {
      destSrc1Name += '≠' + regExclToString(inst.rdRs1Excl);
    }

    // Determine name for immediate
    let immName = '';
    if (!shiftInst) {
      if (inst.nzimm) {
        immName += 'nz';
      }
      if (inst.uimm) {
        immName += 'u';
      }
    }
    immName += shiftInst
      ? FIELDS.c_shamt_0.name
      : FIELDS.c_imm_ci_0.name;

    // Create common fragments
    const f = {
      opcode: new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.c_opcode.name),
      funct3: new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.c_funct3.name),
    };

    // Create and append custom register fragments
    const dynamicRdRs1 = inst.rdRs1Val === undefined;
    if (dynamicRdRs1) {
      f['rd_rs1'] = new Frag(FRAG.RD, destSrc1, rdRs1, destSrc1Name);
    } else {
      f['rd_rs1'] = new Frag(FRAG.OPC, this.#mne, rdRs1, 'static-' + destSrc1Name);
    }

    // Create and append custom immediate fragments
    const immBitsLabels = inst.immBitsLabels ?? inst.immBits;
    const dynamicImm = inst.immVal === undefined;
    if (dynamicImm) {
      f['imm0'] = new Frag(FRAG.IMM, immVal, imm0, immName + immBitsToString(immBitsLabels[0]));
      f['imm1'] = new Frag(FRAG.IMM, immVal, imm1, immName + immBitsToString(immBitsLabels[1]));
    } else {
      f['imm0'] = new Frag(FRAG.OPC, this.#mne, imm0, 'static-' + immName + immBitsToString(immBitsLabels[0]));
      f['imm1'] = new Frag(FRAG.OPC, this.#mne, imm1, 'static-' + immName + immBitsToString(immBitsLabels[1]));
    }

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode']);
    if (dynamicRdRs1) {
      this.asmFrags.push(f['rd_rs1']);
    }
    if (dynamicImm) {
      this.asmFrags.push(f['imm0']);
    }

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['funct3'], f['imm0'], f['rd_rs1'], f['imm1'], f['opcode']);
  }

  /**
   * Decodes CSS-type instruction
   */
  #decodeCSS(inst) {
    // Get fields
    const funct3 = getBits(this.#bin, FIELDS.c_funct3.pos);
    const imm    = getBits(this.#bin, FIELDS.c_imm_css.pos);
    const rs2    = getBits(this.#bin, FIELDS.c_rs2.pos);

    // Determine name for immediate
    let immName = '';
    if (inst.uimm) {
      immName += 'u';
    }
    immName += FIELDS.c_imm_css.name;

    // Check if floating-point load instruction
    const floatRs2 = /^c\.f/.test(this.#mne);

    // Convert fields to string representations
    const offset = decImmBits(imm, inst.immBits, inst.uimm);
    const src = decReg(rs2, floatRs2);

    // Create fragments
    const f = {
      opcode: new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.c_opcode.name),
      funct3: new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.c_funct3.name),
      rs2:    new Frag(FRAG.RS2, src, rs2, FIELDS.c_rs2.name),
      imm: new Frag(FRAG.IMM, offset, imm, immName + immBitsToString(inst.immBits)),
    };

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['rs2'], f['imm']);

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['funct3'], f['imm'], f['rs2'], f['opcode']);
  }

  /**
   * Decodes CIW-type instruction
   */
  #decodeCIW(inst) {
    // Get fields
    const funct3   = getBits(this.#bin, FIELDS.c_funct3.pos);
    const imm      = getBits(this.#bin, FIELDS.c_imm_ciw.pos);
    const rdPrime  = getBits(this.#bin, FIELDS.c_rd_prime.pos);
    const opcode   = getBits(this.#bin, FIELDS.c_opcode.pos);

    // Determine name for immediate
    let immName = '';
    if (inst.nzimm) {
      immName += 'nz';
    }
    if (inst.uimm) {
      immName += 'u';
    }
    immName += FIELDS.c_imm_ciw.name;

    // Prepend bits to compressed register fields
    const rd  = '01' + rdPrime;

    // Convert fields to string representations
    const dest   = decReg(rd);
    const immVal = decImmBits(imm, inst.immBits, inst.uimm);

    // Validate operand values
    if (inst.nzimm && immVal === 0) {
      throw `Detected ${this.#mne}, but instruction expects non-zero immediate value (encoding reserved)`
    }

    // Create fragments
    const f = {
      opcode:   new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.c_opcode.name),
      funct3:   new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.c_funct3.name),
      rd_prime: new Frag(FRAG.RD, dest, rdPrime, FIELDS.c_rd_prime.name),
      imm: new Frag(FRAG.IMM, immVal, imm, immName + immBitsToString(inst.immBits)),
    };

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['rd_prime'], f['imm']);

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['funct3'], f['imm'], f['rd_prime'], f['opcode']);
  }

  /**
   * Decodes CL-type instruction
   */
  #decodeCL(inst) {
    if (inst.subop !== undefined) {
      return this.#decodeZcbMem(inst, false);
    }

    // Get fields
    const funct3   = getBits(this.#bin, FIELDS.c_funct3.pos);
    const imm0     = getBits(this.#bin, FIELDS.c_imm_cl_0.pos);
    const rs1Prime = getBits(this.#bin, FIELDS.c_rs1_prime.pos);
    const imm1     = getBits(this.#bin, FIELDS.c_imm_cl_1.pos);
    const rdPrime  = getBits(this.#bin, FIELDS.c_rd_prime.pos);
    const opcode   = getBits(this.#bin, FIELDS.c_opcode.pos);

    // Determine name for immediate
    let immName = '';
    if (inst.uimm) {
      immName += 'u';
    }
    immName += FIELDS.c_imm_cl_0.name;

    // Check if floating-point load instruction
    const floatRd = /^c\.f/.test(this.#mne);

    // Prepend bits to compressed register fields
    const rs1 = '01' + rs1Prime;
    const rd  = '01' + rdPrime;

    // Convert fields to string representations
    const dest   = decReg(rd, floatRd);
    const offset = decImmBits([imm0, imm1], inst.immBits, inst.uimm);
    const base   = decReg(rs1);

    // Create fragments
    const f = {
      opcode:    new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.c_opcode.name),
      funct3:    new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.c_funct3.name),
      rd_prime:  new Frag(FRAG.RD, dest, rdPrime, FIELDS.c_rd_prime.name),
      rs1_prime: new Frag(FRAG.RS1, base, rs1Prime, FIELDS.c_rs1_prime.name, true),
      imm0: new Frag(FRAG.IMM, offset, imm0, immName + immBitsToString(inst.immBits[0])),
      imm1: new Frag(FRAG.IMM, offset, imm1, immName + immBitsToString(inst.immBits[1])),
    };

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['rd_prime'], f['imm0'], f['rs1_prime']);

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['funct3'], f['imm0'], f['rs1_prime'],
      f['imm1'], f['rd_prime'], f['opcode']);
  }

  /**
   * Decodes CS-type instruction
   */
  #decodeCS(inst) {
    if (inst.subop !== undefined) {
      return this.#decodeZcbMem(inst, true);
    }

    // Get fields
    const funct3   = getBits(this.#bin, FIELDS.c_funct3.pos);
    const imm0     = getBits(this.#bin, FIELDS.c_imm_cl_0.pos);
    const rs1Prime = getBits(this.#bin, FIELDS.c_rs1_prime.pos);
    const imm1     = getBits(this.#bin, FIELDS.c_imm_cl_1.pos);
    const rs2Prime = getBits(this.#bin, FIELDS.c_rs2_prime.pos);
    const opcode   = getBits(this.#bin, FIELDS.c_opcode.pos);

    // Determine name for immediate
    let immName = '';
    if (inst.uimm) {
      immName += 'u';
    }
    immName += FIELDS.c_imm_cs_0.name;

    // Check if floating-point load instruction
    const floatRs2 = /^c\.f/.test(this.#mne);

    // Prepend bits to compressed register fields
    const rs1 = '01' + rs1Prime;
    const rs2 = '01' + rs2Prime;

    // Convert fields to string representations
    const src    = decReg(rs2, floatRs2);
    const offset = decImmBits([imm0, imm1], inst.immBits, inst.uimm);
    const base   = decReg(rs1);

    // Create fragments
    const f = {
      opcode:    new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.c_opcode.name),
      funct3:    new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.c_funct3.name),
      rs2_prime: new Frag(FRAG.RS2, src, rs2Prime, FIELDS.c_rs2_prime.name),
      rs1_prime: new Frag(FRAG.RS1, base, rs1Prime, FIELDS.c_rs1_prime.name, true),
      imm0: new Frag(FRAG.IMM, offset, imm0, immName + immBitsToString(inst.immBits[0])),
      imm1: new Frag(FRAG.IMM, offset, imm1, immName + immBitsToString(inst.immBits[1])),
    };

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['rs2_prime'], f['imm0'], f['rs1_prime']);

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['funct3'], f['imm0'], f['rs1_prime'],
      f['imm1'], f['rs2_prime'], f['opcode']);
  }

  /**
   * Decodes Zcb byte/halfword loads (c.lbu/c.lhu/c.lh) and stores (c.sb/c.sh)
   *   These reuse the CL/CS-type register layout, but their funct3 is
   *   entirely repurposed: a fixed 3-bit subop selector plus, for
   *   halfwords, a fixed discriminator bit (subop2) alongside a
   *   correspondingly narrower immediate (2-bit byte offset, or 1-bit
   *   halfword offset)
   */
  #decodeZcbMem(inst, isStore) {
    // Get fields
    const funct3   = getBits(this.#bin, FIELDS.c_funct3.pos);
    const subop    = getBits(this.#bin, FIELDS.c_zcb_subop.pos);
    const rs1Prime = getBits(this.#bin, FIELDS.c_rs1_prime.pos);
    const regPrime = getBits(this.#bin,
      isStore ? FIELDS.c_rs2_prime.pos : FIELDS.c_rd_prime.pos);

    // Prepend bits to compressed register fields
    const rs1 = '01' + rs1Prime;
    const reg = '01' + regPrime;

    // Convert fields to string representations
    const base = decReg(rs1);
    const val  = decReg(reg, /^c\.f/.test(this.#mne));

    const f = {
      opcode:    new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.c_opcode.name),
      funct3:    new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.c_funct3.name),
      subop:     new Frag(FRAG.OPC, this.#mne, subop, FIELDS.c_zcb_subop.name),
      rs1_prime: new Frag(FRAG.RS1, base, rs1Prime, FIELDS.c_rs1_prime.name, true),
      reg_prime: new Frag(isStore ? FRAG.RS2 : FRAG.RD, val, regPrime,
        isStore ? FIELDS.c_rs2_prime.name : FIELDS.c_rd_prime.name),
    };

    if (inst.subop2 !== undefined) {
      // c.lhu/c.lh/c.sh: bit 6 is a fixed discriminator (subop2), leaving
      // only bit 5 as the immediate (uimm[1]; halfword access is 2-byte
      // aligned so uimm[0] is implicitly 0)
      const subop2 = getBits(this.#bin, FIELDS.c_zcb_subop2.pos);
      const uimmBits = getBits(this.#bin, FIELDS.c_zcb_uimm1.pos);
      const offset = decImm(uimmBits, false) * 2;

      f['subop2'] = new Frag(FRAG.OPC, this.#mne, subop2, FIELDS.c_zcb_subop2.name);
      f['uimm']   = new Frag(FRAG.IMM, offset, uimmBits, FIELDS.c_zcb_uimm1.name);

      this.asmFrags.push(f['opcode'], f['reg_prime'], f['uimm'], f['rs1_prime']);
      this.binFrags.push(f['funct3'], f['subop'], f['rs1_prime'], f['subop2'],
        f['uimm'], f['reg_prime'], f['opcode']);
      return;
    }

    // c.lbu/c.sb: full 2-bit byte offset (uimm[1:0])
    const uimmBits = getBits(this.#bin, FIELDS.c_zcb_uimm2.pos);
    const offset = decImm(uimmBits, false);

    f['uimm'] = new Frag(FRAG.IMM, offset, uimmBits, FIELDS.c_zcb_uimm2.name);

    this.asmFrags.push(f['opcode'], f['reg_prime'], f['uimm'], f['rs1_prime']);
    this.binFrags.push(f['funct3'], f['subop'], f['rs1_prime'], f['uimm'],
      f['reg_prime'], f['opcode']);
  }

  /**
   * Decodes CA-type instruction
   */
  #decodeCA(inst) {
    // Get fields
    const funct6     = getBits(this.#bin, FIELDS.c_funct6.pos);
    const rdRs1Prime = getBits(this.#bin, FIELDS.c_rd_rs1_prime.pos);
    const funct2     = getBits(this.#bin, FIELDS.c_funct2.pos);
    const rs2Prime   = getBits(this.#bin, FIELDS.c_rs2_prime.pos);
    const opcode     = getBits(this.#bin, FIELDS.c_opcode.pos);

    // Prepend bits to compressed register fields
    const rdRs1 = '01' + rdRs1Prime;

    // Convert fields to string representations
    const destSrc1 = decReg(rdRs1);

    // Create fragments
    const f = {
      opcode:       new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.c_opcode.name),
      funct6:       new Frag(FRAG.OPC, this.#mne, funct6, FIELDS.c_funct6.name),
      funct2:       new Frag(FRAG.OPC, this.#mne, funct2, FIELDS.c_funct2.name),
      rd_rs1_prime: new Frag(FRAG.RD, destSrc1, rdRs1Prime, FIELDS.c_rs2_prime.name),
    };

    if (inst.subfunct3 !== undefined) {
      // Zcb single-operand instructions (c.zext.b/h/w, c.sext.b/h, c.not):
      // rs2' bits are a fixed sub-opcode selector, not a register
      f['rs2_prime'] = new Frag(FRAG.OPC, this.#mne, rs2Prime, FIELDS.c_zcb_subfunct3.name);

      this.asmFrags.push(f['opcode'], f['rd_rs1_prime']);
      this.binFrags.push(f['funct6'], f['rd_rs1_prime'],
        f['funct2'], f['rs2_prime'], f['opcode']);
      return;
    }

    const rs2 = '01' + rs2Prime;
    const src2 = decReg(rs2);
    f['rs2_prime'] = new Frag(FRAG.RS2, src2, rs2Prime, FIELDS.c_rs1_prime.name);

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['rd_rs1_prime'], f['rs2_prime']);

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['funct6'], f['rd_rs1_prime'],
      f['funct2'], f['rs2_prime'], f['opcode']);
  }

  /**
   * Decodes CB-type instruction
   */
  #decodeCB(inst) {
    // Get fields
    const funct3     = getBits(this.#bin, FIELDS.c_funct3.pos);
    const imm0       = getBits(this.#bin, FIELDS.c_imm_cb_0.pos);
    const shamt0     = getBits(this.#bin, FIELDS.c_shamt_0.pos);
    const funct2     = getBits(this.#bin, FIELDS.c_funct2_cb.pos);
    const rdRs1Prime = getBits(this.#bin, FIELDS.c_rd_rs1_prime.pos);
    const imm1       = getBits(this.#bin, FIELDS.c_imm_cb_1.pos);
    const shamt1     = getBits(this.#bin, FIELDS.c_shamt_1.pos);
    const opcode     = getBits(this.#bin, FIELDS.c_opcode.pos);

    // Determine instruction type, for special cases
    const branchInst = /^c\.b/.test(this.#mne);
    const shiftInst = /^c\.sr[la]i/.test(this.#mne);

    // Prepend bits to compressed register fields
    const rdRs1 = '01' + rdRs1Prime;

    // Convert fields to string representations
    const destSrc1 = decReg(rdRs1);
    const immVal = decImmBits([imm0, imm1], inst.immBits, inst.uimm);

    // Perform shift-specific special cases
    if (shiftInst) {
      if (immVal === 0) {
        // Determine if shift is a shift64 function
        this.#mne += '64';
        inst = ISA[this.#mne];
        if (inst === undefined) {
          throw `Internal error when converting shift-immediate instruction into ${this.#mne}`;
        }
        // Overwrite ISA
        this.isa = 'RV128' + inst.isa;

      } else if (shamt0 === '1' && /^RV32/.test(this.isa)) {
        // Force RV32C -> RV64C isa if imm[5] is set (shamt > 31)
        this.isa = 'RV64' + inst.isa;
      }
    }

    // Validate operand values
    if (inst.nzimm && immVal === 0) {
      throw `Detected ${this.#mne}, but instruction expects non-zero immediate value (encoding reserved)`
    }

    // Determine name for immediate
    let immName = '';
    if (!shiftInst) {
      if (inst.nzimm) {
        immName += 'nz';
      }
      if (inst.uimm) {
        immName += 'u';
      }
    }
    immName += shiftInst
      ? FIELDS.c_shamt_0.name
      : (branchInst ? FIELDS.c_imm_cb_0.name : FIELDS.c_imm_ci_0.name);

    // Create common fragments
    const f = {
      opcode:       new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.c_opcode.name),
      funct3:       new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.c_funct3.name),
      funct2:       new Frag(FRAG.OPC, this.#mne, funct2, FIELDS.c_funct2.name),
      rd_rs1_prime: new Frag(FRAG.RD, destSrc1, rdRs1Prime, FIELDS.c_rs2_prime.name),
    };

    // Create custom fragments and build fragment arrays
    if (branchInst) {
      // Shift instruction, use shamt and funct2
      f['imm0'] = new Frag(FRAG.IMM, immVal, imm0, immName + immBitsToString(inst.immBits[0]));
      f['imm1'] = new Frag(FRAG.IMM, immVal, imm1, immName + immBitsToString(inst.immBits[1]));

      // Assembly fragments in order of instruction
      this.asmFrags.push(f['opcode'], f['rd_rs1_prime'], f['imm0']);
      // Binary fragments from MSB to LSB
      this.binFrags.push(f['funct3'], f['imm0'], f['rd_rs1_prime'], f['imm1'], f['opcode']);

    } else {
      // Shift instruction and `c.andi`, use shamt and funct2
      const dynamicImm = inst.immVal === undefined;
      if (dynamicImm) {
        f['imm0'] = new Frag(FRAG.IMM, immVal, shamt0, immName + immBitsToString(inst.immBits[0]));
        f['imm1'] = new Frag(FRAG.IMM, immVal, shamt1, immName + immBitsToString(inst.immBits[1]));
      } else {
        f['imm0'] = new Frag(FRAG.OPC, this.#mne, shamt0, 'static-' + immName + immBitsToString(inst.immBits[0]));
        f['imm1'] = new Frag(FRAG.OPC, this.#mne, shamt1, 'static-' + immName + immBitsToString(inst.immBits[1]));
      }

      // Assembly fragments in order of instruction
      this.asmFrags.push(f['opcode'], f['rd_rs1_prime']);
      if (dynamicImm) {
        this.asmFrags.push(f['imm0']);
      }
      // Binary fragments from MSB to LSB
      this.binFrags.push(f['funct3'], f['imm0'], f['funct2'], f['rd_rs1_prime'], f['imm1'], f['opcode']);
    }
  }

  /**
   * Decodes CJ-type instruction
   */
  #decodeCJ(inst) {
    // Get fields
    const funct3 = getBits(this.#bin, FIELDS.c_funct3.pos);
    const imm    = getBits(this.#bin, FIELDS.c_imm_cj.pos);
    const opcode = getBits(this.#bin, FIELDS.c_opcode.pos);

    // Convert fields to string representations
    const jumpTarget = decImmBits(imm, inst.immBits);

    // Create fragments
    const f = {
      opcode:   new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.c_opcode.name),
      funct3:   new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.c_funct3.name),
      imm: new Frag(FRAG.IMM, jumpTarget, imm, FIELDS.c_imm_cj.name + immBitsToString(inst.immBits)),
    };

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['imm']);

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['funct3'], f['imm'], f['opcode']);
  }

  /**
   * Decodes CMJT-type instruction (Zcmt cm.jalt)
   */
  #decodeCMJT() {
    // Get fields
    const funct3 = getBits(this.#bin, FIELDS.c_funct3.pos);
    const subop  = getBits(this.#bin, FIELDS.c_c2_subop.pos);
    const index  = getBits(this.#bin, FIELDS.c_index.pos);

    // Convert fields to string representations
    const indexVal = decImm(index, false);

    // Create fragments
    const f = {
      opcode: new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.c_opcode.name),
      funct3: new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.c_funct3.name),
      subop:  new Frag(FRAG.OPC, this.#mne, subop, FIELDS.c_c2_subop.name),
      index:  new Frag(FRAG.IMM, indexVal, index, FIELDS.c_index.name),
    };

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['index']);

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['funct3'], f['subop'], f['index'], f['opcode']);
  }

  /**
   * Decodes CMPP-type instruction
   *   (Zcmp cm.push/cm.pop/cm.popretz/cm.popret)
   */
  #decodeCMPP(inst) {
    // Get fields
    const funct3 = getBits(this.#bin, FIELDS.c_funct3.pos);
    const subop  = getBits(this.#bin, FIELDS.c_c2_subop.pos);
    const bit9_8 = getBits(this.#bin, FIELDS.c_c2_bit9.pos);
    const rlist  = getBits(this.#bin, FIELDS.c_rlist.pos);
    const spimm  = getBits(this.#bin, FIELDS.c_spimm.pos);

    // Convert fields to string representations
    const rlistVal = decImm(rlist, false);
    if (rlistVal < 4) {
      throw `Detected ${this.#mne} instruction, but rlist value "${rlistVal}" is reserved`;
    }
    const xlenBytes = this.#xlens === XLEN_MASK.rv64 ? 8
      : this.#xlens === XLEN_MASK.rv128 ? 16 : 4;
    const list = decRlist(rlistVal);
    const adjustment = decStackAdj(rlistVal, spimm, xlenBytes, inst.signNeg === true);

    // Create fragments
    const f = {
      opcode: new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.c_opcode.name),
      funct3: new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.c_funct3.name),
      subop:  new Frag(FRAG.OPC, this.#mne, subop, FIELDS.c_c2_subop.name),
      bit9_8: new Frag(FRAG.OPC, this.#mne, bit9_8, FIELDS.c_c2_bit9.name),
      rlist:  new Frag(FRAG.OPC, list, rlist, FIELDS.c_rlist.name),
      spimm:  new Frag(FRAG.IMM, adjustment, spimm, FIELDS.c_spimm.name),
    };

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['rlist'], f['spimm']);

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['funct3'], f['subop'], f['bit9_8'], f['rlist'],
      f['spimm'], f['opcode']);
  }

  /**
   * Decodes CMMV-type instruction (Zcmp cm.mvsa01/cm.mva01s)
   */
  #decodeCMMV() {
    // Get fields
    const funct3 = getBits(this.#bin, FIELDS.c_funct3.pos);
    const subop  = getBits(this.#bin, FIELDS.c_c2_subop.pos);
    const sreg1  = getBits(this.#bin, FIELDS.c_sreg1.pos);
    const funct2 = getBits(this.#bin, FIELDS.c_funct2.pos);
    const sreg2  = getBits(this.#bin, FIELDS.c_sreg2.pos);

    // Convert fields to string representations
    const reg1 = decSreg(sreg1);
    const reg2 = decSreg(sreg2);

    // Create fragments
    const f = {
      opcode: new Frag(FRAG.OPC, this.#mne, this.#opcode, FIELDS.c_opcode.name),
      funct3: new Frag(FRAG.OPC, this.#mne, funct3, FIELDS.c_funct3.name),
      subop:  new Frag(FRAG.OPC, this.#mne, subop, FIELDS.c_c2_subop.name),
      funct2: new Frag(FRAG.OPC, this.#mne, funct2, FIELDS.c_funct2.name),
      sreg1:  new Frag(FRAG.RS1, reg1, sreg1, FIELDS.c_sreg1.name),
      sreg2:  new Frag(FRAG.RS2, reg2, sreg2, FIELDS.c_sreg2.name),
    };

    // Assembly fragments in order of instruction
    this.asmFrags.push(f['opcode'], f['sreg1'], f['sreg2']);

    // Binary fragments from MSB to LSB
    this.binFrags.push(f['funct3'], f['subop'], f['sreg1'], f['funct2'],
      f['sreg2'], f['opcode']);
  }
}

// Extract R-types fields from instruction
function extractRFields(binary) {
  return {
    'rs2': getBits(binary, FIELDS.rs2.pos),
    'rs1': getBits(binary, FIELDS.rs1.pos),
    'funct3': getBits(binary, FIELDS.funct3.pos),
    'rd': getBits(binary, FIELDS.rd.pos),
    'funct5': getBits(binary, FIELDS.r_funct5.pos),
    'funct7': getBits(binary, FIELDS.r_funct7.pos),
    'aq': getBits(binary, FIELDS.r_aq.pos),
    'rl': getBits(binary, FIELDS.r_rl.pos),
    'fmt': getBits(binary, FIELDS.r_fp_fmt.pos),
  };
}

// Extract I-types fields from instruction
function extractIFields(binary) {
  return {
    'imm': getBits(binary, FIELDS.i_imm_11_0.pos),
    'rs1': getBits(binary, FIELDS.rs1.pos),
    'funct3': getBits(binary, FIELDS.funct3.pos),
    'rd': getBits(binary, FIELDS.rd.pos),

    /* Shift instructions */
    'shtyp': getBits(binary, FIELDS.i_shtyp.pos),
    'shamt': getBits(binary, FIELDS.i_shamt.pos),
    'shamt_5': getBits(binary, FIELDS.i_shamt_5.pos),
    'shamt_6': getBits(binary, FIELDS.i_shamt_6.pos),
    /* System instructions */
    'funct12': getBits(binary, FIELDS.i_funct12.pos),
    /* Fence insructions */
    'fm': getBits(binary, FIELDS.i_fm.pos),
    'pred': getBits(binary, FIELDS.i_pred.pos),
    'succ': getBits(binary, FIELDS.i_succ.pos),
  };
}

// Extract S-types fields from instruction
function extractSFields(binary) {
  return {
    'imm_11_5': getBits(binary, FIELDS.s_imm_11_5.pos),
    'rs2': getBits(binary, FIELDS.rs2.pos),
    'rs1': getBits(binary, FIELDS.rs1.pos),
    'funct3': getBits(binary, FIELDS.funct3.pos),
    'imm_4_0': getBits(binary, FIELDS.s_imm_4_0.pos),
  };
}

// Extract B-types fields from instruction
function extractBFields(binary) {
  return {
    'imm_12': getBits(binary, FIELDS.b_imm_12.pos),
    'imm_10_5': getBits(binary, FIELDS.b_imm_10_5.pos),
    'rs2': getBits(binary, FIELDS.rs2.pos),
    'rs1': getBits(binary, FIELDS.rs1.pos),
    'funct3': getBits(binary, FIELDS.funct3.pos),
    'imm_4_1': getBits(binary, FIELDS.b_imm_4_1.pos),
    'imm_11': getBits(binary, FIELDS.b_imm_11.pos),
  };
}

// Extract C-instruction fields for mnemonic lookup
function extractCLookupFields(binary) {
  return {
    'funct6': getBits(binary, FIELDS.c_funct6.pos),
    'funct4': getBits(binary, FIELDS.c_funct4.pos),
    'funct3': getBits(binary, FIELDS.c_funct3.pos),
    'funct2': getBits(binary, FIELDS.c_funct2.pos),
    'funct2_cb': getBits(binary, FIELDS.c_funct2_cb.pos),
    'rd_rs1': getBits(binary, FIELDS.c_rd_rs1.pos),
    'rs2': getBits(binary, FIELDS.c_rs2.pos),
    'zcb_subop': getBits(binary, FIELDS.c_zcb_subop.pos),
    'zcb_subop2': getBits(binary, FIELDS.c_zcb_subop2.pos),
    'zcb_subfunct3': getBits(binary, FIELDS.c_zcb_subfunct3.pos),
    'imm_ci_0': getBits(binary, FIELDS.c_imm_ci_0.pos),
    'imm_ci_1': getBits(binary, FIELDS.c_imm_ci_1.pos),
    'c2_subop': getBits(binary, FIELDS.c_c2_subop.pos),
    'c2_bit9': getBits(binary, FIELDS.c_c2_bit9.pos),
  };
}

// Get bits out of binary instruction
function getBits(binary, pos) {
  if (!Array.isArray(pos)) {
    throw getBits.name + ": position should be an array";
  }

  let end = pos[0] + 1;
  let start = end - pos[1];

  if (start > end || binary.length < end) {
    throw getBits.name + ": position error";
  }

  return binary.substring(binary.length - end, binary.length - start);
}

// Parse given immediate to decimal
function decImm(immediate, signExtend = true) {
  // Sign extension requested and sign bit set
  if (signExtend && immediate[0] === '1') {
    return parseInt(immediate, BASE.bin) - Number('0b1' + ''.padStart(immediate.length, '0'));
  }
  return parseInt(immediate, BASE.bin);
}

// Decode immediate value using the given immBits configuration
function decImmBits(immFields, immBits, uimm = false) {
  // Construct full immediate binary to decode
  // - Start with 18 as length since that supports the widest compressed immediate value
  //     Specifically, `c.lui` provides imm[17:12], so there's 6 encoded bits in the upper-portion,
  //     While the 12 LSBs are assumed to be 0, for a total of 18 bits (hence, len = 18)
  const len = 18;
  let binArray = ''.padStart(len, '0').split('');
  let maxBit = 0;

  // Create singleton arrays if only one immediate field present
  if (typeof immFields === 'string') {
    immFields = [immFields];
    immBits = [immBits];
  }

  // Iterate over fields, if multiple
  for (let i = 0; i < immFields.length; i++) {
    const fieldBin = immFields[i];
    const fieldBits = immBits[i];

    // Iterate over bits configuration
    let k = 0; // Iterator for fieldBin
    for (let j = 0; j < fieldBits.length; j++) {
      let bit = fieldBits[j];
      // Check for highest bit
      maxBit = Math.max(maxBit, bit?.[0] ?? bit);

      // Check for single bit vs bit span
      if (typeof bit === 'number') {
        // Single bit
        binArray[len - 1 - bit] = fieldBin[k];
        k++;
      } else {
        // Bit span
        const bitStart = bit[0];
        const bitSpan = bitStart - bit[1] + 1;
        for (let l = 0; l < bitSpan; l++, k++) {
          binArray[len - 1 - bitStart + l] = fieldBin[k];
        }
      }
    }
  }

  // Join bit array
  let bin = binArray.join('');

  // If sign extending, truncate leading 0s to only include up to max bit
  const signExtend = !uimm;
  if (signExtend) {
    bin = bin.substring(len - maxBit - 1);
  }

  // Decode as coherent binary value
  return decImm(bin, signExtend);
}

// Convert register numbers from binary to string
function decReg(reg, floatReg=false) {
  return (floatReg ? 'f' : 'x') + parseInt(reg, BASE.bin);
}

// Zfa fli.*: rs1 selects one of 32 standard floating-point constants
function decFli(bits) {
  return FLI_STRINGS[parseInt(bits, BASE.bin)];
}

// V register: v0-v31, no ABI aliases
function decVReg(bits) {
  return 'v' + parseInt(bits, BASE.bin);
}

// vsetvli/vsetivli's vtypei immediate: top bits (above bit 7) must be 0
// (reserved), then vma(7)/vta(6)/vsew(5:3)/vlmul(2:0) - returns the 4
// canonical assembly tokens (e.g. ['e32', 'm1', 'ta', 'ma'])
function decVtype(bits) {
  const low8 = bits.slice(-8);
  if (/[^0]/.test(bits.slice(0, -8))) {
    throw 'Invalid vtype immediate: reserved bits must be 0';
  }
  const vma = low8[0], vta = low8[1], vsew = low8.slice(2, 5), vlmul = low8.slice(5, 8);
  const sew = V_SEW[vsew], lmul = V_LMUL[vlmul];
  if (sew === undefined) {
    throw 'Invalid vtype immediate: reserved vsew value';
  }
  if (lmul === undefined) {
    throw 'Invalid vtype immediate: reserved vlmul value';
  }
  return [sew, lmul, vta === '1' ? 'ta' : 'tu', vma === '1' ? 'ma' : 'mu'];
}

// Zcmp cm.mvsa01/cm.mva01s: 3-bit sreg field selects a restricted
// s-register - 0-1 map to s0-s1 (x8-x9), 2-7 map to s2-s7 (x18-x23)
function decSreg(bits) {
  const idx = parseInt(bits, BASE.bin);
  const regNum = idx < 2 ? 8 + idx : 16 + idx;
  return 'x' + regNum;
}

// Zcmp cm.push/cm.pop/cm.popretz/cm.popret: converts the 4-bit rlist value
// (4-15) into the {ra[, s0[-sN]]} register-list assembly operand. rlist=15
// is a special case covering all 12 s-registers (s0-s11), skipping the
// otherwise-unreachable 12-register case, since s10/s11 are always saved
// together for 16-byte stack alignment
function decRlist(rlistVal) {
  const n = rlistVal === 15 ? 13 : rlistVal - 3;
  if (n === 1) {
    return '{ra}';
  } else if (n === 2) {
    return '{ra, s0}';
  }
  return `{ra, s0-s${n - 2}}`;
}

// Zcmp: total stack adjustment in bytes for a given rlist/spimm pair -
// the byte count needed to save rlist's registers (rounded up to 16 bytes)
// plus spimm*16 bytes of extra stack space
function decStackAdj(rlistVal, spimmBits, xlenBytes, negate) {
  const n = rlistVal === 15 ? 13 : rlistVal - 3;
  const base = Math.ceil(n * xlenBytes / 16) * 16;
  const total = base + decImm(spimmBits, false) * 16;
  return negate ? -total : total;
}

// Convert register numbers from binary to ABI name string
export function decRegAbi(regDec, floatReg=false) {
  return Object.keys(
      (floatReg ? FLOAT_REGISTER : REGISTER)
    )[parseInt(regDec, BASE.dec)];
}

// Get device I/O and memory accesses corresponding to given bits
function decMem(bits) {
  let output = "";

  // I: Device input, O: device output, R: memory reads, W: memory writes
  const access = ['i', 'o', 'r', 'w'];

  // Loop through the access array and binary string
  for (let i = 0; i < bits.length; i++) {
    if (bits[i] === '1') {
      output += access[i];
    }
  }

  if (output === "") {
    throw `Invalid IO/Mem field`;
  }

  return output;
}

// Search for CSR name from the given binary string
function decCSR(binStr) {
  // Decode binary string into numerical value
  const val = parseInt(binStr, BASE.bin);

  // Attempt to search for entry in CSR object with matching value
  const entry = Object.entries(CSR).find(e => e[1] === val);

  // Get CSR name if it exists,
  //   otherwise construct an immediate hex string
  let csr = entry
    ? entry[0]
    : ('0x' + val.toString(16).padStart(3, '0'));

  return csr;
}

// search for float rounding mode name from the given binary string
function decFrm(binstr) {
  // decode binary string into numerical value
  const val = parseInt(binstr, BASE.bin);

  // attempt to search for entry in csr object with matching value
  const entry = Object.entries(FLOAT_ROUNDING_MODE).find(e => e[1] === val);
  if (entry === undefined) {
    throw `Invalid float rounding mode field`
  }

  return entry[0];
}

// Convert C instruction immediate bit configurations
//   To a string for binFrag name information
function immBitsToString(immBits) {
  let out = '[';
  let addPipe = false;
  for (const e of immBits) {
    if (!addPipe) {
      addPipe = true;
    } else {
      out += '|';
    }
    if (e instanceof Array) {
      out += e[0] + ':' + e[1];
    } else {
      out += e;
    }
  }
  return out + ']';
}

// Convert C instruction immediate bit configurations
//   To a string for binFrag name information
function regExclToString(excl) {
  if (excl.length === 1)
    return excl[0].toString();
  let out = '{';
  let addComma = false;
  for (const e of excl) {
    if (!addComma) {
      addComma = true;
    } else {
      out += ',';
    }
    out += e;
  }
  return out + '}';
}

// Render assembly instruction
function renderAsm(asmFrags, abi = false) {
  // Extract assembly tokens and build instruction
  let inst = asmFrags[0].asm;
  for (let i = 1; i < asmFrags.length; i++) {
    // Conditionally use ABI names for registers
    let asm = abi ? convertRegToAbi(asmFrags[i].asm) : asmFrags[i].asm;

    // Append delimeter
    if (i === 1) {
      inst += ' ';
    }
    else if (!asmFrags[i].mem || !/^(?:nz)?(?:u)?imm/.test(asmFrags[i-1].field)) {
      inst += ', ';
    }

    // Append assembly fragment
    if (asmFrags[i].mem) {
      inst += '(' + asm + ')';
    } else {
      inst += asm;
    }
  }

  return inst.trim();
}
