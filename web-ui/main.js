// SPDX-License-Identifier: AGPL-3.0-or-later

/*
 * RISC-V Instruction Encoder/Decoder
 *
 * Copyright (c) 2021-2022 LupLab @ UC Davis
 */

import { Instruction, convertRegToAbi } from "../core/Instruction.js";
import { FRAG, ISA_Subsets } from "../core/Constants.js";
import { configDefault, COPTS_ISA } from "../core/Config.js";
import { buildSearchResults, clearSearchResults, renderSearchResults, iterateSearchResults, getSelectedMnemonic, buildPlaceholder, getPlaceholderString } from "./completion.js";

/* RISC-V unprivileged ISA manual base URL and per-extension chapter files.
 * Maps an instruction's `isa` tag (with any RV32/RV64/RV128 prefix
 * stripped) to the chapter it's documented in. Extensions with no entry
 * here (Sdext, Ssctr, Smrnmi, Svinval, ...) are part of the *privileged*
 * spec but have no chapter mapped below (yet). */
const MANUAL_BASE = 'https://docs.riscv.org/reference/isa/v20260120/unpriv/';
const MANUAL_CHAPTER = {
  M: 'm-st-ext.html',
  A: 'a-st-ext.html',
  F: 'f-st-ext.html',
  D: 'd-st-ext.html',
  Q: 'q-st-ext.html',
  C: 'c-st-ext.html',
  DC: 'c-st-ext.html',
  FC: 'c-st-ext.html',
  Zba: 'b-st-ext.html',
  Zbb: 'b-st-ext.html',
  Zbc: 'b-st-ext.html',
  Zbs: 'b-st-ext.html',
  Zbkb: 'scalar-crypto.html',
  Zbkx: 'scalar-crypto.html',
  Zknd: 'scalar-crypto.html',
  Zkne: 'scalar-crypto.html',
  Zknh: 'scalar-crypto.html',
  Zksed: 'scalar-crypto.html',
  Zksh: 'scalar-crypto.html',
  Zfh: 'zfh.html',
  Zfhmin: 'zfh.html',
  Zfa: 'zfa.html',
  Zifencei: 'zifencei.html',
  Zicsr: 'zicsr.html',
  Zicbo: 'cmo.html',
  Zawrs: 'zawrs.html',
  Zacas: 'zacas.html',
  Zabha: 'zabha.html',
  Zicond: 'zicond.html',
  Zimop: 'zimop.html',
  Zcmop: 'zimop.html',
  Zcb: 'zc.html',
  Zcmp: 'zc.html',
  Zcmt: 'zc.html',
  Zicfiss: 'unpriv-cfi.html',
  Zilsd: 'zilsd.html',
  V: 'v-st-ext.html',
  Zfbfmin: 'bfloat16.html',
  Zvfbfmin: 'bfloat16.html',
  Zvbb: 'vector-crypto.html',
  Zvkg: 'vector-crypto.html',
  Zvkned: 'vector-crypto.html',
  Zvknha: 'vector-crypto.html',
  Zvknhb: 'vector-crypto.html',
  Zvksed: 'vector-crypto.html',
  Zvksh: 'vector-crypto.html',
}

/* The privileged spec is a separate manual/base URL. None of these chapters
 * expose per-instruction anchors either, same as most unprivileged chapters
 * above. Ssctr shares its chapter with Smctr (the machine-level
 * counterpart); that page explicitly documents both. Svinval's base
 * sfence.w.inval/sfence.inval.ir/sinval.vma live in the Supervisor chapter
 * (same page as 'S'); its H-gated hinval.vvma/hinval.gvma (isa
 * 'Svinval_H') live in the Hypervisor chapter instead (same page as 'H') -
 * both verified by grepping each page for the actual mnemonics. */
const MANUAL_BASE_PRIV = 'https://docs.riscv.org/reference/isa/v20260120/priv/';
const MANUAL_CHAPTER_PRIV = {
  H: 'hypervisor.html',
  S: 'supervisor.html',
  System: 'machine.html',
  Ssctr: 'smctr.html',
  Smrnmi: 'rnmi.html',
  Svinval: 'supervisor.html',
  Svinval_H: 'hypervisor.html',
}

/* Sdext (external debug) is documented in a wholly separate spec/site from
 * the ISA manual above - its own base URL and versioning. Its "Sdext (ISA
 * Extension)" chapter has no per-instruction anchors and, oddly, never
 * actually names/encodes dret despite being the extension's own chapter
 * (verified directly against the live page) - still the right chapter to
 * land on, just without an anchor. */
const MANUAL_BASE_DEBUG = 'https://docs.riscv.org/reference/debug/v1.0/';
const MANUAL_CHAPTER_DEBUG = {
  Sdext: 'Sdext.html',
}

/* Most chapters in this manual version expose NO per-instruction anchors at
 * all (confirmed by fetching every chapter above and grepping for
 * `id="insns-*"`) - only B, scalar-crypto, cmo (Zicbo), zc (Zcb/Zcmp/Zcmt),
 * zicond, bfloat16, and vector-crypto actually have them. Extensions
 * omitted here fall back to linking at the chapter page. `sep` is the
 * character each chapter substitutes for `.` in the mnemonic to build the
 * anchor (most use `_`, zicond uses `-`, bfloat16.html keeps the dot
 * literally - `sep: '.'` is a no-op replace). Zbkb/Zbkx additionally get a
 * `-sc` suffix since their mnemonics duplicate ones already anchored in the
 * B chapter (e.g. `pack`, `rol`, `zip`); Zknd/Zkne/Zknh/Zksed/Zksh are
 * crypto-only and need none. vector-crypto.html anchors on the base
 * mnemonic only, dropping everything from the first dot onward (e.g.
 * `vaesdm.vv`/`vaesdm.vs` both land on `#insns-vaesdm`) - `truncate: true`
 * does that; `rename` covers the one exception where even the base name
 * differs from the anchor, `vsha2ch.vv`/`vsha2cl.vv` both collapsing to
 * `#insns-vsha2c` (the manual documents them jointly as `vsha2c[hl].vv`).
 * Zvknhb reuses Zvknha's own vsha2*.vv mnemonics (see the comment by their
 * ISA_Subsets entries), so it needs the same rename. */
const MANUAL_ANCHOR_SUPPORT = {
  Zba: { sep: '_' },
  Zbb: { sep: '_' },
  Zbc: { sep: '_' },
  Zbs: { sep: '_' },
  Zbkb: { sep: '_', suffix: '-sc' },
  Zbkx: { sep: '_', suffix: '-sc' },
  Zknd: { sep: '_' },
  Zkne: { sep: '_' },
  Zknh: { sep: '_' },
  Zksed: { sep: '_' },
  Zksh: { sep: '_' },
  Zicbo: { sep: '_' },
  Zcb: { sep: '_' },
  Zcmp: { sep: '_' },
  Zcmt: { sep: '_' },
  Zicond: { sep: '-' },
  Zilsd: { sep: '_' },
  Zfbfmin: { sep: '.' },
  Zvfbfmin: { sep: '.' },
  Zvbb: { truncate: true },
  Zvkg: { truncate: true },
  Zvkned: { truncate: true },
  Zvknha: { truncate: true, rename: { 'vsha2ch.vv': 'vsha2c', 'vsha2cl.vv': 'vsha2c' } },
  Zvknhb: { truncate: true, rename: { 'vsha2ch.vv': 'vsha2c', 'vsha2cl.vv': 'vsha2c' } },
  Zvksed: { truncate: true },
  Zvksh: { truncate: true },
}

/**
 * Builds a docs.riscv.org manual URL for the given instruction, or null if
 * its extension isn't part of the unprivileged manual (e.g. privileged/
 * hypervisor extensions) or has no dedicated chapter here.
 * @param {string} isa
 * @param {string} instName
 * @returns {string|null}
 */
function getManualUrl(isa, instName) {
  // Quad-width (RV128) variants aren't documented in this manual
  if (isa.startsWith('RV128')) {
    return null;
  }
  // The base I extension is split across two XLEN-specific chapters
  if (isa === 'RV32I') {
    return MANUAL_BASE + 'rv32.html';
  }
  if (isa === 'RV64I') {
    return MANUAL_BASE + 'rv64.html';
  }
  const ext = isa.replace(/^RV(32|64)/, '');
  const privChapter = MANUAL_CHAPTER_PRIV[ext];
  if (privChapter) {
    // None of the privileged-spec chapters expose per-instruction anchors
    return MANUAL_BASE_PRIV + privChapter;
  }
  const debugChapter = MANUAL_CHAPTER_DEBUG[ext];
  if (debugChapter) {
    return MANUAL_BASE_DEBUG + debugChapter;
  }
  const chapter = MANUAL_CHAPTER[ext];
  if (!chapter) {
    return null;
  }
  const anchorSupport = MANUAL_ANCHOR_SUPPORT[ext];
  if (!anchorSupport) {
    // No per-instruction anchor available in this chapter; land on the page.
    return MANUAL_BASE + chapter;
  }
  const base = anchorSupport.rename?.[instName]
    ?? (anchorSupport.truncate ? instName.split('.')[0] : instName.replace(/\./g, anchorSupport.sep));
  const anchor = '#insns-' + base + (anchorSupport.suffix || '');
  return MANUAL_BASE + chapter + anchor;
}

/* Define colors per frag ID */
const fragColorMap = {
  [FRAG.UNSD]: '--color-fg',
  [FRAG.CSR]: '--color-magenta',
  [FRAG.IMM]: '--color-blue',
  [FRAG.OPC]: '--color-red',
  [FRAG.PRED]: '--color-blue',
  [FRAG.RD]: '--color-green',
  [FRAG.RS1]: '--color-yellow',
  [FRAG.RS2]: '--color-magenta',
  [FRAG.RS3]: '--color-blue',
  [FRAG.SUCC]: '--color-magenta',
  [FRAG.FRM]: '--color-cyan',
}

/* Fast access to selected document elements */
const input = document.getElementById('search-input');
const inputPlaceholder = document.getElementById('search-placeholder');
const abiParameter = document.getElementById('abi');
const isaParameter = document.getElementById('isa');
const searchResults = document.getElementById('search-result-list');

/**
 * Upon loading page or changing history, trigger conversion from hash paramters
 */
let originalDocumentTitle = '';
let titlePrefix = '';
window.addEventListener('load', (e) => {
  originalDocumentTitle = document.title;
  titlePrefix = originalDocumentTitle.split(' ')[0] + ' - ';
  hashChange(e.target.location.hash);
});
window.addEventListener('popstate', (e) => {
  hashChange(e.target.location.hash);
});

function hashChange(hash) {
  if (!hash) {
    // No hash params
    // Set input field
    input.value = "";
    // Set ABI parameter
    abiParameter.checked = configDefault.ABI;
    // Set ISA parameter
    isaParameter.value = configDefault.ISA.description;

  } else {
    // Hash params present
    // Get hash parameters as a map
    let hash = window.location.hash.substring(1);
    let params = hash
      .split('&')
      .map(kv => kv.split('=', 2))
      .reduce((res, [k, v]) =>
        ({ ...res, [k]: v.replace(/\+/g, ' ') }),
        {}
      );

    // Set input field
    input.value = params.q;
    // Set ABI parameter
    abiParameter.checked = (params.abi === "true");
    // Set ISA parameter
    isaParameter.value = params.isa || configDefault.ISA.description;
  }

  // Close search results and config popup, then execute the input
  searchResults.toggleAttribute('hidden', true);
  modalDiv.style.display = "none";
  runResult(false);
}

/**
 * Input callbacks
 */
function inputChange() {
  buildSearchResults();
}
input.addEventListener('input', function (event) {
  inputChange();
});

input.addEventListener('keydown', function (event) {
  if (event.key === 'Tab' || event.key === 'Enter') {
    // Complete input with placeholder value on 'Tab' or 'Enter'
    const selectedMne = getSelectedMnemonic();
    const inputMne = input.value.trimStart().split(' ')[0]?.toLowerCase();
    if (selectedMne !== undefined && inputMne !== selectedMne) {
      input.value += getPlaceholderString() + ' ';
      event.preventDefault(); // Prevent tab-indexing to next element
      inputChange();

    } else if (event.key === 'Enter') {
      // Run conversion when getting 'Enter'
      runResult();
      // Clear placeholder
      if (input.value.length > 0) {
        searchResults.toggleAttribute('hidden', true);
      }
    }

  } else if (event.key === 'ArrowDown') {
    // Next search result when 'ArrowDown'
    iterateSearchResults(true);
    buildPlaceholder();
    event.preventDefault(); // Prevent jumping to back of input

  } else if (event.key === 'ArrowUp') {
    // Prev search result when 'ArrowUp'
    iterateSearchResults(false);
    buildPlaceholder();
    event.preventDefault(); // Prevent jumping to front of input

  } else if (event.key === 'Escape') {
    // Invalidate iterator in case someone wants to force a bad instruction
    clearSearchResults();
    event.preventDefault();
  }
});

/**
 * Search results callbacks
 */
searchResults.addEventListener('click', function(event) {
  // Get mne from clicked search result
  const mne = event.srcElement.mne;

  // No mne, exit early
  if (mne === undefined) {
    return;
  }

  // Choose whether to autocomplete or run result
  const inputMne = input.value.trimStart().split(' ')[0]?.toLowerCase();
  if (inputMne !== mne) {
    // Complete input mne
    input.value = mne + ' ';
    buildSearchResults();
  } else {
    // Otherwise, run result
    runResult();
  }

  // Refocus on input
  input.focus();
});

/**
 * Execute instruction encoding and decoding
 */
function runResult(addToHistory = true) {
  // Get the instruction from input box
  let q = input.value.trim();
  const emptyQuery = q === "";

  // Push history state and set hash
  if (addToHistory) {
    // Build hash, but make it empty if input is empty
    const hash = emptyQuery ? ' ' : '#'
                                  + 'q='    + q.replace(/\s/g, '+')
                                  + '&abi=' + abiParameter.checked
                                  + '&isa=' + isaParameter.value;
    // Only push state if hash has changed
    if (hash.trimStart() !== window.location.hash) {
      history.pushState(null, null, hash);
    }
  }

  // Set title
  document.title = emptyQuery ? originalDocumentTitle : titlePrefix + q;

  // Reset UI and exit early if query is empty
  if (q === "") {
    document.getElementById('results-container-box').style.display = 'none';
    return;
  }

  // Convert instruction
  try {
    const inst = new Instruction(q,
      {
        ABI: abiParameter.checked,
        ISA: COPTS_ISA[isaParameter.value]
      });
    renderConversion(inst, abiParameter.checked);
  } catch (error) {
    renderError(error);
  }

  // Display conversion results
  document.getElementById('results-container-box').style.display = 'initial';
}

/**
 * Render successful conversion
 * @param {Object} inst
 */
function renderConversion(inst, abi=false) {
  document.getElementById("valid-result").style.display = "inherit";
  document.getElementById("error-container").style.display = "none";
  // Display hex instruction
  document.getElementById('hex-data').innerText = '0x' + inst.hex;

  // Display format and ISA
  document.getElementById('fmt-data').innerText = inst.fmt;
  document.getElementById('isa-data').innerText = inst.isa;
  const instName = inst.name;
  const isa = inst.isa;
  const manualUrl = getManualUrl(isa, instName);
  if (manualUrl === null) {
    document.getElementById('isa-url').innerText = `Not available`
  } else {
    document.getElementById('isa-url').innerHTML = `
    <a href="${manualUrl}"
    target="_blank">${instName}</a>`
  }

  // Display assembly instruction
  let asmInst;
  let asmTokens = inst.asmFrags.map(frag => {
    let asm = abi ? convertRegToAbi(frag.asm) : frag.asm;
    let color = fragColorMap[frag.id];

    if (frag.mem) {
      asm = '(' + asm + ')';
    }
    return `<span class='${"fragId-" + frag.id}' style='color:var(${color})'>${asm}</span>`;
  });

  asmInst = asmTokens[0];
  for (let i = 1; i < asmTokens.length; i++) {
    // Append delimeter
    if (i === 1) {
      asmInst += ' ';
    }
    else if (!inst.asmFrags[i].mem || !/^(?:nz)?(?:u)?imm/.test(inst.asmFrags[i-1].field)) {
      asmInst += ', ';
    }

    // Append assembly fragment
    asmInst += asmTokens[i];
  }
  document.getElementById('asm-data').innerHTML = asmInst;

  // Display binary instruction
  let idx = 0;
  let binaryData = "";
  let binaryDiv = document.getElementById('binary-data');
  binaryDiv.innerHTML = "";
  let fragIdList = new Set();
  inst.binFrags.forEach(frag => {
    let color = fragColorMap[frag.id];

    // Separate bits into binary fragments
    let binaryFragment = document.createElement("span");
    binaryFragment.classList.add("binary-fragment");
    // Add fragID for each binary fragments
    binaryFragment.classList.add("fragId-" + frag.id);
    fragIdList.add("fragId-" + frag.id);
    binaryDiv.appendChild(binaryFragment);

    // Create tooltip for each fragment
    let tooltipFragment = document.createElement("span");
    tooltipFragment.textContent = frag.field + ((frag.id === FRAG.UNSD) ? " (unused)" : "");
    tooltipFragment.classList.add("binary-tooltip");
    binaryFragment.appendChild(tooltipFragment);

    // Add bits into each fragment
    let fragEndPosition = idx + frag.bits.length;
    [...frag.bits].forEach(bit => {
      let bitElm = `<span class='binary-bit' style='color: var(${color})'>${bit}</span>`;
      binaryFragment.innerHTML += bitElm;
      binaryData += bit;
      idx++;

      // Separate between every 4 bits
      if (idx%4 === 0) {
        if (idx === fragEndPosition) {
          binaryDiv.innerHTML += ' ';
        }
        else {
          binaryFragment.innerHTML += ' ';
        }
      }

      // A responsive break for every 16 bits
      if (idx%16 === 0) {
        if (idx === fragEndPosition) {
          binaryDiv.innerHTML += "<br class='binary-break'>";
        }
        else {
          binaryFragment.innerHTML += "<br class='binary-break'>";
        }
      }
    });
  });

  // Highlight feature
  let superHighlight = "var(--color-co)";
  let subHighlight = "var(--color-fd)";

  // Handle tooltip highlight for binary fragment. Info label only appears when showLabel is set true
  // Pass the event as parameter to detect the tooltip position on the screen using 'client'
  let tooltipBinaryDisplay = (binDiv, isDisplay, showLabel = false, event = null) => {
    // Set the options based on isDisplay
    let visibility = (isDisplay && showLabel)?"visible":"hidden";
    let backgroundColor = (isDisplay)?((showLabel)?superHighlight:subHighlight):"inherit";
    binDiv.childNodes.forEach(child => {
      if (child.classList) {
        // Handle binary bits
        if (child.classList.contains("binary-bit")) {
          child.style.backgroundColor = backgroundColor;
        }
        // Handle binary tooltip
        else if (child.classList.contains("binary-tooltip")) {
          child.style.visibility = visibility;

          // If the binary tooltip is pointed, display the information at the cursor
          if (visibility == "visible") {
            const x = event.clientX + 10;
            const y = event.clientY + 10;
            child.style.left = x + "px";
            child.style.top = y + "px";
          }
        }
      }
    });
  }

    // Pass the event as parameter to detect the tooltip position on the screen using 'client'
  let binDivMouseHandle = (binDiv, binDivList, isMouseOver, asmDiv = null, event = null) => {
    // Super highlighted for binary div
    tooltipBinaryDisplay(binDiv, isMouseOver, true, event);

    // Light highlighted for ASM div and other binary div
    if (asmDiv !== null)
      tooltipAsmDisplay(asmDiv, isMouseOver);

    for (let otherKey in binDivList) {
      let otherBinDiv = binDivList[otherKey];
      if (otherBinDiv !== binDiv) {
        tooltipBinaryDisplay(otherBinDiv, isMouseOver, false, event);
      }
    }
  }

  // Handle tooltip highlight for assembly fragment
  let tooltipAsmDisplay = (asmDiv, isDisplay, isSuper = false) => {
    asmDiv.style.backgroundColor = (isDisplay)?(isSuper?superHighlight:subHighlight):"inherit";
  }

  // Handle the tooltip function for each fragID
  fragIdList.forEach(id => {
    let fragList = document.getElementsByClassName(id);

    let asmDiv = null;
    let binDivList = {...fragList};
    if (id !== "fragId-" + FRAG.UNSD) {
      // ASM div is the first div in fragList
      asmDiv = fragList[0];
      // The rest is BIN fragments, so remove the first element (which is ASM)
      delete binDivList[0];

      // Handle tooltip for ASM div
      asmDiv.addEventListener("mousemove", () => {
        tooltipAsmDisplay(asmDiv, true, true);
        // Only highlight binary bits, but not show info label
        for (let key in binDivList) {
          tooltipBinaryDisplay(binDivList[key], true);
        }
      });

      // Remove highlight if hover out
      asmDiv.addEventListener("mouseout", () => {
        tooltipAsmDisplay(asmDiv, false);
        // Stop highlighted for other corresponding binary fragments
        for (let key in binDivList) {
          tooltipBinaryDisplay(binDivList[key], false);
        }
      });
    }

    // Handle tooltip for binary div
    for (let key in binDivList) {
      let binDiv = binDivList[key];
      binDiv.addEventListener("mousemove", (event) => {
        binDivMouseHandle(binDiv, binDivList, true, asmDiv, event);
      })

      // Remove highlight if hover out
      binDiv.addEventListener("mouseout", () => {
        binDivMouseHandle(binDiv, binDivList, false, asmDiv);
      });
    }
  })

  // Copy button function
  let copyBtn = {
    "asm-copy": inst.asm,
    "binary-copy": binaryData,
    "hex-copy": '0x' + inst.hex
  }

  for (let buttonId in copyBtn) {
    let button = document.getElementById(buttonId);
    button.addEventListener("click", () => {
      navigator.clipboard.writeText(copyBtn[buttonId]);
    })
  }

  // Populate button function
  let populateBtn = {
    "asm-populate": inst.asm,
    "binary-populate": binaryData,
    "hex-populate": '0x' + inst.hex
  }

  for (let buttonId in populateBtn) {
    let button = document.getElementById(buttonId);
    button.addEventListener("click", () => {
      input.value = populateBtn[buttonId];
      input.focus(); // Pop up text cursor in the instruction input
    });
  }
}

/**
 * Render conversion error
 * @param {String} error
 */
function renderError(error) {
  // log them to the console - this provides an quick way to get a traceback in the browser
  console.error(error);

  const resultsContainerElm = document.getElementById('error-container');
  resultsContainerElm.style.display = "inherit";
  document.getElementById("valid-result").style.display = "none";

  // Reset result container
  resultsContainerElm.innerHTML = '';

  // Create row title + data
  let errorTitle = document.createElement('div')
  errorTitle.classList.add('result-row', 'result-row-title');
  errorTitle.textContent = 'Error = '

  let errorData = document.createElement('div')
  errorData.id = "error-row";
  errorData.style.color = 'var(--color-red)';
  errorData.textContent = error;

  // Display row
  resultsContainerElm.append(errorTitle);
  resultsContainerElm.append(errorData);
}

/**
 * Focus on input box when pressing '/'
 */
document.addEventListener("keydown", e => {
  // Ignore any other keys than '/'
  if (e.key !== "/" || e.ctrlKey || e.metaKey)
    return;
  // Ignore event if focus is currently in a form
  if (/^(?:input|textarea|select|button)$/i.test(e.target.tagName))
    return;

  e.preventDefault();
  input.focus();
});

// Control the modal div
const modalDiv = document.getElementById("modal-container");
const parameterBtn = document.getElementById("parameter-button");
const closeBtn = document.getElementById('close');
const isaMenu = document.getElementById('isa');

// Add ISA option based on Config.js provides
for (let option in COPTS_ISA) {
  let isaOption = document.createElement("option");
  isaOption.text = option;
  isaOption.value = option;
  isaMenu.add(isaOption);
}

// When user clicks the button, display the modal div
parameterBtn.addEventListener("click", () => {
    modalDiv.style.display = "block";
  }
);

// When user clicks the close button or outside the modal div, close the div and update the result
function updateParameter() {
  modalDiv.style.display = "none";

  // Update input and search results
  const hidingSearchResults = searchResults.hasAttribute('hidden');
  inputChange();

  // Continue hiding search results if previously hidden
  if (hidingSearchResults) {
    searchResults.toggleAttribute('hidden', true);
  }

  // Run the input using the new settings
  runResult();
}

closeBtn.addEventListener("click", () => {
  updateParameter();
})

window.addEventListener("click", (event) => {
    if (event.target == modalDiv) {
      updateParameter();
    }
  }
)

// Add ISA to sidebar
const isaSideBar = document.getElementById("isa-sets-container");
for (let ISA_Type in ISA_Subsets) {
  const isaSet = document.createElement("details");
  const isaSetSummary = document.createElement("summary");
  isaSetSummary.textContent = ISA_Type;
  isaSetSummary.classList = "result-row-data";
  isaSet.appendChild(isaSetSummary);

  for (let inst in ISA_Subsets[ISA_Type]) {
    const instNode = document.createElement("button");
    instNode.textContent = inst;
    instNode.classList = "asm-data asm-button";
    instNode.onclick = ()=>{
      input.value = inst;
      runResult();
    }
    isaSet.appendChild(instNode);
  }
  
  isaSideBar.appendChild(isaSet);
}
isaSideBar.style.display = 'initial';

// Filter ISA extensions / instructions in the sidebar
const isaSearchInput = document.getElementById('isa-search-input');
isaSearchInput.addEventListener('input', () => {
  const query = isaSearchInput.value.trim().toLowerCase();

  for (const isaSet of isaSideBar.children) {
    const summary = isaSet.querySelector('summary');
    const extMatches = summary.textContent.toLowerCase().includes(query);
    let anyInstMatches = false;

    for (const instNode of isaSet.querySelectorAll('button')) {
      const instMatches = extMatches || instNode.textContent.toLowerCase().includes(query);
      instNode.classList.toggle('filtered-out', !instMatches);
      anyInstMatches ||= instMatches;
    }

    // Only hide extensions with no match; leave open/closed state as the
    // user left it instead of forcing matches open.
    isaSet.classList.toggle('filtered-out', !anyInstMatches);
  }
});
