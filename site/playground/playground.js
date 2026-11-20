const $ = (id) => document.getElementById(id);
const encoder = new TextEncoder();
let wasm = null;
let signingPair = null;
let kemPair = null;
let kemEncapsulation = null;

function bytesToHex(bytes, limit = 900) {
  const view = Array.from(bytes).slice(0, limit);
  const hex = view.map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return bytes.length > limit ? `${hex}\n… ${bytes.length - limit} more bytes` : hex;
}
function setStatus(id, message, kind = "") {
  const el = $(id);
  el.textContent = message;
  el.className = `result-status ${kind}`.trim();
}
function setKeyState(id, message, ready = false) {
  const el = $(id);
  el.innerHTML = `<span class="mini-dot"></span>${message}`;
  el.classList.toggle("ready", ready);
}
function enable(id, value = true) { $(id).disabled = !value; }
function copyText(text) {
  if (navigator.clipboard?.writeText) return navigator.clipboard.writeText(text);
  const area = document.createElement("textarea");
  area.value = text;
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.append(area);
  area.select();
  const copied = document.execCommand("copy");
  area.remove();
  if (!copied) throw new Error("Clipboard access is unavailable in this browser.");
  return Promise.resolve();
}

// Uniform sampling over the selected alphabet; do not use Math.random() for secrets.
function secureIndex(max) {
  const range = 0x100000000;
  const ceiling = Math.floor(range / max) * max;
  const sample = new Uint32Array(1);
  do { crypto.getRandomValues(sample); } while (sample[0] >= ceiling);
  return sample[0] % max;
}
function generatePassword() {
  if (!globalThis.crypto?.getRandomValues) throw new Error("Web Crypto is required. Use a secure context (HTTPS or localhost).");
  const length = Number($("password-length").value);
  const groups = [];
  if ($("pw-upper").checked) groups.push("ABCDEFGHJKLMNPQRSTUVWXYZ");
  if ($("pw-lower").checked) groups.push("abcdefghijkmnopqrstuvwxyz");
  if ($("pw-numbers").checked) groups.push("23456789");
  if ($("pw-symbols").checked) groups.push("!@#$%^&*()-_=+[]{}:,.?");
  if (!groups.length) throw new Error("Select at least one character set.");
  if (length < groups.length) throw new Error("Password length must be at least the number of selected character sets.");
  const alphabet = groups.join("");
  const chars = groups.map((group) => group[secureIndex(group.length)]);
  while (chars.length < length) chars.push(alphabet[secureIndex(alphabet.length)]);
  // Fisher–Yates shuffle with unbiased cryptographic indices.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = secureIndex(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return { password: chars.join(""), alphabetSize: alphabet.length, length };
}

for (const tab of document.querySelectorAll(".tab")) {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((item) => {
      const active = item === tab;
      item.classList.toggle("active", active);
      item.setAttribute("aria-selected", String(active));
    });
    document.querySelectorAll(".lab-panel").forEach((panel) => {
      const active = panel.id === `panel-${tab.dataset.panel}`;
      panel.hidden = !active;
      panel.classList.toggle("hidden", !active);
    });
  });
}

$("sign-message").addEventListener("input", (event) => {
  $("message-length").textContent = `${encoder.encode(event.target.value).length} / 4096 bytes`;
});
$("generate-sign-key").addEventListener("click", () => {
  try {
    if (signingPair) signingPair.free();
    signingPair = wasm.WasmMlDsa65KeyPair.generate();
    $("sign-public-key").textContent = bytesToHex(signingPair.public_key());
    $("sign-signature").textContent = "Sign a message to generate a detached signature.";
    enable("sign-message-btn");
    enable("verify-signature-btn", false);
    document.querySelector('[data-copy="sign-public-key"]').disabled = false;
    document.querySelector('[data-copy="sign-signature"]').disabled = true;
    setKeyState("sign-key-state", "ML-DSA-65 key pair ready · private key remains in WASM", true);
    setStatus("sign-result", "Key pair generated successfully.", "success");
  } catch (error) { setStatus("sign-result", error.message, "error"); }
});
$("sign-message-btn").addEventListener("click", () => {
  try {
    if (!signingPair) throw new Error("Generate a key pair first.");
    const message = encoder.encode($("sign-message").value);
    const signature = signingPair.sign(message);
    window.lastSignature = signature;
    window.lastSignedMessage = message;
    $("sign-signature").textContent = bytesToHex(signature);
    document.querySelector('[data-copy="sign-signature"]').disabled = false;
    enable("verify-signature-btn");
    setStatus("sign-result", `Signature created (${signature.length} bytes). Ready to verify.`, "success");
  } catch (error) { setStatus("sign-result", error.message, "error"); }
});
$("verify-signature-btn").addEventListener("click", () => {
  try {
    if (!signingPair || !window.lastSignature) throw new Error("Create a signature first.");
    const valid = wasm.ml_dsa_65_verify(signingPair.public_key(), encoder.encode($("sign-message").value), window.lastSignature);
    setStatus("sign-result", valid ? "VALID — signature matches the current message." : "INVALID — message or signature does not match.", valid ? "success" : "error");
  } catch (error) { setStatus("sign-result", error.message, "error"); }
});

$("generate-kem-key").addEventListener("click", () => {
  try {
    if (kemPair) kemPair.free();
    if (kemEncapsulation) kemEncapsulation.free();
    kemPair = wasm.WasmMlKem768KeyPair.generate();
    kemEncapsulation = null;
    $("kem-public-key").textContent = bytesToHex(kemPair.public_key());
    $("kem-ciphertext").textContent = "Encapsulate a shared secret to generate the ciphertext.";
    document.querySelector('[data-copy="kem-public-key"]').disabled = false;
    document.querySelector('[data-copy="kem-ciphertext"]').disabled = true;
    enable("encapsulate-btn");
    enable("decapsulate-btn", false);
    setKeyState("kem-key-state", "ML-KEM-768 key pair ready · decapsulation key remains in WASM", true);
    setStatus("kem-result", "Recipient key pair generated.", "success");
  } catch (error) { setStatus("kem-result", error.message, "error"); }
});
$("encapsulate-btn").addEventListener("click", () => {
  try {
    if (!kemPair) throw new Error("Generate a key pair first.");
    kemEncapsulation = wasm.ml_kem_768_encapsulate(kemPair.public_key());
    $("kem-ciphertext").textContent = bytesToHex(kemEncapsulation.ciphertext());
    document.querySelector('[data-copy="kem-ciphertext"]').disabled = false;
    enable("decapsulate-btn");
    setStatus("kem-result", "Encapsulation complete. The sender has a shared secret; now decapsulate on the recipient side.", "success");
  } catch (error) { setStatus("kem-result", error.message, "error"); }
});
$("decapsulate-btn").addEventListener("click", () => {
  try {
    if (!kemPair || !kemEncapsulation) throw new Error("Encapsulate a secret first.");
    const received = kemPair.decapsulate(kemEncapsulation.ciphertext());
    const sent = kemEncapsulation.shared_secret();
    const equal = sent.length === received.length && sent.every((byte, index) => byte === received[index]);
    sent.fill(0);
    received.fill(0);
    kemEncapsulation.free();
    kemEncapsulation = null;
    enable("decapsulate-btn", false);
    setStatus("kem-result", equal ? "MATCH — both sides derived the same shared secret. Temporary JS copies were cleared." : "MISMATCH — the derived secrets differ.", equal ? "success" : "error");
  } catch (error) { setStatus("kem-result", error.message, "error"); }
});

$("password-length").addEventListener("input", (event) => { $("password-length-value").textContent = event.target.value; });
$("generate-password").addEventListener("click", () => {
  try {
    const result = generatePassword();
    $("password-output").textContent = result.password;
    $("password-entropy").textContent = `${result.length} characters · CSPRNG`;
    enable("copy-password");
  } catch (error) { $("password-output").textContent = error.message; $("password-entropy").textContent = ""; enable("copy-password", false); }
});
$("copy-password").addEventListener("click", async () => {
  try { await copyText($("password-output").textContent); $("password-entropy").textContent = "Copied to clipboard"; }
  catch (error) { $("password-entropy").textContent = error.message; }
});
document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    try { await copyText($(button.dataset.copy).textContent); button.textContent = "Copied"; setTimeout(() => { button.textContent = "Copy"; }, 1400); }
    catch (error) { button.textContent = "Unavailable"; }
  });
});

const challenges = [
  { question: "Which NIST standard specifies ML-DSA digital signatures?", options: ["FIPS 203", "FIPS 204", "FIPS 205"], answer: 1, explanation: "Correct. FIPS 204 standardizes ML-DSA, the Module-Lattice-Based Digital Signature Algorithm." },
  { question: "What is the primary purpose of ML-KEM?", options: ["Create digital signatures", "Establish a shared secret", "Hash a file"], answer: 1, explanation: "Correct. ML-KEM lets parties establish a shared secret using key encapsulation and decapsulation." },
  { question: "Which browser API should generate cryptographically secure random bytes?", options: ["Math.random()", "Date.now()", "crypto.getRandomValues()"], answer: 2, explanation: "Correct. Web Crypto provides cryptographically secure random values in supported secure contexts." }
];
let challengeIndex = 0;
function renderChallenge() {
  const challenge = challenges[challengeIndex];
  $("challenge-question").textContent = challenge.question;
  $("challenge-feedback").textContent = "Choose an answer to see the explanation.";
  $("challenge-options").innerHTML = "";
  challenge.options.forEach((option, index) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = `${String.fromCharCode(65 + index)} · ${option}`;
    button.addEventListener("click", () => {
      const correct = index === challenge.answer;
      [...$("challenge-options").children].forEach((item, itemIndex) => {
        item.disabled = true;
        if (itemIndex === challenge.answer) item.classList.add("correct");
        else if (itemIndex === index) item.classList.add("incorrect");
      });
      $("challenge-feedback").textContent = correct ? challenge.explanation : `Not quite. ${challenge.explanation}`;
    });
    $("challenge-options").append(button);
  });
  document.querySelector(".challenge-count").innerHTML = `CHALLENGE ${String(challengeIndex + 1).padStart(2, "0")} <span> / ${String(challenges.length).padStart(2, "0")}</span>`;
}
$("next-challenge").addEventListener("click", () => { challengeIndex = (challengeIndex + 1) % challenges.length; renderChallenge(); });
renderChallenge();

async function initializeWasm() {
  const strip = document.querySelector(".status-strip");
  try {
    const module = await import("/playground/pkg/nexusq_wasm.js");
    await module.default();
    wasm = module;
    strip.classList.add("ready");
    $("engine-dot").style.background = "var(--green)";
    $("engine-title").textContent = "NEXUS-Q WASM engine ready";
    $("engine-message").textContent = "ML-DSA-65 and ML-KEM-768 operations are available locally in this browser.";
    $("engine-tag").textContent = "READY · WASM";
    ["generate-sign-key", "generate-kem-key"].forEach((id) => enable(id));
  } catch (error) {
    strip.classList.add("error");
    $("engine-title").textContent = "WASM engine not built for this local preview yet";
    $("engine-message").textContent = "The interface is ready, but the compiled browser module is missing. Run scripts/build-playground-wasm.sh to generate it; password generation and learning challenges still work.";
    $("engine-tag").textContent = "BUILD REQUIRED";
    console.info("NEXUS-Q WASM module unavailable:", error);
  }
}
initializeWasm();
