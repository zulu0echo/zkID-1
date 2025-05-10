import { WitnessTester } from "circomkit";
import { circomkit } from "./common";
import { sha256 } from "@noble/hashes/sha2";

// 1) Base64URL → Base64 + padding
function base64urlToBase64(b64url: string) {
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (b64.length % 4)) % 4;
  return b64 + "=".repeat(pad);
}

function asciiCodes(str: string, length: number) {
  // 1) Map to BigInt char codes
  let codes = Array.from(str, (c) => BigInt(c.charCodeAt(0)));

  // 2) Truncate if too long
  if (codes.length > length) {
    codes = codes.slice(0, length);
  }

  // 3) Pad with '=' (ASCII 61) if too short
  while (codes.length < length) {
    codes.push(61n);
  }

  return codes;
}

describe("Base64Decode circuit", () => {
  let circuit: WitnessTester<["in"], ["out"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester("Base64Decode", {
      file: "base64", // your .circom filename
      template: "Base64Decode",
      params: [32], // byteLength = 32 → charLength = 44
      recompile: true,
    });
  });

  it("decodes JciGc5… correctly", async () => {
    const sd = "JciGc5bKidOGmxjuvC8LdUykaVXBXBPhBX1kXpDe-Lo";
    const b64 = base64urlToBase64(sd); // → standard Base64 (44 chars)
    const inArr = asciiCodes(b64, 44); // pad to 44
    console.log(inArr);

    // calculate the witness
    const witness = await circuit.calculateWitness({ in: inArr });

    let outputs = await circuit.readWitnessSignals(witness, ["out"]);
    console.log("out", outputs.out);
    await circuit.expectConstraintPass(witness);
  });

  // it("decodes another correctly", async () => {
  //   const sd = "WyJ1cWJ5Y0VSZlN4RXF1a0dtWGwyXzl3IiwibmFtZSIsImRlbmtlbmkiXQ";

  //   // Ensure padding to multiple of 4
  //   let paddedInput = sd;
  //   while (paddedInput.length % 4 !== 0) {
  //     paddedInput += "=";
  //   }

  //   const byteLength = Math.floor((paddedInput.length * 3) / 4); // Decoded byte length
  //   const charLength = paddedInput.length; // Input character length

  //   // console.log(`Input: "${paddedInput}" (${charLength} chars)`);
  //   // console.log(`Expected output length: ${byteLength} bytes`);

  //   // Initialize circuit with correct byteLength
  //   circuit = await circomkit.WitnessTester("Base64Decode", {
  //     file: "base64",
  //     template: "Base64Decode",
  //     params: [byteLength],
  //     recompile: true,
  //   });

  //   // Convert the string to an array of BigInt ASCII codes
  //   // Convert to array of ASCII values as BigInt
  //   const inArr = Array.from(paddedInput).map((c) => BigInt(c.charCodeAt(0)));
  //   console.log("Input array length:", inArr.length);

  //   console.log("Input array:", inArr);

  //   let claimArraySha256 = sha256(new Uint8Array(inArr.slice(0, sd.length).map(Number)));
  //   let claimArraySha256Hex = Array.from(claimArraySha256, (x) => x.toString(16).padStart(2, "0")).join("");

  //   console.log("claimArraySha256Hex", claimArraySha256Hex);
  //   console.log(claimArraySha256Hex === "25c8867396ca89d3869b18eebc2f0b754ca46955c15c13e1057d645e90def8ba");

  //   const witness = await circuit.calculateWitness({ in: inArr });
  //   let outputs = await circuit.readWitnessSignals(witness, ["out"]);

  //   // Convert the output bytes to a string
  //   const out = Array.isArray(outputs.out)
  //     ? outputs.out.map((c) => String.fromCharCode(Number(c))).join("")
  //     : String.fromCharCode(Number(outputs.out));
  //   console.log("Decoded:", out);

  //   await circuit.expectConstraintPass(witness);
  // });
});
