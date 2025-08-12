// scripts/generate_input.js
// Generate inputs/input.json by computing Poseidon2 permutation (BN254) for a rate=2 preimage.
// Uses the same constants as the circom circuit.
// Node.js script - no external libraries required (uses BigInt).

const fs = require('fs');
const path = require('path');
const C = require('../circuits/constants/poseidon2_t3_bn254_constants.json');

// BN254 prime field (alt_bn128 / bn128)
const P = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

function mod(a) {
  a %= P;
  if (a < 0n) a += P;
  return a;
}

function toBigInt(x) {
  if (typeof x === 'bigint') return x;
  if (typeof x === 'number') return BigInt(x);
  if (typeof x === 'string') return BigInt(x);
  return BigInt(x);
}

function pow5(x) {
  x = mod(x);
  return mod(x * x % P * x % P * x % P * x % P); // x^5 mod P
}

function mdsMul(mat, vec) {
  // mat flattened row-major t x t, vec length t
  const t = 3;
  let out = [0n,0n,0n];
  for (let i=0;i<t;i++) {
    let acc = 0n;
    for (let j=0;j<t;j++) {
      acc += toBigInt(mat[i*t + j]) * toBigInt(vec[j]);
    }
    out[i] = mod(acc);
  }
  return out;
}

function poseidon_permutation(preimage) {
  const t = C.t;
  const rate = C.rate;
  const fullRounds = C.fullRounds;
  const partialRounds = C.partialRounds;
  const RC3_EXT = C.RC3_EXT.map(s => BigInt(s));
  const RC3_INT = C.RC3_INT.map(s => BigInt(s));
  const MAT_EXT = C.MAT_EXT || [2,1,1,1,2,1,1,1,2];
  const MAT_INT = C.MAT_INT || [2,1,1,1,2,1,1,1,3];

  // initialize state
  let state = [0n,0n,0n];
  for (let i=0;i<rate;i++) {
    state[i] = mod(state[i] + toBigInt(preimage[i]));
  }

  let rc_ext_idx = 0;
  let rc_int_idx = 0;
  const totalRounds = fullRounds + partialRounds;
  for (let r=0;r<totalRounds;r++) {
    const isFull = (r < (fullRounds/2)) || (r >= (fullRounds/2 + partialRounds));
    if (isFull) {
      let a0 = mod(state[0] + RC3_EXT[rc_ext_idx++]);
      let a1 = mod(state[1] + RC3_EXT[rc_ext_idx++]);
      let a2 = mod(state[2] + RC3_EXT[rc_ext_idx++]);
      // sbox x^5 on every element
      let s0 = pow5(a0);
      let s1 = pow5(a1);
      let s2 = pow5(a2);
      // linear layer: MAT_EXT * s
      const n0 = mod(BigInt(MAT_EXT[0])*s0 + BigInt(MAT_EXT[1])*s1 + BigInt(MAT_EXT[2])*s2);
      const n1 = mod(BigInt(MAT_EXT[3])*s0 + BigInt(MAT_EXT[4])*s1 + BigInt(MAT_EXT[5])*s2);
      const n2 = mod(BigInt(MAT_EXT[6])*s0 + BigInt(MAT_EXT[7])*s1 + BigInt(MAT_EXT[8])*s2);
      state = [n0,n1,n2];
    } else {
      // partial round: add single RC to state[0]
      let b0 = mod(state[0] + RC3_INT[rc_int_idx++]);
      let sb0 = pow5(b0);
      let b1 = state[1];
      let b2 = state[2];
      const m0 = mod(BigInt(MAT_INT[0])*sb0 + BigInt(MAT_INT[1])*b1 + BigInt(MAT_INT[2])*b2);
      const m1 = mod(BigInt(MAT_INT[3])*sb0 + BigInt(MAT_INT[4])*b1 + BigInt(MAT_INT[5])*b2);
      const m2 = mod(BigInt(MAT_INT[6])*sb0 + BigInt(MAT_INT[7])*b1 + BigInt(MAT_INT[8])*b2);
      state = [m0,m1,m2];
    }
  }
  return state; // full state
}

// CLI: node scripts/generate_input.js pre0 pre1
const argv = process.argv.slice(2);
let pre0 = argv[0] || "123";
let pre1 = argv[1] || "456";
const pre = [BigInt(pre0), BigInt(pre1)];

const state = poseidon_permutation(pre);
const pubHash = state[0];

const out = {
  preimage: [pre0.toString(), pre1.toString()],
  pubHash: pubHash.toString()
};

const outPath = path.join(__dirname, '..', 'inputs', 'input.json');
fs.mkdirSync(path.join(__dirname, '..', 'inputs'), { recursive: true });
fs.writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log('Wrote', outPath);
console.log('preimage:', out.preimage, 'pubHash:', out.pubHash);
