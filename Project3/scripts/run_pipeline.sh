#!/bin/bash
set -e

echo "[1/7] 编译电路"
mkdir -p build
circom circuits/Poseidon2_t3_bn254.circom --r1cs --wasm --sym -o build

echo "[2/7] Powers of Tau"
cd build
snarkjs powersoftau new bn128 12 pot12_0000.ptau -v
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v

echo "[3/7] Groth16 Setup"
snarkjs groth16 setup Poseidon2_t3_bn254.r1cs pot12_0001.ptau Poseidon2_0000.zkey
snarkjs zkey contribute Poseidon2_0000.zkey Poseidon2_final.zkey --name="1st Contributor" -v
snarkjs zkey export verificationkey Poseidon2_final.zkey verification_key.json

echo "[4/7] 生成输入"
cd ..
node scripts/generate_input.js 123 456 789

echo "[5/7] 生成 witness"
node build/Poseidon2_t3_bn254_js/generate_witness.js     build/Poseidon2_t3_bn254_js/Poseidon2_t3_bn254.wasm     inputs/input.json     build/witness.wtns

echo "[6/7] 生成证明"
cd build
snarkjs groth16 prove Poseidon2_final.zkey witness.wtns proof.json public.json

echo "[7/7] 验证证明"
snarkjs groth16 verify verification_key.json public.json proof.json

echo "全部流程完成 ✅"
