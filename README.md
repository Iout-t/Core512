# core512

An ultra-optimized, multi-threaded SHA-256d mining engine designed explicitly for ARMv8-A architecture utilizing hardware-level cryptographic extensions and dual-state pipeline interleaving.

## Features
- **Hardware-Intrinsic Bypass:** Bypasses software-level algebraic formulas by routing calculations directly through dedicated ARM NEON cryptography silicon slots (`vsha256hq_u32`).
- **Dual-State Pipeline Interleaving:** Concurrently processes two independent hash states within a single thread to eliminate CPU pipeline execution port stalls.
- **Bare-Metal Core Affinity:** Bypasses the default Android OS thread scheduler by hard-pinning threads directly to physical CPU cores via `pthread_setaffinity_np`.

## Requirements
- An ARMv8-A (or higher) AArch64 Android device.
- A terminal environment like **Termux**.
- `clang++` and `cmake` installed.

## Compilation Instructions
Open your terminal environment on the device and run the following commands:

```bash
# Clone the repository
git clone [https://github.com/YOUR_USERNAME/ctminer-core512.git](https://github.com/YOUR_USERNAME/ctminer-core512.git)
cd ctminer-arm-extreme

# Create a build directory
mkdir build && cd build

# Configure and compile using CMake
cmake ..
make -j$(nproc)
