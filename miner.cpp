/*
 * core512: Multi-Threaded Interleaved ARMv8 Crypto Engine
 * Core Architecture: Dual-State Instruction Pipeline Interleaving
 * Target: Unlocking silicon boundaries on AArch64 hardware
 */

#include <arm_neon.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>

// Explicitly define our 128-bit vector types
typedef uint32x4_t vector_128;

// Complete 64-element SHA-256 Constant Array (K), 16-byte aligned for direct vector loading
static const uint32_t K256[64] __attribute__((aligned(16))) = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Global performance counter tracked atomically across all threads
volatile uint64_t global_hash_count = 0;

struct ThreadArgs {
    int core_id;
    uint32_t start_nonce;
};

// Helper macro to execute message schedule extensions for 4 rounds simultaneously
#define EXTEND_MSG_SCHEDULE(w0, w1, w2, w3) \
    vsha256su1q_u32(vsha256su0q_u32(w0, w1), w3, w2)

// -------------------------------------------------------------------------
// DUAL-STATE PIPELINE INTERLEAVING ENGINE
// -------------------------------------------------------------------------
inline void neon_sha256d_interleaved(
    vector_128 &st1_abcd, vector_128 &st1_efgh, vector_128* W1,
    vector_128 &st2_abcd, vector_128 &st2_efgh, vector_128* W2) 
{
    // --- PASS 1: Generate Remaining Message Schedules (Rounds 16-63) ---
    W1[4]  = EXTEND_MSG_SCHEDULE(W1[0], W1[1], W1[2], W1[3]);
    W2[4]  = EXTEND_MSG_SCHEDULE(W2[0], W2[1], W2[2], W2[3]);
    W1[5]  = EXTEND_MSG_SCHEDULE(W1[1], W1[2], W1[3], W1[4]);
    W2[5]  = EXTEND_MSG_SCHEDULE(W2[1], W2[2], W2[3], W2[4]);
    W1[6]  = EXTEND_MSG_SCHEDULE(W1[2], W1[3], W1[4], W1[5]);
    W2[6]  = EXTEND_MSG_SCHEDULE(W2[2], W2[3], W2[4], W2[5]);
    W1[7]  = EXTEND_MSG_SCHEDULE(W1[3], W1[4], W1[5], W1[6]);
    W2[7]  = EXTEND_MSG_SCHEDULE(W2[3], W2[4], W2[5], W2[6]);
    W1[8]  = EXTEND_MSG_SCHEDULE(W1[4], W1[5], W1[6], W1[7]);
    W2[8]  = EXTEND_MSG_SCHEDULE(W2[4], W2[5], W2[6], W2[7]);
    W1[9]  = EXTEND_MSG_SCHEDULE(W1[5], W1[6], W1[7], W1[8]);
    W2[9]  = EXTEND_MSG_SCHEDULE(W2[5], W2[6], W2[7], W2[8]);
    W1[10] = EXTEND_MSG_SCHEDULE(W1[6], W1[7], W1[8], W1[9]);
    W2[10] = EXTEND_MSG_SCHEDULE(W2[6], W2[7], W2[8], W2[9]);
    W1[11] = EXTEND_MSG_SCHEDULE(W1[7], W1[8], W1[9], W1[10]);
    W2[11] = EXTEND_MSG_SCHEDULE(W2[7], W2[8], W2[9], W2[10]);
    W1[12] = EXTEND_MSG_SCHEDULE(W1[8], W1[9], W1[10], W1[11]);
    W2[12] = EXTEND_MSG_SCHEDULE(W2[8], W2[9], W2[10], W2[11]);
    W1[13] = EXTEND_MSG_SCHEDULE(W1[9], W1[10], W1[11], W1[12]);
    W2[13] = EXTEND_MSG_SCHEDULE(W2[9], W2[10], W2[11], W2[12]);
    W1[14] = EXTEND_MSG_SCHEDULE(W1[10], W1[11], W1[12], W1[13]);
    W2[14] = EXTEND_MSG_SCHEDULE(W2[10], W2[11], W2[12], W2[13]);
    W1[15] = EXTEND_MSG_SCHEDULE(W1[11], W1[12], W1[13], W1[14]);
    W2[15] = EXTEND_MSG_SCHEDULE(W2[11], W2[12], W2[13], W2[14]);

    // --- PASS 1: Interleaved Hashing Loop (64 Rounds) ---
    #pragma GCC unroll 16
    for (int i = 0; i < 16; i++) {
        vector_128 k_vec = vld1q_u32(&K256[i * 4]);

        vector_128 wk1 = vaddq_u32(W1[i], k_vec);
        vector_128 wk2 = vaddq_u32(W2[i], k_vec);

        vector_128 temp1 = st1_abcd;
        vector_128 temp2 = st2_abcd;

        // Alternating pipelines to saturate instruction execution ports completely
        st1_abcd = vsha256hq_u32(st1_abcd, st1_efgh, wk1);
        st2_abcd = vsha256hq_u32(st2_abcd, st2_efgh, wk2);

        st1_efgh = vsha256h2q_u32(st1_efgh, temp1, wk1);
        st2_efgh = vsha256h2q_u32(st2_efgh, temp2, wk2);
    }

    // --- PASS 2: Setup Dynamic Input Blocks for Second Hash Layer (SHA-256d) ---
    // Output of Pass 1 acts as message input for Pass 2, appended with standard 512-bit block padding
    vector_128 W1_p2[16], W2_p2[16];
    
    W1_p2[0] = st1_abcd; // First 128 bits of digest
    W2_p2[0] = st2_abcd;
    W1_p2[1] = st1_efgh; // Next 128 bits of digest
    W2_p2[1] = st2_efgh;
    
    // Constant message blocks for SHA-256d Second Pass Padding
    W1_p2[2] = W2_p2[2] = vmake_u32(0x80000000, 0, 0, 0); // End of message indicator bit
    W1_p2[3] = W2_p2[3] = vdupq_n_u32(0);
    W1_p2[4] = W2_p2[4] = vdupq_n_u32(0);
    W1_p2[5] = W2_p2[5] = vdupq_n_u32(0);
    W1_p2[6] = W2_p2[6] = vdupq_n_u32(0);
    W1_p2[7] = W2_p2[7] = vmake_u32(0, 0, 0, 256);      // Message bit-length field (256 bits)

    // Reset initialization states back to default SHA-256 Hashing Constants
    st1_abcd = st2_abcd = vmake_u32(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a);
    st1_efgh = st2_efgh = vmake_u32(0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19);

    // Expand second pass message schedule maps
    W1_p2[4] = EXTEND_MSG_SCHEDULE(W1_p2[0], W1_p2[1], W1_p2[2], W1_p2[3]);
    W2_p2[4] = EXTEND_MSG_SCHEDULE(W2_p2[0], W2_p2[1], W2_p2[2], W2_p2[3]);
    W1_p2[5] = EXTEND_MSG_SCHEDULE(W1_p2[1], W1_p2[2], W1_p2[3], W1_p2[4]);
    W2_p2[5] = EXTEND_MSG_SCHEDULE(W2_p2[1], W2_p2[2], W2_p2[3], W2_p2[4]);
    W1_p2[6] = EXTEND_MSG_SCHEDULE(W1_p2[2], W1_p2[3], W1_p2[4], W1_p2[5]);
    W2_p2[6] = EXTEND_MSG_SCHEDULE(W2_p2[2], W2_p2[3], W2_p2[4], W2_p2[5]);
    W1_p2[7] = EXTEND_MSG_SCHEDULE(W1_p2[3], W1_p2[4], W1_p2[5], W1_p2[6]);
    W2_p2[7] = EXTEND_MSG_SCHEDULE(W2_p2[3], W2_p2[4], W2_p2[5], W2_p2[6]);
    #pragma GCC unroll 8
    for(int j = 8; j < 16; j++) {
        W1_p2[j] = EXTEND_MSG_SCHEDULE(W1_p2[j-4], W1_p2[j-3], W1_p2[j-2], W1_p2[j-1]);
        W2_p2[j] = EXTEND_MSG_SCHEDULE(W2_p2[j-4], W2_p2[j-3], W2_p2[j-2], W2_p2[j-1]);
    }

    // --- PASS 2: Interleaved Hashing Loop (64 Rounds) ---
    #pragma GCC unroll 16
    for (int i = 0; i < 16; i++) {
        vector_128 k_vec = vld1q_u32(&K256[i * 4]);

        vector_128 wk1 = vaddq_u32(W1_p2[i], k_vec);
        vector_128 wk2 = vaddq_u32(W2_p2[i], k_vec);

        vector_128 temp1 = st1_abcd;
        vector_128 temp2 = st2_abcd;

        st1_abcd = vsha256hq_u32(st1_abcd, st1_efgh, wk1);
        st2_abcd = vsha256hq_u32(st2_abcd, st2_efgh, wk2);

        st1_efgh = vsha256h2q_u32(st1_efgh, temp1, wk1);
        st2_efgh = vsha256h2q_u32(st2_efgh, temp2, wk2);
    }
}

// -------------------------------------------------------------------------
// THREAD LOGIC & RESOURCE ISOLATION
// -------------------------------------------------------------------------
void* mine_on_core(void* arg) {
    ThreadArgs* args = (ThreadArgs*)arg;

    // Hardcode affinity mask to lock execution to designated hardware thread
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(args->core_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    uint32_t nonce_tracker_1 = args->start_nonce;
    uint32_t nonce_tracker_2 = args->start_nonce + 1;

    // Local static data buffer allocations (simulating raw block data structures)
    vector_128 W1[16] __attribute__((aligned(16))) = {vdupq_n_u32(0)};
    vector_128 W2[16] __attribute__((aligned(16))) = {vdupq_n_u32(0)};

    // Set static cryptographic padding elements for Pass 1
    W1[4] = W2[4] = vmake_u32(0x80000000, 0, 0, 0); 
    W1[15] = W2[15] = vmake_u32(0, 0, 0, 640); // 80-byte header = 640 bits

    while (true) {
        // Embed the unique, non-overlapping nonces directly inside Word 3 lanes
        W1[0] = vmake_u32(0x1a2b3c4d, 0x5e6f7a8b, 0x9c0d1e2f, nonce_tracker_1);
        W2[0] = vmake_u32(0x1a2b3c4d, 0x5e6f7a8b, 0x9c0d1e2f, nonce_tracker_2);

        // Standard SHA-256 Initialization Vectors
        vector_128 st1_abcd = vmake_u32(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a);
        vector_128 st1_efgh = vmake_u32(0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19);
        vector_128 st2_abcd = vmake_u32(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a);
        vector_128 st2_efgh = vmake_u32(0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19);

        // Execute processing pipeline
        neon_sha256d_interleaved(st1_abcd, st1_efgh, W1, st2_abcd, st2_efgh, W2);

        // Update tracking states concurrently by a factor of two
        nonce_tracker_1 += 2;
        nonce_tracker_2 += 2;

        // Atomically increment the global counter by 2 completed executions
        __atomic_fetch_add(&global_hash_count, 2, __ATOMIC_RELAXED);
    }
    return NULL;
}

// -------------------------------------------------------------------------
// MAIN INITIALIZATION MONITOR
// -------------------------------------------------------------------------
int main() {
    int hardware_cores = sysconf(_SC_NPROCESSORS_ONLN);
    printf("[*] core512 active. Found %d execution structures.\n", hardware_cores);

    pthread_t execution_pool[8];
    ThreadArgs resource_configs[8];

    // Allocate isolated thread loops directly across the environment's core map
    for (int i = 0; i < hardware_cores && i < 8; i++) {
        resource_configs[i].core_id = i;
        resource_configs[i].start_nonce = i * 20000000; 
        pthread_create(&execution_pool[i], NULL, mine_on_core, &resource_configs[i]);
    }

    // Dedicated background reporting telemetry thread
    while (true) {
        sleep(1);
        uint64_t performance_snapshot = __atomic_exchange_n(&global_hash_count, 0, __ATOMIC_RELAXED);
        printf("Current Pipeline Performance: %.3f MH/s\n", (double)performance_snapshot / 1000000.0);
    }

    return 0;
}
