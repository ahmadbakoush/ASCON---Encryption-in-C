#include <stdio.h>
#include <stdint.h>

#define ASCON_128_RATE 8
#define CRYPTO_ABYTES 16
// Define the state size (Ascon uses a 320-bit state: 5 x 64-bit words)
#define ASCON_STATE_WORDS 5



/* get byte from 64-bit Ascon word */
#define GETBYTE(x, i) ((uint8_t)((uint64_t)(x) >> (56 - 8 * (i))))

/* set byte in 64-bit Ascon word */
#define SETBYTE(b, i) ((uint64_t)(b) << (56 - 8 * (i)))

/* set padding byte in 64-bit Ascon word */
#define PAD(i) SETBYTE(0x80, i)

/* define domain separation bit in 64-bit Ascon word */
#define DSEP() SETBYTE(0x01, 7)

/* load bytes into 64-bit Ascon word */
static inline uint64_t LOADBYTES(const uint8_t* bytes, int n) {
  int i;
  uint64_t x = 0;
  for (i = 0; i < n; ++i) x |= SETBYTE(bytes[i], i);
  return x;
}

/* store bytes from 64-bit Ascon word */
static inline void STOREBYTES(uint8_t* bytes, uint64_t x, int n) {
  int i;
  for (i = 0; i < n; ++i) bytes[i] = GETBYTE(x, i);
}

/* clear bytes in 64-bit Ascon word */
static inline uint64_t CLEARBYTES(uint64_t x, int n) {
  int i;
  for (i = 0; i < n; ++i) x &= ~SETBYTE(0xff, i);
  return x;
}

void printDemo(unsigned char c, unsigned char* x, unsigned long long xlen) {
  unsigned long long i;
  printf("%c[%d]=", c, (int)xlen);
  for (i = 0; i < xlen; ++i) printf("%02x", x[i]);
  printf("\n");
}

// Rotation macro
#define ROR64(x,n) (((x) >> (n)) | ((x) << (64 - (n))))


/**
 * Ascon Round Constants.
 * These are 8-bit constants (0xf0...0x4b) applied to the least significant
 * byte of the third state word (x_2).
 * * They serve to break the symmetry between rounds, preventing "slide attacks".
 */
static const uint64_t ASCON_ROUND_CONSTANTS[12] = {
    0x00000000000000f0ULL, 0x00000000000000e1ULL,
    0x00000000000000d2ULL, 0x00000000000000c3ULL,
    0x00000000000000b4ULL, 0x00000000000000a5ULL,
    0x0000000000000096ULL, 0x0000000000000087ULL,
    0x0000000000000078ULL, 0x0000000000000069ULL,
    0x000000000000005aULL, 0x000000000000004bULL
};

/**
 * @brief Adds the Round Constant ($p_C$).
 * * This function XORs a specific 64-bit constant into the third word
 * of the state ($x_2$).
 * * @param state The 320-bit internal state.
 * @param round_index The current loop index (0 to num_rounds - 1).
 * @param num_rounds The total number of rounds being performed (usually 12 or 6).
 */
void add_round_constant(uint64_t state[5], int round_index, int num_rounds) {
    /*
       Calculate the constant index.
       Ascon always uses the *last* N constants from the table of 12.
       - If num_rounds is 12: We use indices 0 through 11.
       - If num_rounds is 6:  We use indices 6 through 11.
    */
    int constant_idx = 12 - num_rounds + round_index;

    // Apply the constant to word x_2
    state[2] ^= ASCON_ROUND_CONSTANTS[constant_idx];
}

/**
 * @brief Applies the Substitution Layer ($p_S$).
 * * This function applies a 5-bit S-box to each of the 64 columns of the
 * state (bit-slicing). It provides the non-linearity (confusion) for the cipher.
 * * The Ascon S-box is lightweight and defined by a combination of:
 * 1. An initial affine transformation.
 * 2. A core Chi ($\chi$) non-linear mapping (similar to Keccak/SHA-3).
 * 3. A final affine transformation.
 *
 * @param state The 320-bit internal state (5 x 64-bit words).
 */
void substitution_layer(uint64_t state[5]) {
   // --- Part 1: Initial Linear Transformation ---
    // Mixes inputs to prepare for the core non-linear step.
    state[0] ^= state[4];
    state[4] ^= state[3];
    state[2] ^= state[1];

    // --- Part 2: The Core Non-Linear S-box (Chi Mapping) ---
    // Instead of a temporary array, we compute the updates directly.
    // The logic is: x_i <= x_i ^ ((not x_{i+1}) & x_{i+2})
    // We use temporary variables t0-t4 to read the state before overwriting it.

    uint64_t t0 = state[0] ^ (~state[1] & state[2]);
    uint64_t t1 = state[1] ^ (~state[2] & state[3]);
    uint64_t t2 = state[2] ^ (~state[3] & state[4]);
    uint64_t t3 = state[3] ^ (~state[4] & state[0]);
    uint64_t t4 = state[4] ^ (~state[0] & state[1]);

    // Update state with the non-linear results
    state[0] = t0;
    state[1] = t1;
    state[2] = t2;
    state[3] = t3;
    state[4] = t4;

    // --- Part 3: Final Linear Transformation ---
    // Further mixing and a NOT operation on the middle word.
    state[1] ^= state[0];
    state[0] ^= state[4];
    state[3] ^= state[2];
    state[2] = ~state[2]; // Invert bits in the middle word
}


/**
 * @brief Applies the Linear Diffusion Layer ($p_L$).
 * * This function applies a linear transformation to each of the five
 * 64-bit words in the state independently. It uses xor-rotations
 * to diffuse bits within each word.
 *
 * @param state The 320-bit internal state (5 x 64-bit words).
 */
void linear_diffusion_layer(uint64_t state[5]) {

   // Sigma_0(x_0) = x_0 ^ (x_0 >>> 19) ^ (x_0 >>> 28)
    state[0] ^= ROR64(state[0], 19) ^ ROR64(state[0], 28);

    // Sigma_1(x_1) = x_1 ^ (x_1 >>> 61) ^ (x_1 >>> 39)
    state[1] ^= ROR64(state[1], 61) ^ ROR64(state[1], 39);

    // Sigma_2(x_2) = x_2 ^ (x_2 >>> 1)  ^ (x_2 >>> 6)
    state[2] ^= ROR64(state[2],  1) ^ ROR64(state[2],  6);

    // Sigma_3(x_3) = x_3 ^ (x_3 >>> 10) ^ (x_3 >>> 17)
    state[3] ^= ROR64(state[3], 10) ^ ROR64(state[3], 17);

    // Sigma_4(x_4) = x_4 ^ (x_4 >>> 7)  ^ (x_4 >>> 41)
    state[4] ^= ROR64(state[4],  7) ^ ROR64(state[4], 41);
}
/**
 * @brief Performs the cryptographic permutation on the state.
 * * This function iterates through a specified number of rounds, applying the
 * Substitution-Permutation Network (SPN) structure:
 * 1. Addition of Round Constants
 * 2. Substitution Layer
 * 3. Linear Diffusion Layer
 *
 * @param state The 320-bit internal state (5 x 64-bit words).
 * This array is modified in place.
 * @param num_rounds The number of rounds to execute (usually 12 for Ascon-128).
 */
void apply_permutation(uint64_t state[5], int num_rounds)// Iterate through the requested number of rounds
  {
      for (int i = 0; i < num_rounds; i++) {

        // Step 1: Add Round Constant ($p_C$)
        // XORs a round-specific constant into the state (usually x_2)
        add_round_constant(state, i, num_rounds);

        // Step 2: Substitution Layer ($p_S$)
        // Applies a non-linear 5-bit S-box to the state columns
        substitution_layer(state);

        // Step 3: Linear Diffusion Layer ($p_L$)
        // Mixes the bits within each 64-bit word to provide diffusion
        linear_diffusion_layer(state);
    }
}

void initialization(uint64_t state[5], uint64_t key[2]) {
   apply_permutation(state, 12);
   state[3] ^= key[0];
   state[4] ^= key[1];
}


void finalization(uint64_t state[5], uint64_t key[2]) {
   state[1] ^= key[0];
   state[2] ^= key[1];
   apply_permutation(state, 12);
   state[3] ^= key[0];
   state[4] ^= key[1];

}



int ascon_aead_encrypt(unsigned char* c, unsigned long long* clen,
                       const unsigned char* m, unsigned long long mlen,
                       const unsigned char* ad, unsigned long long adlen, uint64_t nonce[2],
                       uint64_t key[2])
{
    uint64_t state[5] = { 0 };
    uint64_t IV = 0x80400c0600000000;
   /* set ciphertext size */
   *clen = mlen + CRYPTO_ABYTES;
    //initialize state
    state[0] = IV;
    state[1] = key[0];
    state[2] = key[1];
    state[3] = nonce[0];
    state[4] = nonce[1];
    initialization(state,key);

    if (adlen) {}

    state[4] = state[4] ^ 0x0000000000000001;

    while (mlen >= ASCON_128_RATE) {
     state[0] ^= LOADBYTES(m, 8);
    STOREBYTES(c,  state[0], 8);
    apply_permutation(state, 6);
    m += ASCON_128_RATE;
    c += ASCON_128_RATE;
    mlen -= ASCON_128_RATE;
  }

    state[0] = state[0] ^ LOADBYTES(m, mlen);
    STOREBYTES(c, state[0], mlen);
    state[0] = state[0] ^ PAD(mlen);
    m += mlen;
    c += mlen;


    finalization(state, key);

 /* get tag */
  STOREBYTES(c, state[3], 8);
  STOREBYTES(c + 8, state[4], 8);

}
int main()
{
    // initialize nonce, key and IV
    uint64_t nonce[2] = { 0x0001020304050607, 0x08090a0b0c0d0e0f };
    uint64_t key[2] = { 0x0001020304050607, 0x08090a0b0c0d0e0f };
    uint64_t IV = 0x80400c0600000000;
    unsigned char plaintext[32] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                         11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                         22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    unsigned char ciphertext[32] = { 0 };
    uint64_t associated_data_text[] = { 0x787878, 0x878787, 0x09090};
    unsigned long long clen = 0;
    unsigned long long mlen = 5;
    unsigned long long alen = 0;



    ascon_aead_encrypt(ciphertext,&clen, plaintext, mlen, associated_data_text, alen,nonce
                       ,key);

    printf("encrypt:\n");
    printDemo('c', ciphertext, clen - CRYPTO_ABYTES);
    printDemo('t', ciphertext + clen - CRYPTO_ABYTES, CRYPTO_ABYTES);

}
