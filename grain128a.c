#include <stdio.h>
#include <stdint.h>

/*
 * Define "PRE" to print the pre-output instead of keystream.
 * Define "INIT" to also print the bits during the initialization part.
 * Do this either here or during compilation with -D flag.
 */

uint8_t init_rounds = 0;
uint8_t auth_mode = 0;

typedef struct {
	uint8_t lfsr[128];
	uint8_t nfsr[128];
	uint8_t auth_acc[32];
	uint8_t auth_sr[32];
} grain_state;

void init_grain(grain_state *grain, uint8_t *key, uint8_t *iv)
{
	grain->lfsr[0] = 0;
	for (int i = 1; i < 32; i++) {
		grain->lfsr[i] = 1;
	}

	for (int i = 32; i < 127; i++) {
		grain->lfsr[i] = 0;
	}
	grain->lfsr[127] = 1;
	if (grain->lfsr[127] == 1) auth_mode = 1;

	for (int i = 0; i < 128; i++) {
		grain->nfsr[i] = 0;
	}

	for (int i = 0; i < 32; i++) {
		grain->auth_acc[i] = 0;
		grain->auth_sr[i] = 0;
	}
}

uint8_t next_lfsr_fb(grain_state *grain)
{
 	/* f(x) = 1 + x^32 + x^47 + x^58 + x^90 + x^121 + x^128 */
	return grain->lfsr[31] ^ grain->lfsr[46] ^ grain->lfsr[57] ^ grain->lfsr[89] ^ grain->lfsr[120] ^ grain->lfsr[127];
}

uint8_t next_nfsr_fb(grain_state *grain)
{
	return grain->nfsr[31] ^ grain->nfsr[36] ^ grain->nfsr[71] ^ grain->nfsr[101] ^ grain->nfsr[127] ^ (grain->nfsr[43] & grain->nfsr[59]) ^
			(grain->nfsr[60] & grain->nfsr[124]) ^ (grain->nfsr[62] & grain->nfsr[66]) ^ (grain->nfsr[68] & grain->nfsr[100]) ^
			(grain->nfsr[79] & grain->nfsr[87]) ^ (grain->nfsr[109] & grain->nfsr[110]) ^ (grain->nfsr[114] & grain->nfsr[116]) ^
			(grain->nfsr[45] & grain->nfsr[49] & grain->nfsr[57]) ^ (grain->nfsr[102] & grain->nfsr[103] & grain->nfsr[105]) ^
			(grain->nfsr[32] & grain->nfsr[34] & grain->nfsr[35] & grain->nfsr[39]);
}

uint8_t next_h(grain_state *grain)
{
	// h(x) = x0x1 + x2x3 + x4x5 + x6x7 + x0x4x8
	#define x0 grain->nfsr[128-12-1]	// bi+12
	#define x1 grain->lfsr[128-8-1]		// si+8
	#define x2 grain->lfsr[128-13-1]	// si+13
	#define x3 grain->lfsr[128-20-1]	// si+20
	#define x4 grain->nfsr[128-95-1]	// bi+95
	#define x5 grain->lfsr[128-42-1]	// si+42
	#define x6 grain->lfsr[128-60-1]	// si+60
	#define x7 grain->lfsr[128-79-1]	// si+79
	#define x8 grain->lfsr[128-94-1]	// si+94

	uint8_t h_out = (x0 & x1) ^ (x2 & x3) ^ (x4 & x5) ^ (x6 & x7) ^ (x0 & x4 & x8);
	return h_out;
}

uint8_t shift(uint8_t fsr[128], uint8_t fb)
{
	uint8_t out = fsr[127];
	for (int i = 127; i > 0; i--) {
		fsr[i] = fsr[i-1];
	}
	fsr[0] = fb;

	return out;
}

uint8_t next_z(grain_state *grain)
{
	uint8_t lfsr_fb = next_lfsr_fb(grain);
	uint8_t nfsr_fb = next_nfsr_fb(grain);
	uint8_t h_out = next_h(grain);

	/* y = h + s_{i+93} + sum(b_{i+j}), j \in A */
	uint8_t A[] = {2, 15, 36, 45, 64, 73, 89};

	uint8_t nfsr_tmp = 0;
	for (int i = 0; i < 7; i++) {
		nfsr_tmp ^= grain->nfsr[128-A[i]-1];
	}

	uint8_t y = h_out ^ grain->lfsr[128-93-1] ^ nfsr_tmp;
	
	uint8_t lfsr_out;

	/* feedback y if we are in the initialization instance */
	if (init_rounds) {
		lfsr_out = shift(grain->lfsr, lfsr_fb ^ y);
		shift(grain->nfsr, nfsr_fb ^ lfsr_out ^ y);
	} else {
		lfsr_out = shift(grain->lfsr, lfsr_fb);
		shift(grain->nfsr, nfsr_fb ^ lfsr_out);
	}

	return y;
}

void print_state(grain_state *grain)
{
	printf("LFSR: ");
	for (int i = 0; i < 128; i++) {
		printf("%d", grain->lfsr[i]);
	}
	printf("\nNFSR: ");
	for (int i = 0; i < 128; i++) {
		printf("%d", grain->nfsr[i]);
	}
	printf("\n");
}

void print_preout(grain_state *grain)
{
	printf("pre-out: ");
	for (int i = 0; i < 40; i++) {
		uint8_t yi = 0;
		for (int j = 0; j < 8; j++) {
			yi = (yi << 1) ^ next_z(grain);
		}
		printf("%02x", yi);
	}
	printf("\n");
}

void print_keystream(grain_state *grain)
{
#ifdef AUTH
	/* inititalize the accumulator and shift reg. using the first 64 bits */
	for (int i = 0; i < 32; i++) {
		grain->auth_acc[i] = next_z(grain);
	}

	for (int i = 0; i < 32; i++) {
		grain->auth_sr[i] = next_z(grain);
	}

	printf("accumulator: ");
	for (int i = 0; i < 4; i++) {
		uint8_t ai = 0;
		for (int j = 0; j < 8; j++) {
			ai = (ai << 1) ^ grain->auth_acc[i * 8 + j];
		}
		printf("%02x", ai);
	}
	printf("\n");
	
	printf("shift register: ");
	for (int i = 0; i < 4; i++) {
		uint8_t ri = 0;
		for (int j = 0; j < 8; j++) {
			ri = (ri << 1) ^ grain->auth_sr[i * 8 + j];
		}
		printf("%02x", ri);
	}
	printf("\n");

	printf("keystream: ");
	for (int i = 0; i < 40; i++) {
		/* y = z_{2i} */
		uint8_t yi = 0;
		for (int j = 0; j < 16; j++) {
			/* skip every second */
			uint8_t z_next = next_z(grain);
			if (j % 2 == 1) {
				yi = (yi << 1) ^ z_next;
			}
		}
		printf("%02x", yi);
	}
	printf("\n");

	/*
	for (int i = 0; i < 40; i++) {
		uint8_t yi = 0;
		for (int j = 0; j < 8; j++) {
			yi = (yi << 1) ^ next_z(grain);
		}
		printf("%02x", yi);
	}
	printf("\n");
	*/

#else
	printf("keystream: ");
	for (int i = 0; i < 40; i++) {
		uint8_t yi = 0;
		for (int j = 0; j < 8; j++) {
			yi = (yi << 1) ^ next_z(grain);
		}
		printf("%02x", yi);
	}
	printf("\n");
	
#endif
}

int main()
{
	grain_state grain;

	init_grain(&grain, NULL, NULL);
	
	/* initialize grain and skip output */
	init_rounds = 1;
	int nz;
#ifdef INIT
	printf("init bits: ");
#endif
	for (int i = 0; i < 256; i++) {
		nz = next_z(&grain);
		/* here, we can print the output during the initialization */
#ifdef INIT
		printf("%d", nz);
#endif
	}
#ifdef INIT
	printf("\n");
#endif
	init_rounds = 0;

#ifdef PRE
	print_preout(&grain);
#else
	print_keystream(&grain);
#endif

}
