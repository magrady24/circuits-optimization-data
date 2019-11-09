#include <stdio.h>
#include <stdint.h>
#include <string.h>

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rsbox[256] = { /* No needed in circuit. Just verify it by encryption. */ };

static const double read_cost = 96.0 / 7;
static double aes_cost = 0;

static inline int from_hex(char s){
    return s >= '0' && s <= '9' ? s - '0' : (s >= 'a' && s <= 'z' ? s - 'a' + 10 : s - 'A' + 10);
}

static uint8_t bit_pick(uint8_t x, uint8_t i){
    return !!(x & (1 << i));
}
static uint8_t bit_pack(uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3, uint8_t a4){
    a0 = !!a0;
    a1 = !!a1;
    a2 = !!a2;
    a3 = !!a3;
    a4 = !!a4;
    return (a4 << 4) | (a3 << 3) | (a2 << 2) | (a1 << 1) | a0;
}
static uint8_t bit_pack(uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3, uint8_t a4, uint8_t a5, uint8_t a6, uint8_t a7){
    a0 = !!a0;
    a1 = !!a1;
    a2 = !!a2;
    a3 = !!a3;
    a4 = !!a4;
    a5 = !!a5;
    a6 = !!a6;
    a7 = !!a7;
    return (a7 << 7) | (a6 << 6) | (a5 << 5) | (a4 << 4) | (a3 << 3) | (a2 << 2) | (a1 << 1) | a0;
}

template <uint32_t T>
static bool LUT_5(uint8_t x){
    aes_cost += 2;
    return T & (1U << (x & 0x1F));
}

template <uint8_t rcon>
static void key_schedule(const uint8_t pre[16], uint8_t next[16]){
    aes_cost += 8 + (read_cost + 8) + __builtin_popcount(rcon);
    next[0] = pre[0] ^ sbox[pre[13]] ^ rcon;
    aes_cost += 8 + (read_cost + 8);
    next[1] = pre[1] ^ sbox[pre[14]];
    aes_cost += 8 + (read_cost + 8);
    next[2] = pre[2] ^ sbox[pre[15]];
    aes_cost += 8 + (read_cost + 8);
    next[3] = pre[3] ^ sbox[pre[12]];
    aes_cost += 8 * 12;
    next[4] = pre[4] ^ next[0];
    next[5] = pre[5] ^ next[1];
    next[6] = pre[6] ^ next[2];
    next[7] = pre[7] ^ next[3];
    next[8] = pre[8] ^ next[4];
    next[9] = pre[9] ^ next[5];
    next[10] = pre[10] ^ next[6];
    next[11] = pre[11] ^ next[7];
    next[12] = pre[12] ^ next[8];
    next[13] = pre[13] ^ next[9];
    next[14] = pre[14] ^ next[10];
    next[15] = pre[15] ^ next[11];
}

static void xor_bytes(const uint8_t a[], const uint8_t b[], uint8_t c[]){
    aes_cost += 8 * 16;
    c[0] = a[0] ^ b[0];
    c[1] = a[1] ^ b[1];
    c[2] = a[2] ^ b[2];
    c[3] = a[3] ^ b[3];
    c[4] = a[4] ^ b[4];
    c[5] = a[5] ^ b[5];
    c[6] = a[6] ^ b[6];
    c[7] = a[7] ^ b[7];
    c[8] = a[8] ^ b[8];
    c[9] = a[9] ^ b[9];
    c[10] = a[10] ^ b[10];
    c[11] = a[11] ^ b[11];
    c[12] = a[12] ^ b[12];
    c[13] = a[13] ^ b[13];
    c[14] = a[14] ^ b[14];
    c[15] = a[15] ^ b[15];
}

static void sub_bytes(const uint8_t a[], uint8_t b[]){
    aes_cost += (read_cost + 8) * 16;
    b[0] = sbox[a[0]];
    b[1] = sbox[a[1]];
    b[2] = sbox[a[2]];
    b[3] = sbox[a[3]];
    b[4] = sbox[a[4]];
    b[5] = sbox[a[5]];
    b[6] = sbox[a[6]];
    b[7] = sbox[a[7]];
    b[8] = sbox[a[8]];
    b[9] = sbox[a[9]];
    b[10] = sbox[a[10]];
    b[11] = sbox[a[11]];
    b[12] = sbox[a[12]];
    b[13] = sbox[a[13]];
    b[14] = sbox[a[14]];
    b[15] = sbox[a[15]];
}

static void sub_mix_each_column(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t r[]){
	aes_cost += read_cost + 8;
	a = sbox[a];
	aes_cost += read_cost + 8;
	b = sbox[b];
	aes_cost += read_cost + 8;
	c = sbox[c];
	aes_cost += read_cost + 8;
	d = sbox[d];
	
	aes_cost += 3;
	uint8_t da = bit_pack(
		bit_pick(a, 7), 
		bit_pick(a, 0) ^ bit_pick(a, 7), 
		bit_pick(a, 1), 
		bit_pick(a, 2) ^ bit_pick(a, 7), 
		bit_pick(a, 3) ^ bit_pick(a, 7), 
		bit_pick(a, 4), 
		bit_pick(a, 5), 
		bit_pick(a, 6)
	);
	
	aes_cost += 3;
	uint8_t db = bit_pack(
		bit_pick(b, 7), 
		bit_pick(b, 0) ^ bit_pick(b, 7), 
		bit_pick(b, 1), 
		bit_pick(b, 2) ^ bit_pick(b, 7), 
		bit_pick(b, 3) ^ bit_pick(b, 7), 
		bit_pick(b, 4), 
		bit_pick(b, 5), 
		bit_pick(b, 6)
	);
	
	aes_cost += 3;
	uint8_t dc = bit_pack(
		bit_pick(c, 7), 
		bit_pick(c, 0) ^ bit_pick(c, 7), 
		bit_pick(c, 1), 
		bit_pick(c, 2) ^ bit_pick(c, 7), 
		bit_pick(c, 3) ^ bit_pick(c, 7), 
		bit_pick(c, 4), 
		bit_pick(c, 5), 
		bit_pick(c, 6)
	);

	aes_cost += 3;	
	uint8_t dd = bit_pack(
		bit_pick(d, 7), 
		bit_pick(d, 0) ^ bit_pick(d, 7), 
		bit_pick(d, 1), 
		bit_pick(d, 2) ^ bit_pick(d, 7), 
		bit_pick(d, 3) ^ bit_pick(d, 7), 
		bit_pick(d, 4), 
		bit_pick(d, 5), 
		bit_pick(d, 6)
	);
	
	r[0] = bit_pack(
		LUT_5<0x96696996>(bit_pack(bit_pick(da, 0), bit_pick(db, 0), bit_pick(b, 0), bit_pick(c, 0), bit_pick(d, 0))),
		LUT_5<0x96696996>(bit_pack(bit_pick(da, 1), bit_pick(db, 1), bit_pick(b, 1), bit_pick(c, 1), bit_pick(d, 1))),
		LUT_5<0x96696996>(bit_pack(bit_pick(da, 2), bit_pick(db, 2), bit_pick(b, 2), bit_pick(c, 2), bit_pick(d, 2))),
		LUT_5<0x96696996>(bit_pack(bit_pick(da, 3), bit_pick(db, 3), bit_pick(b, 3), bit_pick(c, 3), bit_pick(d, 3))),
		LUT_5<0x96696996>(bit_pack(bit_pick(da, 4), bit_pick(db, 4), bit_pick(b, 4), bit_pick(c, 4), bit_pick(d, 4))),
		LUT_5<0x96696996>(bit_pack(bit_pick(da, 5), bit_pick(db, 5), bit_pick(b, 5), bit_pick(c, 5), bit_pick(d, 5))),
		LUT_5<0x96696996>(bit_pack(bit_pick(da, 6), bit_pick(db, 6), bit_pick(b, 6), bit_pick(c, 6), bit_pick(d, 6))),
		LUT_5<0x96696996>(bit_pack(bit_pick(da, 7), bit_pick(db, 7), bit_pick(b, 7), bit_pick(c, 7), bit_pick(d, 7)))
	);
	
	r[1] = bit_pack(
		LUT_5<0x96696996>(bit_pack(bit_pick(db, 0), bit_pick(dc, 0), bit_pick(c, 0), bit_pick(d, 0), bit_pick(a, 0))),
		LUT_5<0x96696996>(bit_pack(bit_pick(db, 1), bit_pick(dc, 1), bit_pick(c, 1), bit_pick(d, 1), bit_pick(a, 1))),
		LUT_5<0x96696996>(bit_pack(bit_pick(db, 2), bit_pick(dc, 2), bit_pick(c, 2), bit_pick(d, 2), bit_pick(a, 2))),
		LUT_5<0x96696996>(bit_pack(bit_pick(db, 3), bit_pick(dc, 3), bit_pick(c, 3), bit_pick(d, 3), bit_pick(a, 3))),
		LUT_5<0x96696996>(bit_pack(bit_pick(db, 4), bit_pick(dc, 4), bit_pick(c, 4), bit_pick(d, 4), bit_pick(a, 4))),
		LUT_5<0x96696996>(bit_pack(bit_pick(db, 5), bit_pick(dc, 5), bit_pick(c, 5), bit_pick(d, 5), bit_pick(a, 5))),
		LUT_5<0x96696996>(bit_pack(bit_pick(db, 6), bit_pick(dc, 6), bit_pick(c, 6), bit_pick(d, 6), bit_pick(a, 6))),
		LUT_5<0x96696996>(bit_pack(bit_pick(db, 7), bit_pick(dc, 7), bit_pick(c, 7), bit_pick(d, 7), bit_pick(a, 7)))
	);
	
	r[2] = bit_pack(
		LUT_5<0x96696996>(bit_pack(bit_pick(dc, 0), bit_pick(dd, 0), bit_pick(d, 0), bit_pick(a, 0), bit_pick(b, 0))),
		LUT_5<0x96696996>(bit_pack(bit_pick(dc, 1), bit_pick(dd, 1), bit_pick(d, 1), bit_pick(a, 1), bit_pick(b, 1))),
		LUT_5<0x96696996>(bit_pack(bit_pick(dc, 2), bit_pick(dd, 2), bit_pick(d, 2), bit_pick(a, 2), bit_pick(b, 2))),
		LUT_5<0x96696996>(bit_pack(bit_pick(dc, 3), bit_pick(dd, 3), bit_pick(d, 3), bit_pick(a, 3), bit_pick(b, 3))),
		LUT_5<0x96696996>(bit_pack(bit_pick(dc, 4), bit_pick(dd, 4), bit_pick(d, 4), bit_pick(a, 4), bit_pick(b, 4))),
		LUT_5<0x96696996>(bit_pack(bit_pick(dc, 5), bit_pick(dd, 5), bit_pick(d, 5), bit_pick(a, 5), bit_pick(b, 5))),
		LUT_5<0x96696996>(bit_pack(bit_pick(dc, 6), bit_pick(dd, 6), bit_pick(d, 6), bit_pick(a, 6), bit_pick(b, 6))),
		LUT_5<0x96696996>(bit_pack(bit_pick(dc, 7), bit_pick(dd, 7), bit_pick(d, 7), bit_pick(a, 7), bit_pick(b, 7)))
	);
	                               
	r[3] = bit_pack(                     
		LUT_5<0x96696996>(bit_pack(bit_pick(dd, 0), bit_pick(da, 0), bit_pick(a, 0), bit_pick(b, 0), bit_pick(c, 0))),
		LUT_5<0x96696996>(bit_pack(bit_pick(dd, 1), bit_pick(da, 1), bit_pick(a, 1), bit_pick(b, 1), bit_pick(c, 1))),
		LUT_5<0x96696996>(bit_pack(bit_pick(dd, 2), bit_pick(da, 2), bit_pick(a, 2), bit_pick(b, 2), bit_pick(c, 2))),
		LUT_5<0x96696996>(bit_pack(bit_pick(dd, 3), bit_pick(da, 3), bit_pick(a, 3), bit_pick(b, 3), bit_pick(c, 3))),
		LUT_5<0x96696996>(bit_pack(bit_pick(dd, 4), bit_pick(da, 4), bit_pick(a, 4), bit_pick(b, 4), bit_pick(c, 4))),
		LUT_5<0x96696996>(bit_pack(bit_pick(dd, 5), bit_pick(da, 5), bit_pick(a, 5), bit_pick(b, 5), bit_pick(c, 5))),
		LUT_5<0x96696996>(bit_pack(bit_pick(dd, 6), bit_pick(da, 6), bit_pick(a, 6), bit_pick(b, 6), bit_pick(c, 6))),
		LUT_5<0x96696996>(bit_pack(bit_pick(dd, 7), bit_pick(da, 7), bit_pick(a, 7), bit_pick(b, 7), bit_pick(c, 7)))
	);
}

static void sub_mix_column(uint8_t a[], uint8_t b[]){
	sub_mix_each_column(a[0], a[5], a[10], a[15], b);
	sub_mix_each_column(a[4], a[9], a[14], a[3], b+4);
	sub_mix_each_column(a[8], a[13], a[2], a[7], b+8);
	sub_mix_each_column(a[12], a[1], a[6], a[11], b+12);
}

// the in and key are bit decomposed here.
void AES(uint8_t in[], uint8_t key[], uint8_t out[], uint8_t wit[]){
	uint8_t (*w_keys)[16]=(uint8_t(*)[16])(wit+1024);
	uint8_t (*w_progress)[16]=(uint8_t(*)[16])(wit+2048);
	xor_bytes(in, key, w_progress[0]);
	sub_mix_column(w_progress[0], w_progress[2]);
	key_schedule<0x01>(key, w_keys[0]);
	xor_bytes(w_progress[2], w_keys[0], w_progress[3]);
	sub_mix_column(w_progress[3], w_progress[5]);
	key_schedule<0x02>(w_keys[0], w_keys[1]);
	xor_bytes(w_progress[5], w_keys[1], w_progress[6]);
	sub_mix_column(w_progress[6], w_progress[8]);
	key_schedule<0x04>(w_keys[1], w_keys[2]);
	xor_bytes(w_progress[8], w_keys[2], w_progress[9]);
	sub_mix_column(w_progress[9], w_progress[11]);
	key_schedule<0x08>(w_keys[2], w_keys[3]);
	xor_bytes(w_progress[11], w_keys[3], w_progress[12]);
	sub_mix_column(w_progress[12], w_progress[14]);
	key_schedule<0x10>(w_keys[3], w_keys[4]);
	xor_bytes(w_progress[14], w_keys[4], w_progress[15]);
	sub_mix_column(w_progress[15], w_progress[17]);
	key_schedule<0x20>(w_keys[4], w_keys[5]);
	xor_bytes(w_progress[17], w_keys[5], w_progress[18]);
	sub_mix_column(w_progress[18], w_progress[20]);
	key_schedule<0x40>(w_keys[5], w_keys[6]);
	xor_bytes(w_progress[20], w_keys[6], w_progress[21]);
	sub_mix_column(w_progress[21], w_progress[23]);
	key_schedule<0x80>(w_keys[6], w_keys[7]);
	xor_bytes(w_progress[23], w_keys[7], w_progress[24]);
	sub_mix_column(w_progress[24], w_progress[26]);
	key_schedule<0x1b>(w_keys[7], w_keys[8]);
	xor_bytes(w_progress[26], w_keys[8], w_progress[27]);
	sub_bytes(w_progress[27], w_progress[28]);
	key_schedule<0x36>(w_keys[8], w_keys[9]);
	w_progress[29][0] = w_progress[28][0];
	w_progress[29][1] = w_progress[28][5];
	w_progress[29][2] = w_progress[28][10];
	w_progress[29][3] = w_progress[28][15];
	w_progress[29][4] = w_progress[28][4];
	w_progress[29][5] = w_progress[28][9];
	w_progress[29][6] = w_progress[28][14];
	w_progress[29][7] = w_progress[28][3];
	w_progress[29][8] = w_progress[28][8];
	w_progress[29][9] = w_progress[28][13];
	w_progress[29][10] = w_progress[28][2];
	w_progress[29][11] = w_progress[28][7];
	w_progress[29][12] = w_progress[28][12];
	w_progress[29][13] = w_progress[28][1];
	w_progress[29][14] = w_progress[28][6];
	w_progress[29][15] = w_progress[28][11];
	xor_bytes(w_progress[29], w_keys[9], out);
}

int main(){
    uint8_t in[16], key[16], out[16], wit[10000];
    char s_in[32 + 1] = "6bc1bee22e409f96e93d7e117393172a", s_key[32 + 1] = "2b7e151628aed2a6abf7158809cf4f3c", s_out[32 + 1];

    for (int i = 0; i < 16; i++) {
        int val = from_hex(s_in[i + i + 1]) + (from_hex(s_in[i + i]) << 4);
        in[i] = val;
    }
    for (int i = 0; i < 16; i++) {
        int val = from_hex(s_key[i + i + 1]) + (from_hex(s_key[i + i]) << 4);
        key[i] = val;
    }
    AES(in, key, out, wit);
    char* p = s_out;
    for (int i = 0; i < 16; i++) {
        p += sprintf(p, "%02x", out[i]);
    }
    printf(!strcmp(s_out, "3ad77bb40d7a3660a89ecaf32466ef97") ? "OK %s, total %f constraints.\n" : "Failed %s.\n", s_out, aes_cost);
}
