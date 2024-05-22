// SM3, GB/T 32905-2016 信息安全技术 SM3密码杂凑算法
// bobwxc@yeah.net, 2023
// Public domain

#ifndef SM3_H
#define SM3_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SM3_HASH_DIGEST_SIZE 32 // bytes

#define SM3_HASH_BLOCK_SIZE 64 // bytes

#define is_little_endian() (*(uint16_t *)"a" == 'a')


typedef uint32_t SM3_Word; // stored in local endian

struct sm3
{
    unsigned char remaind_bytes[64];
    size_t remaind_bytes_length;
    size_t handled_bytes_length; // exclude the remainder_bytes
    SM3_Word Vi_sub1[8];
    SM3_Word Vn[8];
};

typedef struct sm3 sm3_t;

void swap_endian(SM3_Word *w)
{
    uint8_t *x = (uint8_t *)w;
    uint8_t t;

    t = *x;
    *x = *(x + 3);
    *(x + 3) = t;

    t = *(x + 1);
    *(x + 1) = *(x + 2);
    *(x + 2) = t;
}

SM3_Word rotate_left(SM3_Word w, short n)
{
    short nl = n % 32;
    short nr = 32 - nl;
    if (nl == 0 || nr == 32)
        return w;
    else
        return (w << nl) | (w >> nr);
}

SM3_Word IV[8] = {
    0x7380166f,
    0x4914b2b9,
    0x172442d7,
    0xda8a0600,
    0xa96f30bc,
    0x163138aa,
    0xe38dee4d,
    0xb0fb0e4e};

SM3_Word T(int j)
{
    if (j >= 0 && j <= 15)
        return 0x79cc4519;
    else if (j >= 16 && j <= 63)
        return 0x7a879d8a;
    else
        return -1;
}

SM3_Word FF(SM3_Word X, SM3_Word Y, SM3_Word Z, int j)
{
    if (j >= 0 && j <= 15)
        return X ^ Y ^ Z;
    else if (j >= 16 && j <= 63)
        return (X & Y) | (X & Z) | (Y & Z);
    else
        return -1;
}

SM3_Word GG(SM3_Word X, SM3_Word Y, SM3_Word Z, int j)
{
    if (j >= 0 && j <= 15)
        return X ^ Y ^ Z;
    else if (j >= 16 && j <= 63)
        return (X & Y) | (~X & Z);
    else
        return -1;
}

SM3_Word P0(SM3_Word X)
{
    return X ^ rotate_left(X, 9) ^ rotate_left(X, 17);
}

SM3_Word P1(SM3_Word X)
{
    return X ^ rotate_left(X, 15) ^ rotate_left(X, 23);
}

void expand_Bi(unsigned char Bi[64], SM3_Word W[68], SM3_Word WW[64])
{
    for (int j = 0; j < 64; j += 4)
        W[j / 4] = (Bi[j] << 24) + (Bi[j + 1] << 16) + (Bi[j + 2] << 8) + Bi[j + 3];
    for (int j = 16; j < 68; j++)
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ rotate_left(W[j - 3], 15)) ^ rotate_left(W[j - 13], 7) ^ W[j - 6];
    for (int j = 0; j < 64; j++)
        WW[j] = W[j] ^ W[j + 4];
}

void CF(SM3_Word Vi[8], unsigned char Bi[64], SM3_Word Vii[8])
{
    SM3_Word A, B, C, D, E, F, G, H;
    A = Vi[0];
    B = Vi[1];
    C = Vi[2];
    D = Vi[3];
    E = Vi[4];
    F = Vi[5];
    G = Vi[6];
    H = Vi[7];

    SM3_Word W[68], WW[64];
    expand_Bi(Bi, W, WW);

    SM3_Word SS1, SS2, TT1, TT2;
    for (int j = 0; j < 64; j++)
    {
        // SS1 ← ((A ≪ 12) + E + (Tj ≪ j)) ≪ 7
        SS1 = rotate_left((rotate_left(A, 12) + E + rotate_left(T(j), j)) & 0xffffffff, 7);
        // SS2 ← SS1 ⊕ (A ≪ 12)
        SS2 = SS1 ^ rotate_left(A, 12);
        // TT1 ← FFj (A, B, C) + D + SS2 + W′j
        TT1 = FF(A, B, C, j) + D + SS2 + WW[j];
        // TT2 ← GGj (E, F, G) + H + SS1 + Wj
        TT2 = GG(E, F, G, j) + H + SS1 + W[j];
        // D ← C
        D = C;
        // C ← B ≪ 9
        C = rotate_left(B, 9);
        // B ← A
        B = A;
        // A ← TT1
        A = TT1;
        // H ← G
        H = G;
        // G ← F ≪ 19
        G = rotate_left(F, 19);
        // F ← E
        F = E;
        // E ← P0(T T2)
        E = P0(TT2);
    }

    Vii[0] = A;
    Vii[1] = B;
    Vii[2] = C;
    Vii[3] = D;
    Vii[4] = E;
    Vii[5] = F;
    Vii[6] = G;
    Vii[7] = H;
    for (int i = 0; i < 8; i++)
        Vii[i] = Vii[i] ^ Vi[i];
}

// bytes_length % 64 == 0, remain bytes will NOT be calculated
void iteration(unsigned char *m, size_t bytes_length, SM3_Word Vi[8], SM3_Word Vn[8])
{
    SM3_Word Vii[8];
    memcpy(Vii, Vi, 32);

    for (int i = 0; i < bytes_length / 64; i++)
    {
        CF(Vii, m + (i * 64), Vn);
        memcpy(Vii, Vn, sizeof(SM3_Word) * 8);
    }
}

// return 1 = one tail block, 2 = two tail blocks
short generate_tail_block(unsigned char *m, size_t bytes_length, size_t handled_bytes_length, unsigned char lbk[128])
{
    short mlr = bytes_length % 64;
    for (int i = 0; i < mlr; i++)
        lbk[i] = m[bytes_length - mlr + i];
    lbk[mlr] = '\x80'; // 0b1000 0000

    short tail_length = 0;
    if (mlr <= 55) // 448 bits = 56 bytes
        tail_length = 64;
    else
        tail_length = 128;

    for (int i = (mlr + 1); i < (tail_length - 8); i++)
        lbk[i] = '\x00';

    uint64_t total_len_bits = (bytes_length + handled_bytes_length) * 8;
    if (is_little_endian())
    {
        for (int i = 0; i < 8; i++)
            lbk[tail_length - 1 - i] = ((char *)&total_len_bits)[i];
    }
    else
    {
        for (int i = 0; i < 8; i++)
            lbk[tail_length - 8 + i] = ((char *)&total_len_bits)[i];
    }

    return tail_length / 64;
}

// digest is stored in big-endian
void sm3_once_calcu(unsigned char *m, size_t bytes_length, unsigned char digest[32])
{
    SM3_Word Vn[8] = {0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
                      0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e};

    if (bytes_length >= 64)
        iteration(m, bytes_length, IV, Vn);

    unsigned char tail_block[128];
    if (generate_tail_block(m, bytes_length, 0, tail_block) == 1)
        iteration(tail_block, 64, Vn, Vn);
    else
        iteration(tail_block, 128, Vn, Vn);

    if (is_little_endian())
        for (int i = 0; i < 8; i++)
            swap_endian(Vn + i);

    memcpy(digest, Vn, 32);
}

void sm3_hexdigest(unsigned char digest[32], char hexdigest[64])
{
    for (int i = 0; i < 32; i++)
        sprintf(hexdigest + 2 * i, "%02x", digest[i]);
}

void sm3_init(sm3_t *hash_body)
{
    memset(hash_body->remaind_bytes, 0, 64);
    hash_body->remaind_bytes_length = 0;
    hash_body->handled_bytes_length = 0;
    memcpy(hash_body->Vi_sub1, IV, 32);
    memcpy(hash_body->Vn, IV, 32);
}

void sm3_update(sm3_t *hash_body, unsigned char *m, size_t bytes_length)
{
    if (bytes_length <= 0)
    {
        return;
    }
    else if ((hash_body->remaind_bytes_length + bytes_length) < 64)
    {
        memcpy(hash_body->remaind_bytes + hash_body->remaind_bytes_length, m, bytes_length);
        hash_body->remaind_bytes_length += bytes_length;

        unsigned char tail_block[128];
        if (generate_tail_block(hash_body->remaind_bytes, hash_body->remaind_bytes_length, hash_body->handled_bytes_length, tail_block) == 1)
            iteration(tail_block, 64, hash_body->Vi_sub1, hash_body->Vn);
        else
            iteration(tail_block, 128, hash_body->Vi_sub1, hash_body->Vn);
    }
    else
    {
        memcpy(hash_body->remaind_bytes + hash_body->remaind_bytes_length, m, 64 - hash_body->remaind_bytes_length);
        iteration(hash_body->remaind_bytes, 64, hash_body->Vi_sub1, hash_body->Vi_sub1);

        unsigned char *mm = m + 64 - hash_body->remaind_bytes_length;
        size_t mml = bytes_length - (64 - hash_body->remaind_bytes_length);

        iteration(mm, mml, hash_body->Vi_sub1, hash_body->Vi_sub1);

        unsigned char tail_block[128];
        if (generate_tail_block(mm, mml, hash_body->handled_bytes_length + 64, tail_block) == 1)
            iteration(tail_block, 64, hash_body->Vi_sub1, hash_body->Vn);
        else
            iteration(tail_block, 128, hash_body->Vi_sub1, hash_body->Vn);

        size_t mrlr = (hash_body->remaind_bytes_length + bytes_length) % 64;
        hash_body->handled_bytes_length += (hash_body->remaind_bytes_length + bytes_length) - mrlr;
        hash_body->remaind_bytes_length = mrlr;
        memcpy(hash_body->remaind_bytes, m + bytes_length - mrlr, mrlr);
    }
}

void sm3_digest(sm3_t *hash_body, unsigned char digest[32])
{
    SM3_Word Vn[32];
    memcpy(Vn, hash_body->Vn, 32);

    if (is_little_endian())
        for (int i = 0; i < 8; i++)
            swap_endian(Vn + i);

    memcpy(digest, Vn, 32);
}

#endif
