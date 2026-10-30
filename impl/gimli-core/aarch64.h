#define GIMLI_ROUND(x, y, z)                             \
    do {                                                 \
        tx = ROTL32((x), 24);                            \
        ty = ROTL32((y), 9);                             \
        tz = (z);                                        \
        (z) = tx ^ (tz << 1) ^ ((ty & tz) << 2);         \
        (y) = ty ^ tx ^ ((tx | tz) << 1);                \
        (x) = tz ^ ty ^ ((tx & ty) << 3);                \
    } while (0)

static void
gimli_core(uint32_t state[gimli_BLOCKBYTES / 4])
{
    uint32_t     x0 = state[0], x1 = state[1], x2 = state[2], x3 = state[3];
    uint32_t     y0 = state[4], y1 = state[5], y2 = state[6], y3 = state[7];
    uint32_t     z0 = state[8], z1 = state[9], z2 = state[10], z3 = state[11];
    uint32_t     tx, ty, tz;
    unsigned int round;

    for (round = 24; round > 0; round -= 4) {
        GIMLI_ROUND(x0, y0, z0);
        GIMLI_ROUND(x1, y1, z1);
        GIMLI_ROUND(x2, y2, z2);
        GIMLI_ROUND(x3, y3, z3);
        tx = x0;
        x0 = x1;
        x1 = tx;
        tx = x2;
        x2 = x3;
        x3 = tx;
        x0 ^= ((uint32_t) 0x9e377900 | round);

        GIMLI_ROUND(x0, y0, z0);
        GIMLI_ROUND(x1, y1, z1);
        GIMLI_ROUND(x2, y2, z2);
        GIMLI_ROUND(x3, y3, z3);

        GIMLI_ROUND(x0, y0, z0);
        GIMLI_ROUND(x1, y1, z1);
        GIMLI_ROUND(x2, y2, z2);
        GIMLI_ROUND(x3, y3, z3);
        tx = x0;
        x0 = x2;
        x2 = tx;
        tx = x1;
        x1 = x3;
        x3 = tx;

        GIMLI_ROUND(x0, y0, z0);
        GIMLI_ROUND(x1, y1, z1);
        GIMLI_ROUND(x2, y2, z2);
        GIMLI_ROUND(x3, y3, z3);
    }
    state[0]  = x0;
    state[1]  = x1;
    state[2]  = x2;
    state[3]  = x3;
    state[4]  = y0;
    state[5]  = y1;
    state[6]  = y2;
    state[7]  = y3;
    state[8]  = z0;
    state[9]  = z1;
    state[10] = z2;
    state[11] = z3;
}

#undef GIMLI_ROUND
