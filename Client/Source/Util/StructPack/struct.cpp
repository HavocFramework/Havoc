#include <Util/StructPack/struct.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>

#define IEEE754_32_NAN     0x7FC00000
#define IEEE754_32_INF     0x7F800000
#define IEEE754_32_NEG_INF 0xFF800000

#define IEEE754_64_NAN     0x7FF8000000000000
#define IEEE754_64_INF     0x7FF0000000000000
#define IEEE754_64_NEG_INF 0xFFF0000000000000

// refer to
// http://beej.us/guide/bgnet/output/html/singlepage/bgnet.html#serialization
// - Beej's Guide to Network Programming
//
// macros for packing floats and doubles:
#define PACK_IEEE754_32(f) (pack_ieee754((f), 32, 8))
#define PACK_IEEE754_64(f) (pack_ieee754((f), 64, 11))
#define UNPACK_IEEE754_32(i) (unpack_ieee754((i), 32, 8))
#define UNPACK_IEEE754_64(i) (unpack_ieee754((i), 64, 11))

#define INIT_REPETITION(_x) int _struct_rep = 0

#define BEGIN_REPETITION(_x) do { _struct_rep--

#define END_REPETITION(_x) } while(_struct_rep > 0)

#define INC_REPETITION(_x) _struct_rep = _struct_rep * 10 + (*p - '0')

#define CLEAR_REPETITION(_x) _struct_rep = 0

static int myendian = STRUCT_ENDIAN_NOT_SET;

int struct_get_endian(void)
{
    int i = 0x00000001;
    if (((char *)&i)[0]) {
        return STRUCT_ENDIAN_LITTLE;
    } else {
        return STRUCT_ENDIAN_BIG;
    }
}

static void struct_init(void)
{
    myendian = struct_get_endian();
}

static uint64_t pack_ieee754(long double f,
                             unsigned int bits, unsigned int expbits)
{
    long double fnorm;
    int shift;
    long long sign;
    long long exp;
    long long significand;
    unsigned int significandbits = bits - expbits - 1; // -1 for sign bit

    int isinf_ret = isinf(f);
    if (isinf_ret != 0) {
        // isinf(f) returns 1 if f is positive infinity,
        //                  -1 if f is negative infinity.
        if (bits == 32) {
            return (isinf_ret == 1) ? IEEE754_32_INF : IEEE754_32_NEG_INF;
        } else {
            return (isinf_ret == 1) ? IEEE754_64_INF : IEEE754_64_NEG_INF;
        }
    }

    if (isnan(f)) {
        if (bits == 32) {
            return IEEE754_32_NAN;
        } else {
            return IEEE754_64_NAN;
        }
    }

    if (f == 0.0) {
        return 0; // get this special case out of the way
    }

    // check sign and begin normalization
    if (f < 0) {
        sign = 1;
        fnorm = -f;
    } else {
        sign = 0;
        fnorm = f;
    }

    // get the normalized form of f and track the exponent
    shift = 0;
    while (fnorm >= 2.0) {
        fnorm /= 2.0;
        shift++;
    }
    while (fnorm < 1.0) {
        fnorm *= 2.0;
        shift--;
    }
    fnorm = fnorm - 1.0;

    // calculate the binary form (non-float) of the significand data
    significand = (long long)(fnorm * ((1LL << significandbits) + 0.5F));

    // get the biased exponent
    // shift + bias
    exp = shift + ((1LL << (expbits - 1)) - 1);

    // return the final answer
    return (sign << (bits - 1U)) | (exp << (bits - expbits - 1U)) | significand;
}

static long double unpack_ieee754(uint64_t i,
                                  unsigned int bits, unsigned int expbits)
{
    long double result;
    long long shift;
    unsigned int bias;
    unsigned int significandbits = bits - expbits - 1; // -1 for sign bit

    if (i == 0) {
        return 0.0;
    }

    if (bits == 32) {
        if (i == IEEE754_32_NAN) {
            return NAN;
        }

        if (i == IEEE754_32_INF) {
            return INFINITY;
        }

        if (i == IEEE754_32_NEG_INF) {
            return -INFINITY;
        }
    } else {
        if (i == IEEE754_64_NAN) {
            return NAN;
        }

        if (i == IEEE754_64_INF) {
            return INFINITY;
        }

        if (i == IEEE754_64_NEG_INF) {
            return -INFINITY;
        }
    }

    // pull the significand
    result = (i & ((1LL << significandbits) - 1)); // mask
    result /= (1LL << significandbits); // convert back to float
    result += 1.0F; // add the one back on

    // deal with the exponent
    bias = (1 << (expbits - 1)) - 1;
    shift = ((i >> significandbits) & ((1LL << expbits) - 1)) - bias;
    while (shift > 0) {
        result *= 2.0;
        shift--;
    }
    while (shift < 0) {
        result /= 2.0;
        shift++;
    }

    // sign it
    result *= ((i >> (bits - 1)) & 1) ? -1.0 : 1.0;

    return result;
}

static void pack_int16_t(unsigned char **bp, uint16_t val, int endian)
{
    if (endian == myendian) {
        *((*bp)++) = val;
        *((*bp)++) = val >> 8;
    } else {
        *((*bp)++) = val >> 8;
        *((*bp)++) = val;
    }
}

static void pack_int32_t(unsigned char **bp, uint32_t val, int endian)
{
    if (endian == myendian) {
        *((*bp)++) = val;
        *((*bp)++) = val >> 8;
        *((*bp)++) = val >> 16;
        *((*bp)++) = val >> 24;
    } else {
        *((*bp)++) = val >> 24;
        *((*bp)++) = val >> 16;
        *((*bp)++) = val >> 8;
        *((*bp)++) = val;
    }
}

static void pack_int64_t(unsigned char **bp, uint64_t val, int endian)
{
    if (endian == myendian) {
        *((*bp)++) = val;
        *((*bp)++) = val >> 8;
        *((*bp)++) = val >> 16;
        *((*bp)++) = val >> 24;
        *((*bp)++) = val >> 32;
        *((*bp)++) = val >> 40;
        *((*bp)++) = val >> 48;
        *((*bp)++) = val >> 56;
    } else {
        *((*bp)++) = val >> 56;
        *((*bp)++) = val >> 48;
        *((*bp)++) = val >> 40;
        *((*bp)++) = val >> 32;
        *((*bp)++) = val >> 24;
        *((*bp)++) = val >> 16;
        *((*bp)++) = val >> 8;
        *((*bp)++) = val;
    }
}

static void pack_float(unsigned char **bp, float val, int endian)
{
    uint64_t ieee754_encoded_val = PACK_IEEE754_32(val);
    pack_int32_t(bp, ieee754_encoded_val, endian);
}

static void pack_double(unsigned char **bp, double val, int endian)
{
    uint64_t ieee754_encoded_val = PACK_IEEE754_64(val);
    pack_int64_t(bp, ieee754_encoded_val, endian);
}

static void unpack_int16_t(const unsigned char **bp, int16_t *dst, int endian)
{
    uint16_t val;
    if (endian == myendian) {
        val = *((*bp)++);
        val |= (uint16_t)(*((*bp)++)) << 8;
    } else {
        val = (uint16_t)(*((*bp)++)) << 8;
        val |= *((*bp)++);
    }
    if (val <= 0x7fffU) {
        *dst = val;
    } else {
        *dst = -1 - (int16_t)(0xffffU - val);
    }
}

static void unpack_uint16_t(const unsigned char **bp, uint16_t *dst, int endian)
{
    if (endian == myendian) {
        *dst = *((*bp)++);
        *dst |= (uint16_t)(*((*bp)++)) << 8;
    } else {
        *dst = (uint16_t)(*((*bp)++)) << 8;
        *dst |= *((*bp)++);
    }
}

static void unpack_int32_t(const unsigned char **bp, int32_t *dst, int endian)
{
    uint32_t val;
    if (endian == myendian) {
        val = *((*bp)++);
        val |= (uint32_t)(*((*bp)++)) << 8;
        val |= (uint32_t)(*((*bp)++)) << 16;
        val |= (uint32_t)(*((*bp)++)) << 24;
    } else {
        val = *((*bp)++) << 24;
        val |= (uint32_t)(*((*bp)++)) << 16;
        val |= (uint32_t)(*((*bp)++)) << 8;
        val |= (uint32_t)(*((*bp)++));
    }
    if (val <= 0x7fffffffU) {
        *dst = val;
    } else {
        *dst = -1 - (int32_t)(0xffffffffU - val);
    }
}

static void unpack_uint32_t(const unsigned char **bp, uint32_t *dst, int endian)
{
    if (endian == myendian) {
        *dst = *((*bp)++);
        *dst |= (uint32_t)(*((*bp)++)) << 8;
        *dst |= (uint32_t)(*((*bp)++)) << 16;
        *dst |= (uint32_t)(*((*bp)++)) << 24;
    } else {
        *dst = *((*bp)++) << 24;
        *dst |= (uint32_t)(*((*bp)++)) << 16;
        *dst |= (uint32_t)(*((*bp)++)) << 8;
        *dst |= (uint32_t)(*((*bp)++));
    }
}

static void unpack_int64_t(const unsigned char **bp, int64_t *dst, int endian)
{
    uint64_t val;
    if (endian == myendian) {
        val = *((*bp)++);
        val |= (uint64_t)(*((*bp)++)) << 8;
        val |= (uint64_t)(*((*bp)++)) << 16;
        val |= (uint64_t)(*((*bp)++)) << 24;
        val |= (uint64_t)(*((*bp)++)) << 32;
        val |= (uint64_t)(*((*bp)++)) << 40;
        val |= (uint64_t)(*((*bp)++)) << 48;
        val |= (uint64_t)(*((*bp)++)) << 56;
    } else {
        val = (uint64_t)(*((*bp)++)) << 56;
        val |= (uint64_t)(*((*bp)++)) << 48;
        val |= (uint64_t)(*((*bp)++)) << 40;
        val |= (uint64_t)(*((*bp)++)) << 32;
        val |= (uint64_t)(*((*bp)++)) << 24;
        val |= (uint64_t)(*((*bp)++)) << 16;
        val |= (uint64_t)(*((*bp)++)) << 8;
        val |= *((*bp)++);
    }
    if (val <= 0x7fffffffffffffffULL) {
        *dst = val;
    } else {
        *dst = -1 - (int64_t)(0xffffffffffffffffULL - val);
    }
}

static void unpack_uint64_t(const unsigned char **bp, uint64_t *dst, int endian)
{
    if (endian == myendian) {
        *dst = *((*bp)++);
        *dst |= (uint64_t)(*((*bp)++)) << 8;
        *dst |= (uint64_t)(*((*bp)++)) << 16;
        *dst |= (uint64_t)(*((*bp)++)) << 24;
        *dst |= (uint64_t)(*((*bp)++)) << 32;
        *dst |= (uint64_t)(*((*bp)++)) << 40;
        *dst |= (uint64_t)(*((*bp)++)) << 48;
        *dst |= (uint64_t)(*((*bp)++)) << 56;
    } else {
        *dst = (uint64_t)(*((*bp)++)) << 56;
        *dst |= (uint64_t)(*((*bp)++)) << 48;
        *dst |= (uint64_t)(*((*bp)++)) << 40;
        *dst |= (uint64_t)(*((*bp)++)) << 32;
        *dst |= (uint64_t)(*((*bp)++)) << 24;
        *dst |= (uint64_t)(*((*bp)++)) << 16;
        *dst |= (uint64_t)(*((*bp)++)) << 8;
        *dst |= *((*bp)++);
    }
}

static void unpack_float(const unsigned char **bp, float *dst, int endian)
{
    uint32_t ieee754_encoded_val = 0;
    unpack_uint32_t(bp, &ieee754_encoded_val, endian);
    *dst = UNPACK_IEEE754_32(ieee754_encoded_val);
}

static void unpack_double(const unsigned char **bp, double *dst, int endian)
{
    uint64_t ieee754_encoded_val = 0;
    unpack_uint64_t(bp, &ieee754_encoded_val, endian);
    *dst = UNPACK_IEEE754_64(ieee754_encoded_val);
}

static int pack_va_list(unsigned char *buf, int offset, const char *fmt,
                        va_list args)
{
    INIT_REPETITION();
    const char *p;
    unsigned char *bp;
    int *ep = &myendian;
    int endian;

    char b;
    unsigned char B;
    int16_t h;
    uint16_t H;
    int32_t l;
    uint32_t L;
    int64_t q;
    uint64_t Q;
    float f;
    double d;
    char *s;

    if (STRUCT_ENDIAN_NOT_SET == myendian) {
        struct_init();
    }

    /*
     * 'char' and 'short' values, they must be extracted as 'int's,
     * because C promotes 'char' and 'short' arguments to 'int' when they are
     * represented by an ellipsis ... parameter.
     */

    bp = buf + offset;
    for (p = fmt; *p != '\0'; p++) {
        switch (*p) {
            case '=': /* native */
                ep = &myendian;
                break;
            case '<': /* little-endian */
                endian = STRUCT_ENDIAN_LITTLE;
                ep = &endian;
                break;
            case '>': /* big-endian */
                endian = STRUCT_ENDIAN_BIG;
                ep = &endian;
                break;
            case '!': /* network (= big-endian) */
                endian = STRUCT_ENDIAN_BIG;
                ep = &endian;
                break;
            case 'b':
                BEGIN_REPETITION();
                    b = va_arg(args, int);
                    *bp++ = b;
                END_REPETITION();
                break;
            case 'B':
                BEGIN_REPETITION();
                    B = va_arg(args, unsigned int);
                    *bp++ = B;
                END_REPETITION();
                break;
            case 'h':
                BEGIN_REPETITION();
                    h = va_arg(args, int);
                    pack_int16_t(&bp, h, *ep);
                END_REPETITION();
                break;
            case 'H':
                BEGIN_REPETITION();
                    H = va_arg(args, int);
                    pack_int16_t(&bp, H, *ep);
                END_REPETITION();
                break;
            case 'i': /* fall through */
            case 'l':
                BEGIN_REPETITION();
                    l = va_arg(args, int32_t);
                    pack_int32_t(&bp, l, *ep);
                END_REPETITION();
                break;
            case 'I': /* fall through */
            case 'L':
                BEGIN_REPETITION();
                    L = va_arg(args, uint32_t);
                    pack_int32_t(&bp, L, *ep);
                END_REPETITION();
                break;
            case 'q':
                BEGIN_REPETITION();
                    q = va_arg(args, int64_t);
                    pack_int64_t(&bp, q, *ep);
                END_REPETITION();
                break;
            case 'Q':
                BEGIN_REPETITION();
                    Q = va_arg(args, uint64_t);
                    pack_int64_t(&bp, Q, *ep);
                END_REPETITION();
                break;
            case 'f':
                BEGIN_REPETITION();
                    f = va_arg(args, double);
                    pack_float(&bp, f, *ep);
                END_REPETITION();
                break;
            case 'd':
                BEGIN_REPETITION();
                    d = va_arg(args, double);
                    pack_double(&bp, d, *ep);
                END_REPETITION();
                break;
            case 's': /* fall through */
            case 'p':
            {
                int i = 0;
                s = va_arg(args, char*);
                BEGIN_REPETITION();
                    *bp++ = s[i++];
                END_REPETITION();
            }
                break;
            case 'x':
                BEGIN_REPETITION();
                    *bp++ = 0;
                END_REPETITION();
                break;
            default:
                if (isdigit((int)*p)) {
                    INC_REPETITION();
                } else {
                    return -1;
                }
        }

        if (!isdigit((int)*p)) {
            CLEAR_REPETITION();
        }
    }
    return (bp - buf);
}

static int unpack_va_list(
        const unsigned char *buf,
        int offset,
        const char *fmt,
        va_list args)
{
    INIT_REPETITION();
    const char *p;
    const unsigned char *bp;
    int *ep = &myendian;
    int endian;

    char *b;
    unsigned char *B;
    int16_t *h;
    uint16_t *H;
    int32_t *l;
    uint32_t *L;
    int64_t *q;
    uint64_t *Q;
    float *f;
    double *d;
    char *s;

    if (STRUCT_ENDIAN_NOT_SET == myendian) {
        struct_init();
    }

    bp = buf + offset;
    for (p = fmt; *p != '\0'; p++) {
        switch (*p) {
            case '=': /* native */
                ep = &myendian;
                break;
            case '<': /* little-endian */
                endian = STRUCT_ENDIAN_LITTLE;
                ep = &endian;
                break;
            case '>': /* big-endian */
                endian = STRUCT_ENDIAN_BIG;
                ep = &endian;
                break;
            case '!': /* network (= big-endian) */
                endian = STRUCT_ENDIAN_BIG;
                ep = &endian;
                break;
            case 'b':
                BEGIN_REPETITION();
                    b = va_arg(args, char*);
                    *b = *bp++;
                END_REPETITION();
                break;
            case 'B':
                BEGIN_REPETITION();
                    B = va_arg(args, unsigned char*);
                    *B = *bp++;
                END_REPETITION();
                break;
            case 'h':
                BEGIN_REPETITION();
                    h = va_arg(args, int16_t*);
                    unpack_int16_t(&bp, h, *ep);
                END_REPETITION();
                break;
            case 'H':
                BEGIN_REPETITION();
                    H = va_arg(args, uint16_t*);
                    unpack_uint16_t(&bp, H, *ep);
                END_REPETITION();
                break;
            case 'i': /* fall through */
            case 'l':
                BEGIN_REPETITION();
                    l = va_arg(args, int32_t*);
                    unpack_int32_t(&bp, l, *ep);
                END_REPETITION();
                break;
            case 'I': /* fall through */
            case 'L':
                BEGIN_REPETITION();
                    L = va_arg(args, uint32_t*);
                    unpack_uint32_t(&bp, L, *ep);
                END_REPETITION();
                break;
            case 'q':
                BEGIN_REPETITION();
                    q = va_arg(args, int64_t*);
                    unpack_int64_t(&bp, q, *ep);
                END_REPETITION();
                break;
            case 'Q':
                BEGIN_REPETITION();
                    Q = va_arg(args, uint64_t*);
                    unpack_uint64_t(&bp, Q, *ep);
                END_REPETITION();
                break;
            case 'f':
                BEGIN_REPETITION();
                    f = va_arg(args, float*);
                    unpack_float(&bp, f, *ep);
                END_REPETITION();
                break;
            case 'd':
                BEGIN_REPETITION();
                    d = va_arg(args, double*);
                    unpack_double(&bp, d, *ep);
                END_REPETITION();
                break;
            case 's': /* fall through */
            case 'p':
            {
                int i = 0;
                s = va_arg(args, char*);
                BEGIN_REPETITION();
                    s[i++] = *bp++;
                END_REPETITION();
            }
                break;
            case 'x':
                BEGIN_REPETITION();
                    bp++;
                END_REPETITION();
                break;
            default:
                if (isdigit((int)*p)) {
                    INC_REPETITION();
                } else {
                    return -1;
                }
        }

        if (!isdigit((int)*p)) {
            CLEAR_REPETITION();
        }
    }
    return (bp - buf);
}

/*
 * EXPORT
 *
 * preifx: struct_
 *
 */
int struct_pack(void *buf, const char *fmt, ...)
{
    va_list args;
    int packed_len = 0;

    va_start(args, fmt);
    packed_len = pack_va_list(
            (unsigned char*)buf, 0, fmt, args);
    va_end(args);

    return packed_len;
}

int struct_pack_into(int offset, void *buf, const char *fmt, ...)
{
    va_list args;
    int packed_len = 0;

    va_start(args, fmt);
    packed_len = pack_va_list(
            (unsigned char*)buf, offset, fmt, args);
    va_end(args);

    return packed_len;
}

int struct_unpack(const void *buf, const char *fmt, ...)
{
    va_list args;
    int unpacked_len = 0;

    va_start(args, fmt);
    unpacked_len = unpack_va_list(
            (const unsigned char*)buf, 0, fmt, args);
    va_end(args);

    return unpacked_len;
}

int struct_unpack_from(int offset, const void *buf, const char *fmt, ...)
{
    va_list args;
    int unpacked_len = 0;

    va_start(args, fmt);
    unpacked_len = unpack_va_list(
            (const unsigned char*)buf, offset, fmt, args);
    va_end(args);

    return unpacked_len;
}

int struct_calcsize(const char *fmt)
{
    INIT_REPETITION();
    int ret = 0;
    const char *p;

    if (STRUCT_ENDIAN_NOT_SET == myendian) {
        struct_init();
    }

    for (p = fmt; *p != '\0'; p++) {
        switch (*p) {
            case '=': /* fall through */
            case '<': /* fall through */
            case '>': /* fall through */
            case '!': /* ignore endian characters */
                break;
            case 'b':
                BEGIN_REPETITION();
                    ret += sizeof(int8_t);
                END_REPETITION();
                break;
            case 'B':
                BEGIN_REPETITION();
                    ret += sizeof(uint8_t);
                END_REPETITION();
                break;
            case 'h':
                BEGIN_REPETITION();
                    ret += sizeof(int16_t);
                END_REPETITION();
                break;
            case 'H':
                BEGIN_REPETITION();
                    ret += sizeof(uint16_t);
                END_REPETITION();
                break;
            case 'i': /* fall through */
            case 'l':
                BEGIN_REPETITION();
                    ret += sizeof(int32_t);
                END_REPETITION();
                break;
            case 'I': /* fall through */
            case 'L':
                BEGIN_REPETITION();
                    ret += sizeof(uint32_t);
                END_REPETITION();
                break;
            case 'q':
                BEGIN_REPETITION();
                    ret += sizeof(int64_t);
                END_REPETITION();
                break;
            case 'Q':
                BEGIN_REPETITION();
                    ret += sizeof(uint64_t);
                END_REPETITION();
                break;
            case 'f':
                BEGIN_REPETITION();
                    ret += sizeof(int32_t); // see pack_float()
                END_REPETITION();
                break;
            case 'd':
                BEGIN_REPETITION();
                    ret += sizeof(int64_t); // see pack_double()
                END_REPETITION();
                break;
            case 's': /* fall through */
            case 'p':
                BEGIN_REPETITION();
                    ret += sizeof(int8_t);
                END_REPETITION();
                break;
            case 'x':
                BEGIN_REPETITION();
                    ret += sizeof(int8_t);
                END_REPETITION();
                break;
            default:
                if (isdigit((int)*p)) {
                    INC_REPETITION();
                } else {
                    return -1;
                }
        }

        if (!isdigit((int)*p)) {
            CLEAR_REPETITION();
        }
    }
    return ret;
}