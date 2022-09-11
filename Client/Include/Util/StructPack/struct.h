#ifndef STRUCT_INCLUDED
#define STRUCT_INCLUDED

/*
 * struct.h
 *
 *  Created on: 2011. 5. 2.
 *      Author: wonseok choi (svperbeast@gmail.com)
 *
 * Interpret strings as packed binary data
 *
 * Table 1. Byte order
 *  ----------------------------------
 *  Character | Byte order
 *  ----------+-----------------------
 *   =        | native
 *  ----------+-----------------------
 *   <        | little-endian
 *  ----------+-----------------------
 *   >        | big-endian
 *  ----------+-----------------------
 *   !        | network (= big-endian)
 *  ----------------------------------
 *
 * Table 2. Format characters
 *  -------------------------------------------
 *  Format | C/C++ Type         | Standard size
 *  -------+--------------------+--------------
 *   b     | char               | 1
 *  -------+--------------------+--------------
 *   B     | unsigned char      | 1
 *  -------+--------------------+--------------
 *   h     | short              | 2
 *  -------+--------------------+--------------
 *   H     | unsigned short     | 2
 *  -------+--------------------+--------------
 *   i     | int                | 4
 *  -------+--------------------+--------------
 *   I     | unsigned int       | 4
 *  -------+--------------------+--------------
 *   l     | long               | 4
 *  -------+--------------------+--------------
 *   L     | unsigned long      | 4
 *  -------+--------------------+--------------
 *   q     | long long          | 8
 *  -------+--------------------+--------------
 *   Q     | unsigned long long | 8
 *  -------+--------------------+--------------
 *   f     | float              | 4
 *  -------+--------------------+--------------
 *   d     | double             | 8
 *  -------+--------------------+--------------
 *   s     | char[]             |
 *  -------+--------------------+--------------
 *   p     | char[]             |
 *  -------+--------------------+--------------
 *   x     | pad bytes          |
 *  -------------------------------------------
 *
 * A format character may be preceded by an integral repeat count.
 * For example, the format string '4h' means exactly the same as 'hhhh'.
 *
 * For the 's' format character, the count is interpreted as the size of the
 * string, not a repeat count like for the other format characters.
 * For example, '10s' means a single 10-byte string.
 *
 * Example 1. pack/unpack int type value.
 *
 * char buf[BUFSIZ] = {0, };
 * int val = 0x12345678;
 * int oval;
 *
 * struct_pack(buf, "i", val);
 * struct_unpack(buf, "i", &oval);
 *
 * Example 2. pack/unpack a string.
 *
 * char buf[BUFSIZ] = {0, };
 * char str[32] = {'\0', };
 * char fmt[32] = {'\0', };
 * char ostr[32] = {'\0', };
 *
 * strcpy(str, "test");
 * sprintf(fmt, "%ds", strlen(str));
 *
 * struct_pack(buf, fmt, str);
 * struct_unpack(buf, fmt, ostr);
 *
 */

#define STRUCT_ENDIAN_NOT_SET   0
#define STRUCT_ENDIAN_BIG       1
#define STRUCT_ENDIAN_LITTLE    2

extern int struct_get_endian(void);

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief pack data
 * @return the number of bytes encoded on success, -1 on failure.
 */
extern int struct_pack(void *buf, const char *fmt, ...);

/**
 * @brief pack data with offset
 * @return the number of bytes encoded on success, -1 on failure.
 */
extern int struct_pack_into(int offset, void *buf, const char *fmt, ...);

/**
 * @brief unpack data
 * @return the number of bytes decoded on success, -1 on failure.
 */
extern int struct_unpack(const void *buf, const char *fmt, ...);

/**
 * @brief unpack data with offset
 * @return the number of bytes decoded on success, -1 on failure.
 */
extern int struct_unpack_from(
        int offset,
        const void *buf,
        const char *fmt,
        ...);

/**
 * @brief calculate the size of a format string
 * @return the number of bytes needed by the format string on success,
 * -1 on failure.
 *
 * make sure that the return value is > 0, before using it.
 */
extern int struct_calcsize(const char *fmt);

#ifdef __cplusplus
}
#endif

#endif /* !STRUCT_INCLUDED */