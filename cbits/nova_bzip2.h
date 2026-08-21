/* Shim over libbz2 for NovaCache.Bzip2.  The bz_stream struct stays
   on the C side, where the compiler knows its layout, so the Haskell
   binding carries no struct offsets to drift across platforms. */
#ifndef NOVA_BZIP2_H
#define NOVA_BZIP2_H

#include <bzlib.h>

bz_stream *nova_bzip2_stream_new(void);
void nova_bzip2_stream_destroy(bz_stream *strm);
int nova_bzip2_decompress_init(bz_stream *strm);
int nova_bzip2_decompress_reinit(bz_stream *strm);
int nova_bzip2_decompress_step(bz_stream *strm,
                               char *input, unsigned int input_len,
                               char *output, unsigned int output_len,
                               unsigned int *consumed,
                               unsigned int *produced);

#endif
