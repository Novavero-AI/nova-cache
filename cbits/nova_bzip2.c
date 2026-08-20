#include "nova_bzip2.h"

#include <stdlib.h>

/* calloc so every field starts zeroed: libbz2 reads NULL allocator
   hooks as "use malloc/free", and a NULL state field makes the
   destroy below safe on a stream that was never initialized. */
bz_stream *nova_bzip2_stream_new(void)
{
    return (bz_stream *) calloc(1, sizeof(bz_stream));
}

/* ForeignPtr finalizer.  BZ2_bzDecompressEnd on an uninitialized or
   already-ended stream is a harmless BZ_PARAM_ERROR, so this is safe
   in every decoder state; a NULL strm (failed calloc) is a no-op. */
void nova_bzip2_stream_destroy(bz_stream *strm)
{
    if (strm != NULL) {
        (void) BZ2_bzDecompressEnd(strm);
        free(strm);
    }
}

/* verbosity 0 and small 0 (the fast algorithm), the arguments
   upstream Nix's decompression sink passes.  BZ2_bzDecompressInit
   itself rejects a NULL strm with BZ_PARAM_ERROR, so a failed calloc
   surfaces as a status, not a crash. */
int nova_bzip2_decompress_init(bz_stream *strm)
{
    return BZ2_bzDecompressInit(strm, 0, 0);
}

/* Between concatenated streams: tear down and start fresh on the
   same struct, as upstream's decompression sink does at stream end
   while input remains. */
int nova_bzip2_decompress_reinit(bz_stream *strm)
{
    int ret = BZ2_bzDecompressEnd(strm);
    if (ret != BZ_OK) {
        return ret;
    }
    return BZ2_bzDecompressInit(strm, 0, 0);
}

/* One BZ2_bzDecompress call: feed input, fill output, report both
   counts.  libbz2 only reads through next_in, but the field is not
   const-qualified, so the parameter is plain char *. */
int nova_bzip2_decompress_step(bz_stream *strm,
                               char *input, unsigned int input_len,
                               char *output, unsigned int output_len,
                               unsigned int *consumed,
                               unsigned int *produced)
{
    int ret;
    strm->next_in = input;
    strm->avail_in = input_len;
    strm->next_out = output;
    strm->avail_out = output_len;
    ret = BZ2_bzDecompress(strm);
    *consumed = input_len - strm->avail_in;
    *produced = output_len - strm->avail_out;
    return ret;
}
