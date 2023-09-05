### Origin and License

Taken verbatim from https://github.com/google/brotli/commit/c1bd196833e4ce05ef49b82ec5e124bb79e095ff
below "c", with the exception of this file and removal of the directories "fuzz" and "tools".

Sources are under an MIT-style license. Also, Google has made a RF commitment here:
https://datatracker.ietf.org/ipr/2396
Excerpt:
"In addition, to facilitate the use of the Brotli Compression Algorithm in
other applications, Google hereby provides a W3C RF commitment (that is not
limited to font data) to the Brotli Compression Algorithm specification
linked above and, if that specification leads to a final IETF RFC for
Brotli, then to the specification in that RFC."


### Introduction to Brotli

Brotli is a generic-purpose lossless compression algorithm that compresses data
using a combination of a modern variant of the LZ77 algorithm, Huffman coding
and 2nd order context modeling, with a compression ratio comparable to the best
currently available general-purpose compression methods. It is similar in speed
with deflate but offers more dense compression.

The specification of the Brotli Compressed Data Format is defined in [RFC 7932](https://tools.ietf.org/html/rfc7932).

Brotli is open-sourced under the MIT License, see the LICENSE file.

> **Please note:** brotli is a "stream" format; it does not contain
> meta-information, like checksums or uncompresssed data length. It is possible
> to modify "raw" ranges of the compressed stream and the decoder will not
> notice that.
