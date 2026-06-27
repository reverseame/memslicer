"""Compression/decompression wrappers for MSL page data."""
import zstandard
import lz4.block

from memslicer.msl.constants import CompAlgo

_ZSTD_COMPRESSOR = zstandard.ZstdCompressor()
_ZSTD_DECOMPRESSOR = zstandard.ZstdDecompressor()


def compress(data: bytes, algo: CompAlgo) -> bytes:
    """Compress data using the specified algorithm."""
    if algo == CompAlgo.NONE:
        return data
    if algo == CompAlgo.ZSTD:
        return _ZSTD_COMPRESSOR.compress(data)
    if algo == CompAlgo.LZ4:
        return lz4.block.compress(data, store_size=True)
    raise ValueError(f"Unknown compression algorithm: {algo}")


def decompress(data: bytes, algo: CompAlgo,
               uncompressed_size: int | None = None) -> bytes:
    """Decompress data using the specified algorithm.

    *uncompressed_size*, when known (the block writer stores it), lets the LZ4
    path cope with the writer's 8-byte block alignment: ``_write_block`` packs
    ``UncompressedSize + lz4-block`` and pads the tuple to 8 bytes, so the
    payload handed here may carry up to 7 trailing padding bytes. With
    ``store_size`` embedded, ``lz4.block.decompress`` consumes the WHOLE input
    and overruns the output on that padding ("insufficient space in destination
    buffer"). The true compressed length is not recoverable arithmetically (the
    whole tuple is 8-aligned), so we strip 0..7 trailing bytes and accept the
    first decode whose length matches *uncompressed_size*.
    """
    if algo == CompAlgo.NONE:
        return data
    if algo == CompAlgo.ZSTD:
        # zstd frames are self-delimiting -> trailing padding is ignored.
        return _ZSTD_DECOMPRESSOR.decompress(data)
    if algo == CompAlgo.LZ4:
        if uncompressed_size is None:
            return lz4.block.decompress(data)
        last_err: Exception | None = None
        for pad in range(0, 8):
            chunk = data[:len(data) - pad] if pad else data
            try:
                out = lz4.block.decompress(chunk)
            except Exception as exc:  # noqa: BLE001 - over-read on padding; retry shorter
                last_err = exc
                continue
            if len(out) == uncompressed_size:
                return out
        if last_err is not None:
            raise last_err
        raise ValueError(
            f"lz4 decode produced no output matching uncompressed_size "
            f"{uncompressed_size}"
        )
    raise ValueError(f"Unknown compression algorithm: {algo}")
