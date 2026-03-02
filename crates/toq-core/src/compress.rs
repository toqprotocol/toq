use std::io::{Read, Write};

use crate::error::Error;

/// Compress data using gzip.
pub fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| Error::Io(e.to_string()))?;
    encoder.finish().map_err(|e| Error::Io(e.to_string()))
}

/// Decompress gzip data.
pub fn gzip_decompress(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut result = Vec::new();
    decoder
        .read_to_end(&mut result)
        .map_err(|e| Error::Io(e.to_string()))?;
    Ok(result)
}

/// Compress data using zstd.
pub fn zstd_compress(data: &[u8]) -> Result<Vec<u8>, Error> {
    zstd::encode_all(data, crate::constants::ZSTD_COMPRESSION_LEVEL)
        .map_err(|e| Error::Io(e.to_string()))
}

/// Decompress zstd data.
pub fn zstd_decompress(data: &[u8]) -> Result<Vec<u8>, Error> {
    zstd::decode_all(data).map_err(|e| Error::Io(e.to_string()))
}
