//! Collection of utility functions to read data from a stream.

use std::{
    convert::{TryFrom, TryInto},
    io::{Error, Result, prelude::*},
};

use byteorder::{BigEndian, ByteOrder, LittleEndian};
use cesu8::{from_java_cesu8, to_java_cesu8};

/// Reads a Java character. Note that in Java, characters are 16-bit "Unicode" values.
pub fn read_char(readable: &mut dyn Read) -> Result<[u8; 2]> {
    let mut buf: [u8; 2] = [0; 2];
    readable.read_exact(&mut buf)?;
    Ok(buf)
}

/// Reads a string, encoded in CESU-8 (a UTF-8 variant).
pub fn read_cesu8(readable: &mut dyn Read) -> Result<(usize, String)> {
    let mut total_read = 2; // length u16
    let mut buf: [u8; 2] = [0; 2];
    readable.read_exact(&mut buf)?;
    let cesu8_len = BigEndian::read_u16(&buf);

    let mut utf_buf: Vec<u8> = vec![0; cesu8_len.into()];
    readable.read_exact(&mut utf_buf)?;
    total_read += cesu8_len as usize;

    let s = from_java_cesu8(&utf_buf).map_err(Error::other)?;
    Ok((total_read, s.into_owned()))
}

/// Encodes a string as CESU-8 string (a UTF-8 variant).
pub fn str_to_cesu8(string: &str) -> Vec<u8> {
    let cesu8_len = string.len();
    let mut buf: Vec<u8> = [0; 2].to_vec();
    BigEndian::write_u16(&mut buf, cesu8_len.try_into().unwrap());
    let str_buf = to_java_cesu8(string).into_owned();
    buf.extend(str_buf);
    buf
}

/// Reads a u32 encoded as little-endian
pub fn read_u32le(readable: &mut dyn Read) -> Result<u32> {
    let mut buf: [u8; 4] = [0; 4];
    readable.read_exact(&mut buf)?;
    Ok(LittleEndian::read_u32(&buf))
}

/// Reads a u64 encoded as big-endian
pub fn read_u64be(readable: &mut dyn Read) -> Result<u64> {
    let mut buf: [u8; 8] = [0; 8];
    readable.read_exact(&mut buf)?;
    Ok(BigEndian::read_u64(&buf))
}

/// Reads an array of boolean values preceded by a varint length
pub fn read_bool_array(readable: &mut dyn Read) -> Result<Vec<u8>> {
    let bool_len = read_var_int(readable)?;
    let buf_len = bool_len / 8 + u32::from(bool_len % 8 != 0); // Div round up
    let mut probe_buf: Vec<u8> = vec![0; usize::try_from(buf_len).unwrap()];
    readable.read_exact(&mut probe_buf)?;
    Ok(probe_buf)
}

/// Reads a varint u32. A varint is defined as one or more bytes; each byte's
/// most significant bit is 1 if more bytes are to follow. The seven remaining
/// bits of each byte are concatenated in little-endian order.
/// This function does not check if the encoded value fits in a u32.
pub fn read_var_int(readable: &mut dyn Read) -> Result<u32> {
    let mut buf: [u8; 1] = [0];
    readable.read_exact(&mut buf)?;
    let b = buf[0];
    if b & 0x80 == 0 {
        return Ok(b as u32);
    }
    let nxt = read_var_int(readable)?;
    Ok((b & 0x7f) as u32 | (nxt << 7))
}

/// Reads a byte vector, preceded by a length given as little-endian u32.
pub fn read_byte_vec(stream: &mut dyn Read) -> Result<Vec<u8>> {
    let mut buffer: Vec<u8> = vec![0; read_u32le(stream)? as usize];
    stream.read_exact(&mut buffer)?;
    Ok(buffer)
}
