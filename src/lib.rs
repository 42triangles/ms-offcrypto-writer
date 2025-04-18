//! This crate allows encrypting ECMA376/OOXML (so newer MS-Office files such as
//! XLSX) using the agile encryption method as described in
//! [MS-OFFCRYPTO](https://msopenspecs.azureedge.net/files/MS-OFFCRYPTO/[MS-OFFCRYPTO].pdf).
//!
//! See the [`Ecma376AgileWriter`] type for the actual API of this crate.
//!
//! # Implementation details
//! All functions writing structures expect the buffer to be logically aligned
//! to (= the length of the buffer is a multiple of) four bytes, and leave the
//! buffer aligned to four bytes upon returning.
//!
//! A such, they may panic if and only if
//! 1. They are passed an improperly aligned buffer, or
//! 2. Reallocation of the buffer upon growing fails.

use std::{
    fmt,
    io::{self, prelude::*, SeekFrom},
    mem,
    ops::RangeBounds,
};

use aes::Aes256;
use cfb::{CompoundFile, Stream};
use cipher::{block_padding::NoPadding, BlockEncryptMut, BlockSizeUser, KeyIvInit, KeySizeUser};
use hmac::Mac;
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha512};
use widestring::{utf16str, Utf16Str};

type HmacSha512 = hmac::Hmac<Sha512>;

/// The number of iterations of hashing the password (see 2.3.4.13).
const SPIN_COUNT: u32 = 100_000;

/// The size of the header in the CFB stream of the actual encrypted data (see
/// 2.3.4.4).
const ENCRYPTED_PACKAGE_HEADER_SIZE: u64 = size_of::<u64>() as u64;

/// Append a `UNICODE-LP-P4`, as defined in 2.1.2, to a buffer,
fn write_unicode_lp_p4(buffer: &mut Vec<u8>, data: &Utf16Str) {
    let length = data.len() * 2;

    buffer.reserve(4 + length.next_multiple_of(4));

    // Length:
    buffer.extend(&u32::to_le_bytes(length.try_into().unwrap()));

    // Data:
    for i in data.code_units() {
        buffer.extend(&u16::to_le_bytes(i));
    }

    // Padding:
    if length % 4 != 0 {
        buffer.extend(&[0u8; 4][..(length.next_multiple_of(4) - length)]);
    }
}

/// Append a `Version`, as defined in 2.1.4, to a buffer.
fn write_version(buffer: &mut Vec<u8>, major: u16, minor: u16) {
    buffer.reserve(4);
    buffer.extend(&u16::to_le_bytes(major));
    buffer.extend(&u16::to_le_bytes(minor));
}

fn len_backpatch(buffer: &mut [u8], index: usize, length_of: impl RangeBounds<usize>) {
    let len = buffer[(
        length_of.start_bound().cloned(),
        length_of.end_bound().cloned(),
    )]
        .len();
    buffer[index..(index + 4)].copy_from_slice(&u32::to_le_bytes(len.try_into().unwrap()));
}

/// Write a `DataSpaceVersionInfo`, as defined in 2.1.5, to a buffer, clearing
/// any previous contents and returning a read-only slice to the resulting
/// bytes.
fn data_space_version_info(buffer: &mut Vec<u8>) -> &[u8] {
    // type: DataSpaceVersionInfo
    buffer.clear();
    // FeatureIdentifier:
    write_unicode_lp_p4(buffer, utf16str!("Microsoft.Container.DataSpaces"));
    // ReaderVersion:
    write_version(buffer, 1, 0);
    // UpdaterVersion:
    write_version(buffer, 1, 0);
    // WriterVersion:
    write_version(buffer, 1, 0);

    buffer
}

/// Write a `DataSpaceMap`, as defined in 2.1.6, to a buffer, clearing any
/// previous contents and returning a read-only slice to the resulting bytes.
fn data_space_map(buffer: &mut Vec<u8>) -> &[u8] {
    // type: DataSpaceMap
    buffer.clear();
    // HeaderLength:
    buffer.extend(&u32::to_le_bytes(8));
    // EntryCount:
    buffer.extend(&u32::to_le_bytes(1));
    // MapEntries:
    // a single entry of type: DataSpaceMapEntry
    // (MapEntries[0] as DataSpaceMapEntry).Length
    let length_pos = buffer.len();
    buffer.extend(&u32::to_le_bytes(0));
    // MapEntries[0].ReferenceComponentCount
    buffer.extend(&u32::to_le_bytes(1));
    // MapEntries[0].ReferenceComponents[0].ReferenceComponentType
    buffer.extend(&u32::to_le_bytes(0));
    // MapEntries[0].ReferenceComponents[0].ReferenceComponent
    write_unicode_lp_p4(buffer, utf16str!("EncryptedPackage"));
    // MapEntries[0].DataSpaceName
    write_unicode_lp_p4(buffer, utf16str!("StrongEncryptionDataSpace"));

    len_backpatch(buffer, length_pos, length_pos..);

    buffer
}

/// Write a `DataSpaceDefinition`, as defined in 2.1.7, to a buffer, clearing
/// any previous contents and returning a read-only slice to the resulting
/// bytes.
fn data_space_definition(buffer: &mut Vec<u8>) -> &[u8] {
    // type: DataSpaceDefinition
    buffer.clear();
    // HeaderLength
    buffer.extend(&u32::to_le_bytes(8));
    // TransformReferenceCount
    buffer.extend(&u32::to_le_bytes(1));
    // TransformReferences[0]
    write_unicode_lp_p4(buffer, utf16str!("StrongEncryptionTransform"));

    buffer
}

/// Write a `TransformInfoHeader`, as defined in 2.1.8, and then an
/// `EncryptionTransformInfo`, as defined in 2.1.9, to a buffer, clearing any
/// previous contents and returning a read-only slice to the resulting bytes.
fn transform_info(buffer: &mut Vec<u8>) -> &[u8] {
    buffer.clear();

    // type: TransformInfoHeader
    // TransformLength
    let transform_length_pos = buffer.len();
    buffer.extend(&u32::to_le_bytes(0));
    // TransformType
    buffer.extend(&u32::to_le_bytes(1));
    // TransformID
    write_unicode_lp_p4(buffer, utf16str!("{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}"));

    len_backpatch(buffer, transform_length_pos, ..);
    // TransformName
    write_unicode_lp_p4(buffer, utf16str!("Microsoft.Container.EncryptionTransform"));
    // ReaderVersion
    write_version(buffer, 1, 0);
    // UpdaterVersion
    write_version(buffer, 1, 0);
    // WriterVersion
    write_version(buffer, 1, 0);

    // type: EncryptionTransformInfo
    // EncryptionName (null)
    buffer.extend(&u32::to_le_bytes(0));
    // EncryptionBlockSize. What this value should actually be in the standard is at
    // best underspecified, and the actual value is taken from files encrypted
    // by the reference implementation.
    buffer.extend(&u32::to_le_bytes(0));
    // CipherMode
    buffer.extend(&u32::to_le_bytes(0));
    // Reserved
    buffer.extend(&u32::to_le_bytes(4));

    buffer
}

/// Produce the SHA512 hash of the concatenation of any number of byte slices.
#[allow(
    single_use_lifetimes,
    reason = "See the `anonymous_lifetime_in_impl_trait` feature"
)]
fn sha512<'a>(x: impl IntoIterator<Item = &'a [u8]>) -> [u8; 64] {
    let mut sha = Sha512::new();
    x.into_iter().for_each(|i| sha.update(i));
    sha.finalize().into()
}

/// A type that can be used as a password. Passwords are encoded as UTF16LE, so
/// types that can directly return those codepoints without reencoding are
/// preferable.
pub trait Password {
    /// Encode the password as UTF16.
    fn encode_utf16(&self) -> impl IntoIterator<Item = u16> + '_;
}

impl<T: Password + ?Sized> Password for &'_ T {
    fn encode_utf16(&self) -> impl IntoIterator<Item = u16> {
        T::encode_utf16(self)
    }
}

impl Password for str {
    fn encode_utf16(&self) -> impl IntoIterator<Item = u16> {
        self.encode_utf16()
    }
}

impl Password for String {
    fn encode_utf16(&self) -> impl IntoIterator<Item = u16> {
        (**self).encode_utf16()
    }
}

impl Password for Utf16Str {
    fn encode_utf16(&self) -> impl IntoIterator<Item = u16> {
        self.code_units()
    }
}

impl Password for widestring::Utf16String {
    fn encode_utf16(&self) -> impl IntoIterator<Item = u16> {
        self.code_units()
    }
}

impl Password for widestring::U16Str {
    fn encode_utf16(&self) -> impl IntoIterator<Item = u16> {
        self.as_slice().iter().copied()
    }
}

impl Password for widestring::U16String {
    fn encode_utf16(&self) -> impl IntoIterator<Item = u16> {
        self.as_slice().iter().copied()
    }
}

/// Encrypt data with the first 16 bytes of an initialisation vector using
/// AES256 CBC.
///
/// # Panics
/// Panics if `iv` is less than 16 bytes, or if `data` isn't a multiple of 16
/// bytes (since the block size of AES256 is 16 bytes).
fn encrypt_direct<'a>(data: &'a mut [u8], key: [u8; 32], iv: &[u8]) -> &'a [u8] {
    let mut iv_array = [0; 16];
    iv_array.copy_from_slice(&iv[..16]);

    cbc::Encryptor::<Aes256>::new(&key.into(), &iv_array.into())
        .encrypt_padded_mut::<NoPadding>(data, data.len())
        .unwrap();

    data
}

/// Encrypt data with a key, salt & block key. This is used for the HMAC key &
/// value, as well as the actual encrypted blocks of the main encrypted data
/// stream.
fn encrypt_with_block_key<'a>(
    data: &'a mut [u8],
    key: [u8; 32],
    salt: [u8; 16],
    block_key: &[u8],
) -> &'a [u8] {
    encrypt_direct(data, key, &sha512([&salt as &[u8], block_key]))
}

/// A wrapper for a given buffer or file type that implements the ECMA376 Agile
/// encryption as described in [MS-OFFCRYPTO](https://msopenspecs.azureedge.net/files/MS-OFFCRYPTO/[MS-OFFCRYPTO].pdf).
///
/// # Encryption Safety
/// This only ever encrypts once this type is either dropped, or you call
/// [`Ecma376AgileWriter::encrypt`] or [`Ecma376AgileWriter::into_inner`]. This
/// is preferable over just relying on dropping it, as
/// 1. Not dropping a type is safe in Rust (in which case the file would remain
///    unencrypted), and
/// 2. If there are IO errors on encrypting, the `Drop` implementation on this
///    type will panic.
///
/// Additionally, ***THIS TYPE SHOULD NOT BE USED WITH A BACKING THAT ISN'T
/// TRUSTED***, such as a (in most circumstances) a physical file, since
/// otherwise unencrypted data could be leaked for intermediate writes, or in
/// the case of an IO error, the final resulting file.
pub struct Ecma376AgileWriter<F: Read + Write + Seek> {
    cfb: Option<CompoundFile<F>>,
    encrypted_package: Stream<F>,
    verifier_salt: [u8; 16],
    verifier_h_n: [u8; 64],
    key_salt: [u8; 16],
    intermediate_key: [u8; 32],
    hmac_key: [u8; 64],
    verifier_hash_input: [u8; 16],
}

impl<F: Read + Write + Seek> Ecma376AgileWriter<F> {
    /// Create a new [`Ecma376AgileWriter`].
    ///
    /// `file` should initially be empty.
    ///
    /// # Encryption Safety
    /// This type ONLY encrypts the written data once it is either dropped or
    /// [`Self::into_inner`] is called.
    pub fn create(
        rng: &mut (impl CryptoRng + Rng),
        password: impl Password,
        file: F,
    ) -> io::Result<Self> {
        #[allow(clippy::absolute_paths, reason = "this is more readable")]
        let mut cfb = CompoundFile::create_with_version(cfb::Version::V3, file)?;
        cfb.create_storage("\x06DataSpaces")?;

        let mut buffer = Vec::new();

        let write = |cfb: &mut CompoundFile<_>, name, data: &[u8]| -> io::Result<_> {
            let mut stream = cfb.create_new_stream(name)?;
            stream.write_all(data)?;
            stream.flush()?;
            Ok(stream)
        };

        write(
            &mut cfb,
            "/\x06DataSpaces/Version",
            data_space_version_info(&mut buffer),
        )?;

        write(
            &mut cfb,
            "/\x06DataSpaces/DataSpaceMap",
            data_space_map(&mut buffer),
        )?;

        cfb.create_storage("/\x06DataSpaces/DataSpaceInfo")?;
        write(
            &mut cfb,
            "/\x06DataSpaces/DataSpaceInfo/StrongEncryptionDataSpace",
            data_space_definition(&mut buffer),
        )?;

        cfb.create_storage("/\x06DataSpaces/TransformInfo")?;
        cfb.create_storage("/\x06DataSpaces/TransformInfo/StrongEncryptionTransform")?;
        write(
            &mut cfb,
            "/\x06DataSpaces/TransformInfo/StrongEncryptionTransform/\x06Primary",
            transform_info(&mut buffer),
        )?;

        let mut key_salt = [0u8; 16];
        rng.fill(&mut key_salt);
        let mut intermediate_key = [0u8; 32];
        rng.fill(&mut intermediate_key);

        let mut verifier_salt = [0u8; 16];
        rng.fill(&mut verifier_salt);

        let mut verifier_h_0 = Sha512::new_with_prefix(verifier_salt);
        for i in password.encode_utf16() {
            verifier_h_0.update(u16::to_le_bytes(i));
        }
        let verifier_h_0 = <[u8; 64]>::from(verifier_h_0.finalize());

        let mut verifier_h_n = verifier_h_0;
        for i in 0..SPIN_COUNT {
            verifier_h_n = sha512([&u32::to_le_bytes(i) as &[u8], &verifier_h_n]);
        }

        // NOTE: The standard requires this to be the salt length, however actual files
        // encrypted by the reference implementation use 64 bytes.
        let mut hmac_key = [0u8; 64];
        rng.fill(&mut hmac_key);

        let mut verifier_hash_input = [0u8; 16];
        rng.fill(&mut verifier_hash_input);

        let encrypted_package = write(&mut cfb, "/EncryptedPackage", &u64::to_le_bytes(0))?;

        Ok(Ecma376AgileWriter {
            cfb: Some(cfb),
            encrypted_package,
            verifier_salt,
            verifier_h_n,
            key_salt,
            intermediate_key,
            hmac_key,
            verifier_hash_input,
        })
    }

    /// Write the `EncryptionInfo` for Agile Encryption, as defined in 2.3.4.10,
    /// to the provided stream using the HMAC value that resulted from
    /// encrypting the full data stream.
    fn encryption_info(&self, stream: &mut Stream<F>, hmac: HmacSha512) -> io::Result<()> {
        use base64::{
            display::Base64Display,
            engine::general_purpose::{GeneralPurpose, STANDARD},
        };

        fn base64(bytes: &[u8]) -> Base64Display<'_, 'static, GeneralPurpose> {
            Base64Display::new(bytes, &STANDARD)
        }

        let verifier_key = |block_key: &[u8]| {
            let hash = sha512([&self.verifier_h_n as &[u8], block_key]);
            let mut out = [0; 32];
            out.copy_from_slice(&hash[..32]);
            out
        };

        // type: EncryptionInfo for Agile Encryption
        // EncryptionVersionInfo = 0x04u16, 0x04u16
        // Reserved: 0x40u32
        // And then a bunch of XML

        write!(
            stream,
            include_str!("encryption_info.xml"),
            key_salt_size = self.key_salt.len(),
            aes_block_size = Aes256::block_size(),
            aes_key_bits = Aes256::key_size() * 8,
            sha512_size = Sha512::output_size(),
            key_salt_base64 = base64(&self.key_salt),
            encrypted_hmac_key = base64(encrypt_with_block_key(
                &mut { self.hmac_key },
                self.intermediate_key,
                self.key_salt,
                &[0x5F, 0xB2, 0xAD, 0x01, 0x0C, 0xB9, 0xE1, 0xF6],
            )),
            encrypted_hmac_value = base64(encrypt_with_block_key(
                &mut { hmac.finalize().into_bytes() },
                self.intermediate_key,
                self.key_salt,
                &[0xA0, 0x67, 0x7F, 0x02, 0xB2, 0x2C, 0x84, 0x33],
            )),
            spin_count = SPIN_COUNT,
            verifier_salt_size = self.verifier_salt.len(),
            verifier_salt_base64 = base64(&self.verifier_salt),
            verifier_encrypted_hash_input = base64(encrypt_direct(
                &mut { self.verifier_hash_input },
                verifier_key(&[0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79]),
                &self.verifier_salt,
            )),
            verifier_encrypted_hash_value = base64(encrypt_direct(
                &mut Sha512::digest(self.verifier_hash_input),
                verifier_key(&[0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E]),
                &self.verifier_salt,
            )),
            verifier_encrypted_key_value = base64(encrypt_direct(
                &mut { self.intermediate_key },
                verifier_key(&[0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6]),
                &self.verifier_salt,
            )),
        )
    }

    /// Encrypt the encrypted data stream & write the encryption info.
    fn encrypt_impl(&mut self) -> io::Result<F> {
        let mut cfb = self.cfb.take().unwrap();

        let len: u64 = self.encrypted_package.len() - 8;

        if len % 16 != 0 {
            let padding = usize::try_from(len.next_multiple_of(16) - len).unwrap();
            self.encrypted_package.write_all(&[0u8; 16][..padding])?;
        }

        let mut hmac = HmacSha512::new_from_slice(&self.hmac_key).unwrap();

        self.encrypted_package.seek(SeekFrom::Start(0))?;
        self.encrypted_package.write_all(&u64::to_le_bytes(len))?;
        hmac.update(&u64::to_le_bytes(len));

        let mut block_key = 0u32;
        let mut buffer = Box::new([0; 4096]);
        loop {
            let mut length_read = 0;
            loop {
                let remaining = &mut buffer[length_read..];

                let read = self.encrypted_package.read(remaining)?;
                length_read += read;

                if read == 0 {
                    remaining.fill(0);
                    break;
                } else if read == remaining.len() {
                    break;
                }
            }

            let encrypted_len = length_read.next_multiple_of(16);

            encrypt_with_block_key(
                &mut buffer[..encrypted_len],
                self.intermediate_key,
                self.key_salt,
                &u32::to_le_bytes(block_key),
            );

            self.encrypted_package
                .seek(SeekFrom::Current(-i64::try_from(length_read).unwrap()))?;

            self.encrypted_package.write_all(&buffer[..encrypted_len])?;
            hmac.update(&buffer[..encrypted_len]);

            if length_read < buffer.len() {
                // we encountered the end of the stream
                break;
            } else {
                block_key += 1;
            }
        }

        self.encrypted_package.flush()?;

        let mut encryption_info_stream = cfb.create_new_stream("/EncryptionInfo")?;
        self.encryption_info(&mut encryption_info_stream, hmac)?;
        encryption_info_stream.flush()?;

        cfb.flush()?;

        Ok(cfb.into_inner())
    }

    /// Retrieve the inner reader/writer.
    pub fn into_inner(mut self) -> io::Result<F> {
        let out = self.encrypt_impl();
        mem::forget(self);
        out
    }

    /// Encrypt the written file.
    pub fn encrypt(self) -> io::Result<()> {
        self.into_inner().map(|_| ())
    }
}

impl<F: Read + Write + Seek> Read for Ecma376AgileWriter<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.encrypted_package.read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        self.encrypted_package.read_vectored(bufs)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.encrypted_package.read_exact(buf)
    }
}

impl<F: Read + Write + Seek> Write for Ecma376AgileWriter<F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.encrypted_package.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.encrypted_package.flush()
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.encrypted_package.write_vectored(bufs)
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.encrypted_package.write_all(buf)
    }

    fn write_fmt(&mut self, fmt: fmt::Arguments<'_>) -> io::Result<()> {
        self.encrypted_package.write_fmt(fmt)
    }
}

impl<F: Read + Write + Seek> Seek for Ecma376AgileWriter<F> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let out = match pos {
            SeekFrom::Start(pos) => self
                .encrypted_package
                .seek(SeekFrom::Start(pos + ENCRYPTED_PACKAGE_HEADER_SIZE))?,
            SeekFrom::Current(_) | SeekFrom::End(_) => self.encrypted_package.seek(pos)?,
        };

        out.checked_sub(ENCRYPTED_PACKAGE_HEADER_SIZE)
            .ok_or_else(|| io::Error::other("seek failed due to seeking into the header"))
    }
}

impl<F: Read + Write + Seek> Drop for Ecma376AgileWriter<F> {
    fn drop(&mut self) {
        self.encrypt_impl().unwrap();
    }
}

#[cfg(test)]
mod test {
    // NOTE: The tests testing MS-OFFCRYPTO structures are based on what the
    // functions actually produce, and only exist to catch regressions.
    //
    // At the time that these outputs were taken, this crate reliably created
    // encrypted XLSX files that could be read both by LibreOffice Calc &
    // Microsoft Excel.

    use std::io::Cursor;

    use super::*;

    #[test]
    fn write_unicode_lp_p4_len() {
        assert_eq!(unicode_lp_p4_len(utf16str!("")), 4);
        assert_eq!(unicode_lp_p4_len(utf16str!("Even")), 4 + 4 * 2);
        assert_eq!(unicode_lp_p4_len(utf16str!("Longer Odd.")), 4 + 12 * 2);
    }

    #[test]
    fn write_unicode_lp_p4_empty() {
        let mut buffer = b"some prefix ".to_vec();
        write_unicode_lp_p4(&mut buffer, &utf16str!(""));
        assert_eq!(buffer, b"some prefix \0\0\0\0");
    }

    #[test]
    fn write_unicode_lp_p4_even() {
        let mut buffer = b"some prefix ".to_vec();
        write_unicode_lp_p4(&mut buffer, &utf16str!("Even"));
        assert_eq!(buffer, b"some prefix \x08\0\0\0E\0v\0e\0n\0");
    }

    #[test]
    fn write_unicode_lp_p4_odd() {
        let mut buffer = b"some prefix ".to_vec();
        write_unicode_lp_p4(&mut buffer, &utf16str!("Longer Odd."));
        assert_eq!(
            buffer,
            b"some prefix \x16\0\0\0L\0o\0n\0g\0e\0r\0 \0O\0d\0d\0.\0\0\0"
        );
    }

    #[test]
    fn write_version_okay() {
        let mut buffer = b"some prefix ".to_vec();
        write_version(&mut buffer, 1, 2);
        assert_eq!(buffer, b"some prefix \x01\0\x02\0");
    }

    #[test]
    fn data_space_version_info() {
        let mut buffer = b"something".to_vec(); // should be cleared
        assert_eq!(
            super::data_space_version_info(&mut buffer),
            b"\x3C\0\0\0\
            M\0i\0c\0r\0o\0s\0o\0f\0t\0.\0C\0o\0n\0t\0a\0i\0n\0e\0r\0.\0\
            D\0a\0t\0a\0S\0p\0a\0c\0e\0s\0\
            \x01\0\0\0\x01\0\0\0\x01\0\0\0",
        );
    }

    #[test]
    fn data_space_map() {
        let mut buffer = b"something".to_vec(); // should be cleared
        assert_eq!(
            super::data_space_map(&mut buffer),
            b"\x08\0\0\0\x01\0\0\0\x68\0\0\0\x01\0\0\0\0\0\0\0\
            \x20\0\0\0E\0n\0c\0r\0y\0p\0t\0e\0d\0P\0a\0c\0k\0a\0g\0e\0\
            \x32\0\0\0\
            S\0t\0r\0o\0n\0g\0E\0n\0c\0r\0y\0p\0t\0i\0o\0n\0D\0a\0t\0a\0S\0p\0a\0c\0e\0\0\0"
        );
    }

    #[test]
    fn data_space_definition() {
        let mut buffer = b"something".to_vec(); // should be cleared
        assert_eq!(
            super::data_space_definition(&mut buffer),
            b"\x08\0\0\0\x01\0\0\0\
            \x32\0\0\0\
            S\0t\0r\0o\0n\0g\0E\0n\0c\0r\0y\0p\0t\0i\0o\0n\0T\0r\0a\0n\0s\0f\0o\0r\0m\0\0\0"
        )
    }

    #[test]
    fn transform_info() {
        let mut buffer = b"something".to_vec(); // should be cleared
        assert_eq!(
            super::transform_info(&mut buffer),
            b"\x58\0\0\0\x01\0\0\0\
            \x4C\0\0\0\
            {\0F\0F\09\0A\03\0F\00\03\0-\05\06\0E\0F\0-\04\06\01\03\0-\0B\0D\0D\05\0-\0\
            5\0A\04\01\0C\01\0D\00\07\02\04\06\0}\0\
            \x4E\0\0\0\
            M\0i\0c\0r\0o\0s\0o\0f\0t\0.\0C\0o\0n\0t\0a\0i\0n\0e\0r\0.\0\
            E\0n\0c\0r\0y\0p\0t\0i\0o\0n\0T\0r\0a\0n\0s\0f\0o\0r\0m\0\0\0\
            \x01\0\0\0\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0"
        );
    }

    #[test]
    fn sha512() {
        assert_eq!(
            super::sha512([b"test" as &[u8], b"multiple"]),
            super::sha512([b"testmultiple" as &[u8]]),
        );
        assert_eq!(super::sha512([b"testmultiple" as &[u8]]), [
            0x19, 0xA8, 0xCF, 0x28, 0xD9, 0xD1, 0xB6, 0x72, 0x44, 0x19, 0x25, 0xFF, 0x5E, 0xA2,
            0x0A, 0xE0, 0x46, 0xDA, 0x7D, 0x90, 0x34, 0x85, 0x52, 0xC1, 0xBE, 0x9C, 0xD5, 0xE8,
            0x19, 0x7E, 0x3D, 0x6D, 0x36, 0x5B, 0x4E, 0xE7, 0x6D, 0xA9, 0xF1, 0x68, 0x7B, 0xA3,
            0xD7, 0x32, 0x0B, 0xF8, 0x9D, 0x41, 0x1A, 0xD9, 0x89, 0xE4, 0xF1, 0xD3, 0x83, 0x0D,
            0x07, 0xAD, 0x62, 0x1C, 0xD0, 0xF5, 0x81, 0xAA,
        ],);
    }

    #[test]
    fn password() {
        use widestring::u16str;
        fn encode<T: Password + ?Sized>(value: &T) -> impl Iterator<Item = u16> + '_ {
            value.encode_utf16().into_iter()
        }
        assert!(encode("pässword").eq("pässword".chars().map(|c| u16::try_from(c).unwrap())));
        assert!(encode("pässword").eq(encode(&"pässword".to_string())));
        assert!(encode("pässword").eq(encode(utf16str!("pässword"))));
        assert!(encode("pässword").eq(encode(&utf16str!("pässword").to_owned())));
        assert!(encode("pässword").eq(encode(u16str!("pässword"))));
        assert!(encode("pässword").eq(encode(&u16str!("pässword").to_owned())));
    }

    #[test]
    fn encrypt_direct() {
        assert_eq!(
            super::encrypt_direct(
                &mut { *b"datadatadatadatadatadatadatadata" },
                *b"keykeykeykeykeykeykeykeykeykeyke",
                b"iviviviviviviviv",
            ),
            [
                0x28, 0xDD, 0x94, 0xE0, 0xA2, 0x4E, 0x70, 0x90, 0x2D, 0xED, 0x70, 0x60, 0x2F, 0xCE,
                0xE7, 0xBD, 0x45, 0x1B, 0x3E, 0xD5, 0x63, 0x58, 0xAA, 0xDC, 0xD0, 0xF6, 0x6A, 0x59,
                0xF2, 0x28, 0xA5, 0x73,
            ],
        )
    }

    #[test]
    fn encrypt_with_block_key() {
        assert_eq!(
            super::encrypt_with_block_key(
                &mut { *b"datadatadatadatadatadatadatadata" },
                *b"keykeykeykeykeykeykeykeykeykeyke",
                *b"saltsaltsaltsalt",
                b"block key",
            ),
            [
                0x2F, 0x77, 0x60, 0xE9, 0x20, 0x88, 0x5B, 0xF7, 0x37, 0x5C, 0x62, 0x7D, 0xE7, 0x61,
                0xA2, 0xD2, 0x96, 0xE8, 0x66, 0x9E, 0x4E, 0x42, 0x61, 0x65, 0xA6, 0xE1, 0xF3, 0xF7,
                0x2E, 0x9C, 0x3D, 0x9D,
            ],
        )
    }

    // NOTE: Things outside of the integration are difficult to test for
    // `Ecma376AgileWriter`, since it the results do not appear to be repeatable.

    #[test]
    fn test_integration() {
        use calamine::Reader;
        use simple_xlsx_writer::{row, Row, WorkBook};

        let password = "test password";
        let count = 1000;
        let mapping = |index| {
            let mut out = [0; 8];
            out.copy_from_slice(&super::sha512([&u64::to_le_bytes(index) as &[u8]])[..8]);
            format!("[{}]", u64::from_le_bytes(out).to_string()) // avoid the float roundtrip
        };

        let mut cursor = Cursor::new(Vec::new());
        let mut agile =
            Ecma376AgileWriter::create(&mut rand::rng(), password, &mut cursor).unwrap();
        let mut workbook = WorkBook::new(&mut agile).unwrap();
        workbook
            .get_new_sheet()
            .write_sheet(|sheet| {
                sheet.write_row(row!["String", "Index", "Mapping"]).unwrap();
                for i in 0u64..count {
                    sheet.write_row(row!["String", i.to_string(), mapping(i)])?;
                }
                Ok(())
            })
            .unwrap();
        workbook.finish().unwrap();
        agile.encrypt().unwrap();

        let decrypted = office_crypto::decrypt_from_bytes(cursor.into_inner(), password).unwrap();

        let mut workbook: calamine::Xlsx<_> =
            calamine::open_workbook_from_rs(Cursor::new(decrypted)).unwrap();

        let sheet_names = workbook.sheet_names();
        assert_eq!(sheet_names.len(), 1);

        let sheet = workbook.worksheet_range(&sheet_names[0]).unwrap();

        let mut index = 0u64;
        for i in sheet.deserialize().unwrap() {
            let (s, i, m): (String, String, String) = i.unwrap();
            assert_eq!(s, "String");
            assert_eq!(i, index.to_string());
            assert_eq!(m, mapping(index));
            index += 1;
        }
        assert_eq!(index, count);
    }
}
