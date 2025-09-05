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
    io::{self, prelude::*, SeekFrom},
    mem, ops,
};

use aes::Aes256;
use cfb::{CompoundFile, Stream};
use cipher::{
    block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, KeyIvInit,
    KeySizeUser,
};
use hmac::Mac;
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha512};
use widestring::{utf16str, Utf16Str};

#[cfg(test)] mod test;

mod buffer;
use buffer::EncryptingBufferingCursor;

type HmacSha512 = hmac::Hmac<Sha512>;

/// The number of iterations of hashing the password (see 2.3.4.13).
const SPIN_COUNT: u32 = 100_000;

/// The size of the header in the CFB stream of the actual encrypted data (see
/// 2.3.4.4).
const ENCRYPTED_PACKAGE_HEADER_SIZE: u64 = size_of::<u64>() as u64;

/// The basic alignment for all data structures in the CFBs generated according
/// to MS-OFFCRYPTO.
const BASE_ALIGN: usize = 4;

/// The size of the chunk that can be encrypted & decrypted independently of
/// other chunks
const CHUNK_SIZE: usize = 4096;

fn pad_to<const ALIGN: usize>(mut writer: impl Write, len: usize) {
    if !len.is_multiple_of(ALIGN) {
        writer
            .write_all(&[0; ALIGN][..(len.next_multiple_of(ALIGN) - len)])
            .unwrap();
    }
}

/// A hole that the length of a substructure, including that length, should be
/// back-patched into.
///
/// This type panics if dropped.
struct LenBackpatchHole {
    at: usize,
}

#[cfg(debug_assertions)]
impl Drop for LenBackpatchHole {
    fn drop(&mut self) {
        panic!("Length never got patched into the buffer at the appropriate position.")
    }
}

/// A wrapper type around the buffer that includes extra assertions regarding
/// structure size and buffer alignment.
struct BufferAlignAssertScope<'a> {
    #[cfg(debug_assertions)]
    buffer: Option<&'a mut Vec<u8>>,
    #[cfg(not(debug_assertions))]
    buffer: &'a mut Vec<u8>,
    #[cfg(debug_assertions)]
    name: &'static str,
    #[cfg(debug_assertions)]
    initial_len: usize,
    #[cfg(debug_assertions)]
    grow_by: usize,
}

impl<'a> BufferAlignAssertScope<'a> {
    /// Assert alignment of the `buffer` for the `"beginning"` or `"end"` (in
    /// `at`) for a structure with some `name`.
    #[cfg(debug_assertions)]
    fn assert(buffer: &[u8], name: &str, at: &str) {
        assert_eq!(
            buffer.len() % BASE_ALIGN,
            0,
            "The buffer should be aligned to {BASE_ALIGN} bytes at the {at} of {name}"
        );
    }

    /// Assert buffer alignment and structure size at the end of the structure.
    #[cfg(debug_assertions)]
    fn assert_end(&self) {
        assert!(
            self.len() >= self.initial_len,
            "Expected the buffer to have grown from {} at the end of {}, but it now has a size of \
             {}",
            self.initial_len,
            self.name,
            self.len(),
        );
        let actual_growth = self.len() - self.initial_len;
        assert_eq!(
            actual_growth, self.grow_by,
            "Expected the buffer to have grown by {} at the end of {}, but it grew by \
             {actual_growth}",
            self.grow_by, self.name,
        );
        Self::assert(self, self.name, "end");
    }

    /// Create a new `BufferAlignAssertScope` with all debugging information.
    #[cfg(debug_assertions)]
    fn new_inner(name: &'static str, buffer: &'a mut Vec<u8>, grow_by: usize) -> Self {
        Self::assert(buffer, name, "start");
        let initial_len = buffer.len();
        BufferAlignAssertScope {
            buffer: Some(buffer),
            name,
            initial_len,
            grow_by,
        }
    }

    /// Create a new `BufferAlignAssertScope` *without* all debugging
    /// information.
    #[cfg(not(debug_assertions))]
    fn new_inner(_: &'static str, buffer: &'a mut Vec<u8>, _: usize) -> Self {
        BufferAlignAssertScope { buffer }
    }

    /// Create a new `BufferAlignAssertScope` for a structure with a given
    /// length that should be appended to the buffer.
    fn new(name: &'static str, buffer: &'a mut Vec<u8>, length: usize) -> Self {
        buffer.reserve(length);
        Self::new_inner(name, buffer, length)
    }

    /// Create a new `BufferAlignAssertScope` for a structure with a given
    /// length that should replace all data within the buffer.
    fn clear(name: &'static str, buffer: &'a mut Vec<u8>, length: usize) -> Self {
        buffer.clear();
        Self::new(name, buffer, length)
    }

    /// Pad to the base alignment.
    fn pad(&mut self) {
        let len = self.len();
        pad_to::<BASE_ALIGN>(&mut **self, len);
    }

    /// Add a 4 byte length field (`u32`) that should be back-patched later.
    fn length_field(&mut self) -> LenBackpatchHole {
        let at = self.len();
        self.extend(u32::to_le_bytes(0));
        LenBackpatchHole { at }
    }

    /// Back-patch a hole with the 4 byte length (`u32`), including that hole.
    fn back_patch(&mut self, hole: LenBackpatchHole) {
        let len_as_le_bytes = u32::to_le_bytes(self[hole.at..].len().try_into().unwrap());
        self[hole.at..(hole.at + size_of::<u32>())].copy_from_slice(&len_as_le_bytes);
        mem::forget(hole);
    }

    /// Produce the inner bytes as a reference
    #[cfg(debug_assertions)]
    fn into_bytes(mut self) -> &'a [u8] {
        self.assert_end();
        let buffer = self.buffer.take().unwrap();
        mem::forget(self);
        buffer
    }

    /// Produce the inner bytes as a reference
    #[cfg(not(debug_assertions))]
    fn into_bytes(self) -> &'a [u8] {
        self.buffer
    }
}

impl ops::Deref for BufferAlignAssertScope<'_> {
    type Target = Vec<u8>;

    #[cfg(debug_assertions)]
    fn deref(&self) -> &Vec<u8> {
        self.buffer.as_ref().unwrap()
    }

    #[cfg(not(debug_assertions))]
    fn deref(&self) -> &Vec<u8> {
        self.buffer
    }
}

impl ops::DerefMut for BufferAlignAssertScope<'_> {
    #[cfg(debug_assertions)]
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        self.buffer.as_mut().unwrap()
    }

    #[cfg(not(debug_assertions))]
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        self.buffer
    }
}

#[cfg(debug_assertions)]
impl Drop for BufferAlignAssertScope<'_> {
    fn drop(&mut self) {
        self.assert_end();
    }
}

/// Return the length in bytes of a `UNICODE-LP-P4`, as defined in 2.1.2.
const fn unicode_lp_p4_len(data: &Utf16Str) -> usize {
    size_of::<u32>() + (data.len() * 2).next_multiple_of(BASE_ALIGN)
}

/// Append a `UNICODE-LP-P4`, as defined in 2.1.2, to a buffer,
fn write_unicode_lp_p4(buffer: &mut Vec<u8>, data: &Utf16Str) {
    let data_length_in_bytes = data.len() * 2;
    let struct_len = unicode_lp_p4_len(data);
    let mut buffer = BufferAlignAssertScope::new("UNICODE-LP-P4", buffer, struct_len);

    // Data length in bytes:
    buffer.extend(&u32::to_le_bytes(data_length_in_bytes.try_into().unwrap()));

    // Data:
    for i in data.code_units() {
        buffer.extend(&u16::to_le_bytes(i));
    }

    // Padding:
    buffer.pad();
}

/// The length of a `Version`, as defined in 2.1.4.
const VERSION_LEN: usize = size_of::<u16>() * 2;

/// Append a `Version`, as defined in 2.1.4, to a buffer.
fn write_version(buffer: &mut Vec<u8>, major: u16, minor: u16) {
    let mut buffer = BufferAlignAssertScope::new("Version", buffer, VERSION_LEN);
    buffer.extend(&u16::to_le_bytes(major));
    buffer.extend(&u16::to_le_bytes(minor));
}

/// Write a `DataSpaceVersionInfo`, as defined in 2.1.5, to a buffer, clearing
/// any previous contents and returning a read-only slice to the resulting
/// bytes.
fn data_space_version_info(buffer: &mut Vec<u8>) -> &[u8] {
    let feature_identifier = utf16str!("Microsoft.Container.DataSpaces");
    let struct_len = unicode_lp_p4_len(feature_identifier) + 3 * VERSION_LEN;
    let mut buffer = BufferAlignAssertScope::clear("DataSpaceVersionInfo", buffer, struct_len);

    // FeatureIdentifier:
    write_unicode_lp_p4(&mut buffer, feature_identifier);
    // ReaderVersion:
    write_version(&mut buffer, 1, 0);
    // UpdaterVersion:
    write_version(&mut buffer, 1, 0);
    // WriterVersion:
    write_version(&mut buffer, 1, 0);

    buffer.into_bytes()
}

/// Write a `DataSpaceMap`, as defined in 2.1.6, to a buffer, clearing any
/// previous contents and returning a read-only slice to the resulting bytes.
fn data_space_map(buffer: &mut Vec<u8>) -> &[u8] {
    let component = utf16str!("EncryptedPackage");
    let name = utf16str!("StrongEncryptionDataSpace");
    let struct_len = 5 * size_of::<u32>() + unicode_lp_p4_len(component) + unicode_lp_p4_len(name);
    let mut buffer = BufferAlignAssertScope::clear("DataSpaceMap", buffer, struct_len);

    // HeaderLength:
    buffer.extend(&u32::to_le_bytes(8));
    // EntryCount:
    buffer.extend(&u32::to_le_bytes(1));
    // MapEntries:
    // a single entry of type: DataSpaceMapEntry
    // (MapEntries[0] as DataSpaceMapEntry).Length
    let length_hole = buffer.length_field();
    // MapEntries[0].ReferenceComponentCount
    buffer.extend(&u32::to_le_bytes(1));
    // MapEntries[0].ReferenceComponents[0].ReferenceComponentType
    buffer.extend(&u32::to_le_bytes(0));
    // MapEntries[0].ReferenceComponents[0].ReferenceComponent
    write_unicode_lp_p4(&mut buffer, component);
    // MapEntries[0].DataSpaceName
    write_unicode_lp_p4(&mut buffer, name);

    buffer.back_patch(length_hole);

    buffer.into_bytes()
}

/// Write a `DataSpaceDefinition`, as defined in 2.1.7, to a buffer, clearing
/// any previous contents and returning a read-only slice to the resulting
/// bytes.
fn data_space_definition(buffer: &mut Vec<u8>) -> &[u8] {
    let name = utf16str!("StrongEncryptionTransform");
    let struct_len = 2 * size_of::<u32>() + unicode_lp_p4_len(name);
    let mut buffer = BufferAlignAssertScope::clear("DataSpaceDefinition", buffer, struct_len);

    // HeaderLength
    buffer.extend(&u32::to_le_bytes(8));
    // TransformReferenceCount
    buffer.extend(&u32::to_le_bytes(1));
    // TransformReferences[0]
    write_unicode_lp_p4(&mut buffer, name);

    buffer.into_bytes()
}

/// Write a `TransformInfoHeader`, as defined in 2.1.8, and then an
/// `EncryptionTransformInfo`, as defined in 2.1.9, to a buffer, clearing any
/// previous contents and returning a read-only slice to the resulting bytes.
fn transform_info(buffer: &mut Vec<u8>) -> &[u8] {
    let id = utf16str!("{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}");
    let name = utf16str!("Microsoft.Container.EncryptionTransform");
    let struct_len = 2 * size_of::<u32>()
        + unicode_lp_p4_len(id)
        + unicode_lp_p4_len(name)
        + 3 * VERSION_LEN
        + 4 * size_of::<u32>();
    let mut buffer = BufferAlignAssertScope::clear("TransformInfo", buffer, struct_len);

    // type: TransformInfoHeader
    // TransformLength
    let transform_length_hole = buffer.length_field();
    // TransformType
    buffer.extend(&u32::to_le_bytes(1));
    // TransformID
    write_unicode_lp_p4(&mut buffer, id);
    buffer.back_patch(transform_length_hole);

    // TransformName
    write_unicode_lp_p4(&mut buffer, name);
    // ReaderVersion
    write_version(&mut buffer, 1, 0);
    // UpdaterVersion
    write_version(&mut buffer, 1, 0);
    // WriterVersion
    write_version(&mut buffer, 1, 0);

    // type: EncryptionTransformInfo
    // EncryptionName (null)
    buffer.extend(&u32::to_le_bytes(0));
    // EncryptionBlockSize. What this value should actually be in the standard
    // is at best underspecified, and the actual value is taken from files
    // encrypted by the reference implementation.
    buffer.extend(&u32::to_le_bytes(0));
    // CipherMode
    buffer.extend(&u32::to_le_bytes(0));
    // Reserved
    buffer.extend(&u32::to_le_bytes(4));

    buffer.into_bytes()
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
fn encrypt(data: &mut [u8], key: [u8; 32], iv: [u8; 16]) -> &[u8] {
    assert_eq!(data.len() % 16, 0);

    cbc::Encryptor::<Aes256>::new(&key.into(), &iv.into())
        .encrypt_padded_mut::<NoPadding>(data, data.len())
        .unwrap();

    data
}

/// Inverse of [`encrypt`].
fn decrypt(data: &mut [u8], key: [u8; 32], iv: [u8; 16]) -> &[u8] {
    assert_eq!(data.len() % 16, 0);

    cbc::Decryptor::<Aes256>::new(&key.into(), &iv.into())
        .decrypt_padded_mut::<NoPadding>(data)
        .unwrap();

    data
}

/// Get the IV based on the salt & block key.
fn block_key_to_iv(salt: [u8; 16], block_key: &[u8]) -> [u8; 16] {
    let mut iv = [0; 16];
    iv.copy_from_slice(&sha512([&salt as &[u8], block_key])[..16]);

    iv
}

/// The necessary data for encrypting single chunks.
struct ChunkEncryptionContext {
    key_salt: [u8; 16],
    intermediate_key: [u8; 32],
}

/// A wrapper for a given buffer or file type that implements the ECMA376 Agile
/// encryption as described in [MS-OFFCRYPTO](https://msopenspecs.azureedge.net/files/MS-OFFCRYPTO/[MS-OFFCRYPTO].pdf).
///
/// This type makes sure that no unencrypted data ever hits the underlying
/// writer, at some performance cost & increased memory usage.
///
/// The resulting file is only guaranteed to be valid once this type is either
/// dropped, [`Ecma376AgileWriter::encrypt`], [`Ecma376AgileWriter::into_inner`]
/// or [`Ecma376AgileWriter::flush`] are called.
pub struct Ecma376AgileWriter<F: Read + Write + Seek> {
    cfb: Option<CompoundFile<F>>,
    /// The internal buffering to make sure no unencrypted data ever hits the
    /// underlying reader.
    encrypted_package: EncryptingBufferingCursor<ENCRYPTED_PACKAGE_HEADER_SIZE, Stream<F>>,
    verifier_salt: [u8; 16],
    verifier_h_n: [u8; 64],
    hmac_key: [u8; 64],
    verifier_hash_input: [u8; 16],
    dirty: bool,
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

        // NOTE: The standard requires the length of this to be the salt length,
        // however actual files encrypted by the reference implementation use
        // 64 bytes.
        let mut hmac_key = [0u8; 64];
        rng.fill(&mut hmac_key);

        let mut verifier_hash_input = [0u8; 16];
        rng.fill(&mut verifier_hash_input);

        let encrypted_package = EncryptingBufferingCursor::new(
            write(&mut cfb, "/EncryptedPackage", &u64::to_le_bytes(0))?,
            ChunkEncryptionContext {
                key_salt,
                intermediate_key,
            },
        );

        Ok(Ecma376AgileWriter {
            cfb: Some(cfb),
            encrypted_package,
            verifier_salt,
            verifier_h_n,
            hmac_key,
            verifier_hash_input,
            dirty: true,
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
            key_salt_size = self.encrypted_package.encryption_context().key_salt.len(),
            aes_block_size = Aes256::block_size(),
            aes_key_bits = Aes256::key_size() * 8,
            sha512_size = Sha512::output_size(),
            key_salt_base64 = base64(&self.encrypted_package.encryption_context().key_salt),
            encrypted_hmac_key = base64(encrypt(
                &mut { self.hmac_key },
                self.encrypted_package.encryption_context().intermediate_key,
                block_key_to_iv(self.encrypted_package.encryption_context().key_salt, &[
                    0x5F, 0xB2, 0xAD, 0x01, 0x0C, 0xB9, 0xE1, 0xF6
                ]),
            )),
            encrypted_hmac_value = base64(encrypt(
                &mut { hmac.finalize().into_bytes() },
                self.encrypted_package.encryption_context().intermediate_key,
                block_key_to_iv(self.encrypted_package.encryption_context().key_salt, &[
                    0xA0, 0x67, 0x7F, 0x02, 0xB2, 0x2C, 0x84, 0x33
                ]),
            )),
            spin_count = SPIN_COUNT,
            verifier_salt_size = self.verifier_salt.len(),
            verifier_salt_base64 = base64(&self.verifier_salt),
            verifier_encrypted_hash_input = base64(encrypt(
                &mut { self.verifier_hash_input },
                verifier_key(&[0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79]),
                self.verifier_salt,
            )),
            verifier_encrypted_hash_value = base64(encrypt(
                &mut Sha512::digest(self.verifier_hash_input),
                verifier_key(&[0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E]),
                self.verifier_salt,
            )),
            verifier_encrypted_key_value = base64(encrypt(
                &mut { self.encrypted_package.encryption_context().intermediate_key },
                verifier_key(&[0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6]),
                self.verifier_salt,
            )),
        )
    }

    /// Retrieve the inner reader/writer.
    pub fn into_inner(mut self) -> io::Result<F> {
        self.flush()?;
        let out = self.cfb.take().unwrap();
        mem::forget(self);
        Ok(out.into_inner())
    }

    /// The same as calling [`Ecma376AgileWriter::flush`] & then dropping the
    /// writer.
    pub fn finalize(self) -> io::Result<()> {
        self.into_inner().map(|_| ())
    }

    /// Renamed to [`Ecma376AgileWriter::finalize`].
    #[deprecated]
    pub fn encrypt(self) -> io::Result<()> {
        self.finalize()
    }
}

impl<F: Read + Write + Seek> Read for Ecma376AgileWriter<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.encrypted_package.read(buf)
    }
}

impl<F: Read + Write + Seek> Write for Ecma376AgileWriter<F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.dirty = true;
        self.encrypted_package.write(buf)
    }

    // Write the length for the encrypted package & the encryption info, and
    // flush the encrypted package as well as the cfb file.
    fn flush(&mut self) -> io::Result<()> {
        let mut cfb = self.cfb.take().unwrap();

        if !self.dirty {
            // Flushing in that case is unnecessary.
            // Flush the `cfb` just to be sure that flushes arrive in the underlying writer if that
            // is - for whatever reason - depended upon
            cfb.flush()?;
            return Ok(());
        }

        let len: u64 = self.encrypted_package.size();
        pad_to::<16>(&mut self.encrypted_package, usize::try_from(len).unwrap());

        let mut hmac = HmacSha512::new_from_slice(&self.hmac_key).unwrap();
        // `write_inner` flushes the inner writer first:
        self.encrypted_package.write_inner(|writer| {
            writer.seek(SeekFrom::Start(0))?;

            writer.write_all(&u64::to_le_bytes(len))?;
            hmac.update(&u64::to_le_bytes(len));

            let mut buffer = [0; 1024];
            loop {
                let length_read = writer.read(&mut buffer)?;
                if length_read == 0 {
                    break;
                }

                hmac.update(&buffer[..length_read]);
            }

            writer.flush()?;

            Ok(())
        })?;

        let mut encryption_info_stream = cfb.create_new_stream("/EncryptionInfo")?;
        self.encryption_info(&mut encryption_info_stream, hmac)?;
        encryption_info_stream.flush()?;

        cfb.flush()?;

        // Put the `cfb` back
        self.cfb = Some(cfb);

        self.dirty = false;

        Ok(())
    }
}

impl<F: Read + Write + Seek> Seek for Ecma376AgileWriter<F> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.encrypted_package.seek(pos)
    }
}

impl<F: Read + Write + Seek> Drop for Ecma376AgileWriter<F> {
    fn drop(&mut self) {
        if self.cfb.is_some() {
            self.flush().unwrap();
        }
    }
}
