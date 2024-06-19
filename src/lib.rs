//! This crate allows encrypting ECMA376/OOXML (so newer MS-Office files such as
//! XLSX) using the agile encryption method as described in [MS-OFFCRYPTO](https://msopenspecs.azureedge.net/files/MS-OFFCRYPTO/[MS-OFFCRYPTO].pdf).
//!
//! See [`Ecma376AgileWriter`].

use std::{
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

const SPIN_COUNT: u32 = 100_000;
const ENCRYPTED_PACKAGE_HEADER_SIZE: u64 = mem::size_of::<u64>() as u64;

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

#[allow(single_use_lifetimes)]
fn sha512<'a>(x: impl IntoIterator<Item = &'a [u8]>) -> [u8; 64] {
    let mut sha = Sha512::new();
    x.into_iter().for_each(|i| sha.update(i));
    sha.finalize().into()
}

/// A type that can be used as a password. Passwords are encoded as UTF16LE, so
/// types that can directly return those codepoints without reencoding are
/// preferable.
pub trait Password {
    /// Encode the password as UTF16
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

fn encrypt_direct<'a>(data: &'a mut [u8], key: [u8; 32], iv: &[u8]) -> &'a [u8] {
    let mut iv_array = [0; 16];
    iv_array.copy_from_slice(&iv[..16]);

    cbc::Encryptor::<Aes256>::new(&key.into(), &iv_array.into())
        .encrypt_padded_mut::<NoPadding>(data, data.len())
        .unwrap();

    data
}

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
        #[allow(clippy::absolute_paths)]
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

    #[allow(clippy::absolute_paths)]
    fn write_fmt(&mut self, fmt: std::fmt::Arguments<'_>) -> io::Result<()> {
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
