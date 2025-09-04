// NOTE: The tests testing MS-OFFCRYPTO structures are based on what the
// functions actually produce, and only exist to catch regressions.
//
// At the time that these outputs were taken, this crate reliably created
// encrypted XLSX files that could be read both by LibreOffice Calc & Microsoft
// Excel.

use super::*;

#[test]
fn buffer_align_assert_scope_okay() {
    BufferAlignAssertScope::new("test", &mut b"okay".to_vec(), 0);
    let mut buffer = b"okay".to_vec();
    let mut buffer = BufferAlignAssertScope::new("test", &mut buffer, 4);
    buffer.extend(b"more");
}

#[test]
#[should_panic(expected = "aligned to 4 bytes at the start of test")]
fn buffer_align_assert_scope_unaligned_start() {
    BufferAlignAssertScope::new("test", &mut b"odd".to_vec(), 0);
}

#[test]
#[should_panic(expected = "aligned to 4 bytes at the end of test")]
fn buffer_align_assert_scope_unaligned_end() {
    let mut buffer = b"even".to_vec();
    let mut buffer = BufferAlignAssertScope::new("test", &mut buffer, 3);
    buffer.extend(b"odd");
}

#[test]
#[should_panic(expected = "grown by 8 at the end of test, but it grew by 4")]
fn buffer_align_assert_scope_wrong_length() {
    let mut buffer = b"okay".to_vec();
    let mut buffer = BufferAlignAssertScope::new("test", &mut buffer, 8);
    buffer.extend(b"more");
}

#[test]
#[should_panic(expected = "grown from 4 at the end of test, but it now has a size of 0")]
fn buffer_align_assert_scope_shrunk() {
    let mut buffer = b"okay".to_vec();
    let mut buffer = BufferAlignAssertScope::new("test", &mut buffer, 0);
    buffer.clear();
}

#[test]
fn len_backpatch() {
    let mut buffer = b"prefix  ".to_vec();
    let mut buffer = BufferAlignAssertScope::new("test", &mut buffer, 24);
    buffer.extend(b"start   ");
    let len_hole = buffer.length_field();
    buffer.extend(b"end ");
    buffer.back_patch(len_hole);
    buffer.extend(b"suffix  ");
    assert_eq!(*buffer, b"prefix  start   \x08\0\0\0end suffix  ");
}

#[test]
#[should_panic(expected = "never got patched into the buffer")]
fn len_backpatch_dropped() {
    BufferAlignAssertScope::new("test", &mut b"even".to_vec(), 4).length_field();
}

#[test]
fn write_unicode_lp_p4_len() {
    assert_eq!(unicode_lp_p4_len(utf16str!("")), 4);
    assert_eq!(unicode_lp_p4_len(utf16str!("Even")), 4 + 4 * 2);
    assert_eq!(unicode_lp_p4_len(utf16str!("Longer Odd.")), 4 + 12 * 2);
}

#[test]
fn write_unicode_lp_p4_empty() {
    let mut buffer = b"some prefix ".to_vec();
    write_unicode_lp_p4(&mut buffer, utf16str!(""));
    assert_eq!(buffer, b"some prefix \0\0\0\0");
}

#[test]
fn write_unicode_lp_p4_even() {
    let mut buffer = b"some prefix ".to_vec();
    write_unicode_lp_p4(&mut buffer, utf16str!("Even"));
    assert_eq!(buffer, b"some prefix \x08\0\0\0E\0v\0e\0n\0");
}

#[test]
fn write_unicode_lp_p4_odd() {
    let mut buffer = b"some prefix ".to_vec();
    write_unicode_lp_p4(&mut buffer, utf16str!("Longer Odd."));
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
    );
}

#[test]
#[allow(
    clippy::octal_escapes,
    reason = "they aren't octal, it's just a ton of null bytes"
)]
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
        0x19, 0xA8, 0xCF, 0x28, 0xD9, 0xD1, 0xB6, 0x72, 0x44, 0x19, 0x25, 0xFF, 0x5E, 0xA2, 0x0A,
        0xE0, 0x46, 0xDA, 0x7D, 0x90, 0x34, 0x85, 0x52, 0xC1, 0xBE, 0x9C, 0xD5, 0xE8, 0x19, 0x7E,
        0x3D, 0x6D, 0x36, 0x5B, 0x4E, 0xE7, 0x6D, 0xA9, 0xF1, 0x68, 0x7B, 0xA3, 0xD7, 0x32, 0x0B,
        0xF8, 0x9D, 0x41, 0x1A, 0xD9, 0x89, 0xE4, 0xF1, 0xD3, 0x83, 0x0D, 0x07, 0xAD, 0x62, 0x1C,
        0xD0, 0xF5, 0x81, 0xAA,
    ],);
}

#[test]
fn password() {
    use widestring::u16str;
    fn encode<T: Password + ?Sized>(value: &T) -> impl Iterator<Item = u16> + '_ {
        value.encode_utf16().into_iter()
    }
    assert!(encode("pässword").eq("pässword".chars().map(|c| u16::try_from(c).unwrap())));
    assert!(encode("pässword").eq(encode(&"pässword".to_owned())));
    assert!(encode("pässword").eq(encode(utf16str!("pässword"))));
    assert!(encode("pässword").eq(encode(&utf16str!("pässword").to_owned())));
    assert!(encode("pässword").eq(encode(u16str!("pässword"))));
    assert!(encode("pässword").eq(encode(&u16str!("pässword").to_owned())));
}

#[test]
fn encrypt() {
    assert_eq!(
        super::encrypt(
            &mut { *b"datadatadatadatadatadatadatadata" },
            *b"keykeykeykeykeykeykeykeykeykeyke",
            *b"iviviviviviviviv",
        ),
        [
            0x28, 0xDD, 0x94, 0xE0, 0xA2, 0x4E, 0x70, 0x90, 0x2D, 0xED, 0x70, 0x60, 0x2F, 0xCE,
            0xE7, 0xBD, 0x45, 0x1B, 0x3E, 0xD5, 0x63, 0x58, 0xAA, 0xDC, 0xD0, 0xF6, 0x6A, 0x59,
            0xF2, 0x28, 0xA5, 0x73,
        ],
    );
}

#[test]
fn encrypt_with_block_key() {
    assert_eq!(
        super::encrypt(
            &mut { *b"datadatadatadatadatadatadatadata" },
            *b"keykeykeykeykeykeykeykeykeykeyke",
            block_key_to_iv(*b"saltsaltsaltsalt", b"block key"),
        ),
        [
            0x2F, 0x77, 0x60, 0xE9, 0x20, 0x88, 0x5B, 0xF7, 0x37, 0x5C, 0x62, 0x7D, 0xE7, 0x61,
            0xA2, 0xD2, 0x96, 0xE8, 0x66, 0x9E, 0x4E, 0x42, 0x61, 0x65, 0xA6, 0xE1, 0xF3, 0xF7,
            0x2E, 0x9C, 0x3D, 0x9D,
        ],
    );
}

#[test]
fn encrypt_decrypt_roundtrips() {
    for len in [0, 16, 32, 128, 256] {
        let data = [0x42; 256];
        let mut modified = data;

        let data = &data[..len];
        let modified = &mut modified[..len];

        let key = *b"keykeykeykeykeykeykeykeykeykeyke";
        let iv = block_key_to_iv(*b"saltsaltsaltsalt", b"block key");

        super::encrypt(modified, key, iv);
        decrypt(modified, key, iv);

        assert_eq!(modified, data);
    }
}

#[test]
fn big_sheet() {
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    let backing = io::Cursor::new(Vec::new());

    let mut writer = Ecma376AgileWriter::create(
        &mut ChaCha12Rng::from_seed(Default::default()),
        "12345",
        backing,
    )
    .unwrap();

    // Write three chunks
    for _ in 0..3u8 {
        static ZERO_CHUNK: [u8; CHUNK_SIZE] = [0u8; _];

        writer.write_all(&ZERO_CHUNK).unwrap();
    }

    // Go back to first chunk
    writer.seek(SeekFrom::Start(0)).unwrap();
    let mut buffer = [0; 256];
    writer.read_exact(&mut buffer).unwrap();
    assert_eq!(buffer, [0; 256]);
}

// NOTE: Things outside of the integration are difficult to test for
// `Ecma376AgileWriter`, since the results of the `cfb` crate do not appear
// to be deterministic.
