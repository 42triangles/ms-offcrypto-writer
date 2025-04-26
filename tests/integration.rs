use calamine::Reader;
use ms_offcrypto_writer::Ecma376AgileWriter;
use simple_xlsx_writer::{row, Row, WorkBook};
use sha2::{Digest, Sha512};
use std::io::Cursor;

const PASSWORD: &str = "test password";
const ROW_COUNT: u64 = 1000;

// Column with higher entropy:
fn mapped_int(index: u64) -> String {
    let mut out = [0; 8];
    let digest: [u8; 64] = Sha512::new_with_prefix(&u64::to_le_bytes(index)).finalize().into();
    out.copy_from_slice(&digest[..8]);
    // Avoid the float roundtrip:
    format!("[{}]", u64::from_le_bytes(out).to_string())
}

#[test]
fn integration() {
    let mut cursor = Cursor::new(Vec::new());
    let mut agile = Ecma376AgileWriter::create(&mut rand::rng(), PASSWORD, &mut cursor).unwrap();
    let mut workbook = WorkBook::new(&mut agile).unwrap();
    workbook
        .get_new_sheet()
        .write_sheet(|sheet| {
            // The header
            sheet.write_row(row!["String", "Index", "Mapping"]).unwrap();

            for i in 0u64..ROW_COUNT {
                sheet.write_row(row!["String", i.to_string(), mapped_int(i)])?;
            }
            Ok(())
        })
        .unwrap();
    workbook.finish().unwrap();
    agile.encrypt().unwrap();

    let decrypted = office_crypto::decrypt_from_bytes(cursor.into_inner(), PASSWORD).unwrap();

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
        assert_eq!(m, mapped_int(index));
        index += 1;
    }
    assert_eq!(index, ROW_COUNT);
}
