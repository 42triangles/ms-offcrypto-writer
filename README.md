# `ms-offcrypto-writer`
This crate allows encrypting ECMA376/OOXML (so newer MS-Office files such as XLSX) using the agile encryption method as described in [MS-OFFCRYPTO](https://msopenspecs.azureedge.net/files/MS-OFFCRYPTO/[MS-OFFCRYPTO].pdf).

## How to use
Use the `Ecma376AgileWriter` wrapper around a `File` or `Cursor` (or whatever writer you're using) for other crates such as [`simple-xlsx-writer`](https://crates.io/crates/simple-xlsx-writer).

## If you find security flaws
If you find any security flaws beyond the lack of zeroing out data structures, please send me an email at 42triangles@tutanota.com. I will *try* to answer within two days.

## Compatibility notes
The created files are NOT byte-equivalent to the ones created by the used reference implementation of "Microsoft Excel für Microsoft 365 MSO (16.0.13001.20508) 64-Bit", but the streams embedded in the CFB files are, and the CFB metadata beyond access dates (specifically the CFB version, and per storage & stream the state bits & CLSID) are equivalent as well.

This does also include one deviation from the standard, which specifies that the HMAC key should have a length equal to the salt length in `<keyData>`. However, the reference implementation uses an HMAC key length of 64.

The used values are:
* A salt size of 16 for both `<keyData>` and `<p:encryptedKey>`
* for encryption in both `<keyData>` and `<p:encryptedKey>`: AES256 with CBC, and its derived values
* for hashing in both `<keyData>` and `<p:encryptedKey>`: SHA512, and its derived values
* *An HMAC key length of 64, contrary to the standard, but following the reference implementation*
* A spin count of `100_000`

## Contributing
PRs are open; this is specifically aims to be a very simple and easy to audit implementation.
A more complete implementation that includes reading as well, plus a lot more features & configurability, is in the works though - if you're interested in working on that instead, please send me an email at 42triangles@tutanota.com!

### The `src/encryption_info.xml` file
If you need to edit this, you may want to do it in a binary editor.
It includes both binary data in the beginning, uses CRLF and should NOT include a trailing newline.

## Roadmap
* A more complete implementation (though that will be a second crate, this crate will continue to receive updates)
* Make the XML templating saner. Mostly such that the file is fully UTF8 & trailing newlines (such as the ones added by vim) aren't an issue.
* Add examples & tests
* *Maybe* byte equivalent files including the CFB container file (though that will require a reimplementation for CFBs).
* *Maybe* on-the-fly encryption that never actually commits unencrypted data to the underlying writer. While I'm very interested in this, there's some design decisions to hash out & benchmarks to be done.
* *Maybe* optimising it for speed. It should be plenty fast, and either the `cfb` crate or the `write!` usage directly into the stream is a likely culprit if things aren't, but nothing has been verified or even tested regarding performance.
* *Maybe* implement zeroing of data structures.

The following things are NOT the goal of this crate, and will only be found in the more complete crate:
* Any Information Rights Management features
* Encryption other than agile
* Configurable agile encryption
* Certificates
* Supporting the old office binary file format (XLS for example, as opposed to XLSX)
* Reading encrypted files
* Write protection
* Signatures
* Things in MS-OFFCRYPTO that I don't know what they do yet: Sensitivity labels, MsoDataStore, EncryptedSIHash, EncryptedDSIHash, EncryptedPropertyStreamInfo
