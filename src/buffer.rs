use std::{
    io::{self, prelude::*, SeekFrom},
    mem,
};

use crate::{block_key_to_iv, decrypt, encrypt, ChunkEncryptionContext, CHUNK_SIZE};

const CHUNK_SIZE_U64: u64 = CHUNK_SIZE as u64;

/// A pair of position & size (both as `u64`s).
struct PositionSize {
    position: u64,
    size: u64,
}

impl PositionSize {
    fn bump_to_position(&mut self, position: u64) {
        self.position = position;
        self.size = u64::max(self.size, position);
    }
}

/// A buffer for exactly one chunk[^chunk] of unencrypted data before it is
/// written to the underlying writer.
///
/// As long as this type is used with its defined methods, it is guaranteed that
/// no unencrypted data ever hits the underlying writer.
///
/// NOTE: It's important that this type manages the `size` & `position` field in
/// [`PositionSize`], to make sure that it stays in sync with the underlying
/// writer.
///
/// [^chunk]: One chunk of encrypted data is 4KiB, the size that MS-OFFCRYPTO
///           encrypts based on the block key independently of other chunks.
struct UnencryptedBufferedChunk {
    /// The start position of the unencrypted chunk, or `None` if the buffer is
    /// not "active" (the `buffer` field does not contain unencrypted data).
    start: Option<u64>,
    /// The actual data of this chunk, lazily allocated.
    buffer: Option<Box<[u8; CHUNK_SIZE]>>,
}

impl UnencryptedBufferedChunk {
    /// Create a new unencrypted buffer pointing to the given start position (or
    /// staying inactive if `None` is passed).
    fn new(start: Option<u64>) -> Self {
        UnencryptedBufferedChunk {
            start,
            buffer: None,
        }
    }

    /// Returns whether or not the given position is part of the chunk starting
    /// at `start`.
    fn start_is_in_range(start: u64, pos_size: &PositionSize) -> bool {
        (start..(start + CHUNK_SIZE_U64)).contains(&pos_size.position)
    }

    /// Returns whether or not the given position is part of this buffer.
    fn is_in_range(&self, pos_size: &PositionSize) -> bool {
        self.start
            .is_some_and(|start| Self::start_is_in_range(start, pos_size))
    }

    /// Return a reference to the buffer (allocating it if it wasn't allocated
    /// already).
    fn buffer(&mut self) -> &mut [u8] {
        &mut **self
            .buffer
            .get_or_insert_with(|| Box::new([0u8; CHUNK_SIZE]))
    }

    /// Returns the length of the chunk starting at `start` for reading.
    fn encrypted_chunk_len(start: u64, pos_size: &PositionSize) -> usize {
        assert!(pos_size.size >= start);

        let chunk_len = u64::min(pos_size.size - start, CHUNK_SIZE_U64);
        usize::try_from(chunk_len.next_multiple_of(16)).unwrap()
    }

    /// Returns the offset into the chunk for `pos_size`.
    fn offset_to_chunk_for(pos_size: &PositionSize) -> usize {
        usize::try_from(pos_size.position % CHUNK_SIZE_U64).unwrap()
    }

    fn readable_range(&mut self, start: u64, pos_size: &PositionSize) -> &[u8] {
        assert!(Self::start_is_in_range(start, pos_size));

        let offset = Self::offset_to_chunk_for(pos_size);
        let chunk_len = Self::encrypted_chunk_len(start, pos_size);
        assert!(offset <= chunk_len);

        &mut self.buffer()[offset..chunk_len]
    }

    fn writable_range(&mut self, pos_size: &PositionSize) -> &mut [u8] {
        assert!(self.is_in_range(pos_size));

        &mut self.buffer()[Self::offset_to_chunk_for(pos_size)..]
    }

    fn read(&mut self, pos_size: &mut PositionSize, data: &mut [u8]) -> io::Result<usize> {
        if !self.is_in_range(pos_size) {
            return Ok(0);
        }

        let read = self
            .readable_range(self.start.unwrap(), pos_size)
            .read(data)?;
        pos_size.bump_to_position(pos_size.position + u64::try_from(read).unwrap());
        Ok(read)
    }

    /// Write as much as is possible out of `data` into this chunk.
    fn write(&mut self, pos_size: &mut PositionSize, data: &[u8]) -> io::Result<usize> {
        if !self.is_in_range(pos_size) {
            return Ok(0);
        }

        let written = self.writable_range(pos_size).write(data)?;
        pos_size.bump_to_position(pos_size.position + u64::try_from(written).unwrap());
        Ok(written)
    }

    fn encryption_iv(ctx: &ChunkEncryptionContext, start: u64) -> [u8; 16] {
        let idx = u32::try_from((start / CHUNK_SIZE_U64) % u64::from(u32::MAX)).unwrap();
        let block_key = u32::to_le_bytes(idx);

        block_key_to_iv(ctx.key_salt, &block_key)
    }

    /// The inner flushing routine, which can optionally decrypt the block again
    /// after.
    fn priv_flush_inner(
        &mut self,
        pos_size: &PositionSize,
        ctx: &ChunkEncryptionContext,
        writer: &mut (impl Write + Seek),
        seek_offset: u64,
        redecrypt: bool,
    ) -> io::Result<()> {
        let Some(start) = self.start.take() else {
            return Ok(());
        };

        let partial_chunk = &mut self.buffer()[..Self::encrypted_chunk_len(start, pos_size)];
        let iv = Self::encryption_iv(ctx, start);
        encrypt(partial_chunk, ctx.intermediate_key, iv);

        writer.seek(SeekFrom::Start(start + seek_offset))?;
        writer.write_all(partial_chunk)?;

        if redecrypt {
            decrypt(partial_chunk, ctx.intermediate_key, iv);
        }

        self.start = None;
        Ok(())
    }

    /// Encrypt & flush this chunk to the underlying writer & mark it as
    /// inactive.
    fn flush_and_destroy(
        &mut self,
        pos_size: &PositionSize,
        ctx: &ChunkEncryptionContext,
        writer: &mut (impl Write + Seek),
        seek_offset: u64,
    ) -> io::Result<()> {
        self.priv_flush_inner(pos_size, ctx, writer, seek_offset, false)
    }

    /// Encrypt & flush this chunk to the underlying writer without marking it
    /// as inactive.
    fn flush(
        &mut self,
        pos_size: &PositionSize,
        ctx: &ChunkEncryptionContext,
        writer: &mut (impl Write + Seek),
        seek_offset: u64,
    ) -> io::Result<()> {
        self.priv_flush_inner(pos_size, ctx, writer, seek_offset, true)
    }

    /// If the given position isn't in range of this chunk, flush this chunk to
    /// the writer, and move the start position to be in range for the new
    /// position.
    ///
    /// If that position is within the range of the amount of known chunks
    /// implied by `pos_size.size`, read the chunk from the underlying writer &
    /// decrypt it.
    fn seek(
        &mut self,
        pos_size: &mut PositionSize,
        ctx: &ChunkEncryptionContext,
        writer: &mut (impl Read + Write + Seek),
        seek_offset: u64,
    ) -> io::Result<()> {
        if self.is_in_range(pos_size) {
            return Ok(());
        }

        self.flush_and_destroy(pos_size, ctx, writer, seek_offset)?;

        let start = if pos_size.position.is_multiple_of(CHUNK_SIZE_U64) {
            pos_size.position
        } else {
            pos_size.position.next_multiple_of(CHUNK_SIZE_U64) - CHUNK_SIZE_U64
        };

        let buffer = self.buffer();
        buffer.fill(0);
        if start < pos_size.size.next_multiple_of(CHUNK_SIZE_U64) {
            // It's a preexisting buffer that needs reading & decrypting from
            // the underlying writer
            let length = Self::encrypted_chunk_len(start, pos_size);
            let partial_chunk = &mut buffer[..length];

            // Read back & decrypt the existing chunk:
            writer.seek(SeekFrom::Start(start + seek_offset))?;
            writer.read_exact(partial_chunk)?;

            decrypt(
                partial_chunk,
                ctx.intermediate_key,
                Self::encryption_iv(ctx, start),
            );
        }

        pos_size.bump_to_position(pos_size.position);

        self.start = Some(start);
        Ok(())
    }
}

/// The buffering scheme implementation.
///
/// I'm not sure which exact behaviour most writers will have, so I'm just using
/// (up to) two buffers to decrease potential problems arising from seeking too
/// much back & forth.
pub(crate) struct EncryptingBufferingCursor<const SEEK_OFFSET: u64, W> {
    writer: W,
    encryption_context: ChunkEncryptionContext,
    pos_size: PositionSize,
    active: UnencryptedBufferedChunk,
    last: UnencryptedBufferedChunk,
}

impl<const SEEK_OFFSET: u64, W: Read + Write + Seek> EncryptingBufferingCursor<SEEK_OFFSET, W> {
    pub(crate) fn new(writer: W, encryption_context: ChunkEncryptionContext) -> Self {
        EncryptingBufferingCursor {
            writer,
            encryption_context,
            pos_size: PositionSize {
                position: 0,
                size: 0,
            },
            active: UnencryptedBufferedChunk::new(Some(0)),
            last: UnencryptedBufferedChunk::new(None),
        }
    }

    fn update_active_position(&mut self) -> io::Result<()> {
        if self.active.is_in_range(&self.pos_size) {
            // already active
            Ok(())
        } else {
            mem::swap(&mut self.last, &mut self.active);

            self.active.seek(
                &mut self.pos_size,
                &self.encryption_context,
                &mut self.writer,
                SEEK_OFFSET,
            )
        }
    }

    pub(crate) fn encryption_context(&self) -> &ChunkEncryptionContext {
        &self.encryption_context
    }

    pub(crate) fn write_inner<R>(
        &mut self,
        f: impl FnOnce(&mut W) -> io::Result<R>,
    ) -> io::Result<R> {
        self.flush()?;

        let out = f(&mut self.writer);
        let seek = self.seek(SeekFrom::Start(self.pos_size.position));
        let out = out?;
        seek?;

        Ok(out)
    }

    pub(crate) fn size(&self) -> u64 {
        self.pos_size.size
    }
}

impl<const SEEK_OFFSET: u64, W> Read for EncryptingBufferingCursor<SEEK_OFFSET, W>
where
    W: Read + Write + Seek,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.update_active_position()?;
        self.active.read(&mut self.pos_size, buf)
    }
}

impl<const SEEK_OFFSET: u64, W> Write for EncryptingBufferingCursor<SEEK_OFFSET, W>
where
    W: Read + Write + Seek,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update_active_position()?;
        self.active.write(&mut self.pos_size, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.last.flush(
            &self.pos_size,
            &self.encryption_context,
            &mut self.writer,
            SEEK_OFFSET,
        )?;
        // Flushing last so the current position in the underlying writer will
        // be close to `active` again. Not sure if it helps, but can't hurt:
        self.active.flush(
            &self.pos_size,
            &self.encryption_context,
            &mut self.writer,
            SEEK_OFFSET,
        )?;

        self.writer.flush()?;

        Ok(())
    }
}

impl<const SEEK_OFFSET: u64, W> Seek for EncryptingBufferingCursor<SEEK_OFFSET, W>
where
    W: Read + Write + Seek,
{
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let relative = |from: u64, delta: i64| {
            if delta >= 0 {
                Ok(from + u64::try_from(delta).unwrap())
            } else {
                from.checked_sub(u64::try_from(-i128::from(delta)).unwrap())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "invalid seek to a negative or overflowing position",
                        )
                    })
            }
        };

        self.pos_size.position = match pos {
            SeekFrom::Start(position) => position,
            SeekFrom::End(delta) => relative(self.pos_size.size, delta)?,
            SeekFrom::Current(delta) => relative(self.pos_size.position, delta)?,
        };

        self.update_active_position()?;

        Ok(self.pos_size.position)
    }
}
