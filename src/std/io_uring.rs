use crate::{PduRx, PduTx, SendableFrame, error::Error, fmt, std::unix::RawSocketDesc};
use core::task::Waker;
use io_uring::{IoUring, cqueue, opcode, squeue, types::Fd};
use smallvec::SmallVec;
use std::{
    io,
    os::fd::{AsRawFd, RawFd},
    sync::Arc,
    task::Wake,
};

const ENTRIES: u32 = 256;

// The upper two bits of an operation's user data say what kind of operation it is. The rest holds
// the slab key of the operation's buffer, if it has one.
const KIND_MASK: u64 = 0b11 << 62;
const KIND_READ: u64 = 0b00 << 62;
const KIND_WRITE: u64 = 0b01 << 62;
const KIND_CANCEL: u64 = 0b10 << 62;
const KIND_WAKE: u64 = 0b11 << 62;

/// Create a blocking TX/RX loop using `io_uring`.
///
/// This function is only available on `linux` targets as it requires `io_uring` support. Older
/// kernels may not support `io_uring`.
pub fn tx_rx_task_io_uring<'sto>(
    interface: &str,
    pdu_tx: PduTx<'sto>,
    pdu_rx: PduRx<'sto>,
) -> Result<(PduTx<'sto>, PduRx<'sto>), io::Error> {
    let mut socket = RawSocketDesc::new(interface)?;

    let mtu = socket.interface_mtu()?;

    fmt::debug!(
        "Opening {} with MTU {}, blocking, using io_uring",
        interface,
        mtu
    );

    // MTU is payload size. We need to add the layer 2 header which is 18 bytes.
    let mtu = mtu + 18;

    // io_uring waits for the socket to become ready by itself. On a non-blocking socket some
    // kernels complete reads with `EAGAIN` straight away instead, which makes the loop spin.
    set_blocking(socket.as_raw_fd())?;

    run(socket.as_raw_fd(), mtu, pdu_tx, pdu_rx)
}

/// Run the TX/RX loop on an already opened socket that sends and receives whole Ethernet frames.
fn run<'sto>(
    socket: RawFd,
    mtu: usize,
    mut pdu_tx: PduTx<'sto>,
    mut pdu_rx: PduRx<'sto>,
) -> Result<(PduTx<'sto>, PduRx<'sto>), io::Error> {
    let ring = IoUring::new(ENTRIES)?;

    // checks io_uring support for used opcodes
    let mut probe = io_uring::register::Probe::new();
    ring.submitter().register_probe(&mut probe)?;
    if !(probe.is_supported(opcode::Read::CODE)
        && probe.is_supported(opcode::Write::CODE)
        && probe.is_supported(opcode::AsyncCancel::CODE))
    {
        fmt::error!("io_uring does not support read, write and/or async cancel opcodes");
        return Err(io::Error::other(Error::Internal));
    }

    let wake = Arc::new(EventFd::new()?);
    let waker = Waker::from(Arc::clone(&wake));

    let mut driver = Driver {
        ring,
        socket,
        mtu,
        wake,
        wake_buf: Box::new([0; 8]),
        wake_armed: false,
        writes: slab::Slab::with_capacity(ENTRIES as usize),
        reads: slab::Slab::with_capacity(ENTRIES as usize),
        active_reads: 0,
        spare: Vec::new(),
    };

    loop {
        pdu_tx.replace_waker(&waker);

        if pdu_tx.should_exit() {
            fmt::debug!("io_uring TX/RX was asked to exit");

            driver.drain()?;

            return Ok((pdu_tx.release(), pdu_rx.release()));
        }

        while let Some(frame) = pdu_tx.next_sendable_frame() {
            driver.send(frame)?;
        }

        // Responses aren't tied to a particular read, so all we need is one pending read for each
        // frame still waiting for a response. When a response is lost, its frame stops waiting
        // once its future times out, and the read we queued for it is cancelled here.
        driver.balance_reads(pdu_tx.frames_awaiting_response())?;

        driver.arm_wake()?;

        // Block until something completes: a frame was sent or received, a read was cancelled, or
        // the waker fired because there are new frames to send or we've been asked to exit.
        driver.submit_and_wait(1)?;

        driver.reap(Some(&mut pdu_rx));
    }
}

/// A pending read from the socket.
struct Read {
    buf: Box<[u8]>,
    /// The read has been asked to cancel, so it doesn't count towards the reads we want pending.
    cancelling: bool,
}

struct Driver {
    ring: IoUring,
    socket: RawFd,
    mtu: usize,

    /// Written to by the PDU loop's waker. A read of it is always pending while we wait so the
    /// waker can interrupt the wait.
    wake: Arc<EventFd>,
    wake_buf: Box<[u8; 8]>,
    wake_armed: bool,

    // The kernel holds pointers into these buffers until their operation completes, so they are
    // boxed to keep their addresses stable when the slabs grow.
    writes: slab::Slab<Box<[u8]>>,
    reads: slab::Slab<Read>,
    /// The number of reads in `reads` that are not being cancelled.
    active_reads: usize,
    /// Buffers kept for reuse.
    spare: Vec<Box<[u8]>>,
}

impl Driver {
    fn take_buf(&mut self) -> Box<[u8]> {
        self.spare
            .pop()
            .unwrap_or_else(|| vec![0; self.mtu].into_boxed_slice())
    }

    fn push(&mut self, entry: &squeue::Entry) -> io::Result<()> {
        // SAFETY: Every entry points into a buffer owned by `self` that isn't freed until the
        // entry's completion has been reaped (or is leaked if that can't be guaranteed).
        while unsafe { self.ring.submission().push(entry) }.is_err() {
            // If the submission queue is full, flush it to the kernel
            self.submit_and_wait(0)?;
        }

        Ok(())
    }

    fn submit_and_wait(&mut self, want: usize) -> io::Result<()> {
        match self.ring.submit_and_wait(want) {
            Ok(_) => Ok(()),
            // Interrupted by a signal, or the completion queue overflowed. Either way, the caller
            // reaps what has completed and tries again.
            Err(e) if matches!(e.raw_os_error(), Some(libc::EINTR | libc::EBUSY)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn send(&mut self, frame: SendableFrame<'_>) -> io::Result<()> {
        let idx = frame.storage_slot_index();

        let mut buf = self.take_buf();

        // TODO: Zero copy
        let len = frame.send_blocking(|data| {
            buf.get_mut(0..data.len())
                .ok_or(Error::Internal)?
                .copy_from_slice(data);

            Ok(data.len())
        });

        let len = match len {
            Ok(len) => len,
            Err(e) => {
                fmt::error!("Frame {:#04x} does not fit in the interface MTU", idx);

                self.spare.push(buf);

                return Err(io::Error::other(e));
            }
        };

        let ptr = buf.as_ptr();
        let key = self.writes.insert(buf);

        fmt::trace!("Send frame {:#04x}, write key {}", idx, key);

        let entry = opcode::Write::new(Fd(self.socket), ptr, len as u32)
            .build()
            .user_data(key as u64 | KIND_WRITE);

        self.push(&entry)
    }

    fn balance_reads(&mut self, wanted: usize) -> io::Result<()> {
        while self.active_reads < wanted {
            let mut buf = self.take_buf();
            let (ptr, len) = (buf.as_mut_ptr(), buf.len());

            let key = self.reads.insert(Read {
                buf,
                cancelling: false,
            });
            self.active_reads += 1;

            fmt::trace!("Queue read key {}", key);

            let entry = opcode::Read::new(Fd(self.socket), ptr, len as u32)
                .build()
                .user_data(key as u64 | KIND_READ);

            self.push(&entry)?;
        }

        if self.active_reads > wanted {
            let surplus: SmallVec<[usize; 16]> = self
                .reads
                .iter()
                .filter(|(_key, read)| !read.cancelling)
                .map(|(key, _read)| key)
                .take(self.active_reads - wanted)
                .collect();

            for key in surplus {
                fmt::trace!("Cancel surplus read key {}", key);

                self.cancel_read(key)?;
            }
        }

        Ok(())
    }

    fn cancel_read(&mut self, key: usize) -> io::Result<()> {
        self.reads[key].cancelling = true;
        self.active_reads -= 1;

        // If the read completes before the cancel runs and a new read reuses its key, the new read
        // is cancelled instead. That's harmless: `balance_reads` queues another one.
        let entry = opcode::AsyncCancel::new(key as u64 | KIND_READ)
            .build()
            .user_data(KIND_CANCEL);

        self.push(&entry)
    }

    fn arm_wake(&mut self) -> io::Result<()> {
        if self.wake_armed {
            return Ok(());
        }

        let entry = opcode::Read::new(
            Fd(self.wake.0),
            self.wake_buf.as_mut_ptr(),
            self.wake_buf.len() as u32,
        )
        .build()
        .user_data(KIND_WAKE);

        self.push(&entry)?;

        self.wake_armed = true;

        Ok(())
    }

    /// Handle all available completions. Received frames are passed to `pdu_rx` if given, or
    /// dropped otherwise.
    fn reap(&mut self, mut pdu_rx: Option<&mut PduRx<'_>>) {
        loop {
            // The queue is synced back to the kernel when the temporary is dropped at the end of
            // this statement.
            let Some(entry) = self.ring.completion().next() else {
                break;
            };

            self.complete(entry, pdu_rx.as_deref_mut());
        }
    }

    fn complete(&mut self, entry: cqueue::Entry, pdu_rx: Option<&mut PduRx<'_>>) {
        let user_data = entry.user_data();
        let key = (user_data & !KIND_MASK) as usize;
        let result = entry.result();

        match user_data & KIND_MASK {
            KIND_WRITE => {
                if let Some(buf) = self.writes.try_remove(key) {
                    self.spare.push(buf);
                }

                // The frame's future times out (and maybe retries) like any other lost frame.
                if result < 0 {
                    fmt::warn!(
                        "Failed to send frame: {}",
                        io::Error::from_raw_os_error(-result)
                    );
                }
            }
            KIND_READ => {
                let Some(read) = self.reads.try_remove(key) else {
                    fmt::error!("Completion for unknown read key {}", key);

                    return;
                };

                if !read.cancelling {
                    self.active_reads -= 1;
                }

                if result > 0 {
                    if let (Some(pdu_rx), Some(frame)) = (pdu_rx, read.buf.get(..result as usize)) {
                        Self::receive(pdu_rx, frame);
                    }
                } else if result < 0
                    && !matches!(-result, libc::ECANCELED | libc::EAGAIN | libc::EINTR)
                {
                    fmt::warn!(
                        "Failed to receive frame: {}",
                        io::Error::from_raw_os_error(-result)
                    );
                }

                self.spare.push(read.buf);
            }
            KIND_WAKE => {
                self.wake_armed = false;
            }
            // Cancellation results don't matter. If the read had already completed, its own
            // completion has been or will be handled above.
            _ => (),
        }
    }

    fn receive(pdu_rx: &mut PduRx<'_>, frame: &[u8]) {
        fmt::trace!(
            "Received frame with first PDU {:?}, {} bytes",
            frame.get(0x11),
            frame.len()
        );

        // Responses that arrive after their frame timed out or was resent, duplicates and garbage
        // all end up here. None of them affect other frames, so drop them and carry on.
        if let Err(e) = pdu_rx.receive_frame(frame) {
            fmt::warn!("Ignoring received frame: {}", e);
        }
    }

    /// Cancel all pending operations and wait for them to complete so their buffers can be freed.
    fn drain(&mut self) -> io::Result<()> {
        let keys: SmallVec<[usize; 16]> = self
            .reads
            .iter()
            .filter(|(_key, read)| !read.cancelling)
            .map(|(key, _read)| key)
            .collect();

        for key in keys {
            self.cancel_read(key)?;
        }

        // Complete the pending eventfd read, if any.
        self.wake.notify();

        while self.wake_armed || !self.reads.is_empty() || !self.writes.is_empty() {
            self.submit_and_wait(1)?;

            self.reap(None);
        }

        Ok(())
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        if self.drain().is_err() {
            fmt::error!("Failed to cancel pending io_uring operations. Leaking their buffers.");

            // The kernel may still write into these, so they must never be freed.
            core::mem::forget(core::mem::take(&mut self.writes));
            core::mem::forget(core::mem::take(&mut self.reads));
            core::mem::forget(core::mem::replace(&mut self.wake_buf, Box::new([0; 8])));
        }
    }
}

/// An eventfd used as the PDU loop waker.
///
/// It's kept alive by the waker, so a stored waker can still be called safely after the TX/RX loop
/// has exited.
struct EventFd(RawFd);

impl EventFd {
    fn new() -> io::Result<Self> {
        // Blocking so io_uring waits for it to be written instead of completing reads straight
        // away with `EAGAIN`.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };

        if fd == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self(fd))
    }

    fn notify(&self) {
        let one = 1u64.to_ne_bytes();

        // Can only fail if the counter would overflow, in which case a wakeup is already pending.
        let _ = unsafe { libc::write(self.0, one.as_ptr().cast(), one.len()) };
    }
}

impl Wake for EventFd {
    fn wake(self: Arc<Self>) {
        self.notify();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.notify();
    }
}

impl Drop for EventFd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

fn set_blocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };

    if flags == -1 {
        return Err(io::Error::last_os_error());
    }

    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Command, PduStorage, Timeouts,
        ethernet::{EthernetAddress, EthernetFrame},
    };
    use std::{os::unix::net::UnixDatagram, thread, time::Duration};

    const PDU_TIMEOUT: Duration = Duration::from_millis(50);

    /// Reply to frames like a SubDevice would, except frame 1 is lost, frame 3 is answered after
    /// its PDU timeout and frame 5 is answered twice.
    fn subdevice(socket: UnixDatagram) {
        let mut buf = [0u8; 1518];

        for n in 0.. {
            let Ok(len) = socket.recv(&mut buf) else {
                return;
            };

            let mut frame = EthernetFrame::new_checked(buf[..len].to_vec()).unwrap();
            frame.set_src_addr(EthernetAddress([0x12, 0x10, 0x10, 0x10, 0x10, 0x10]));
            let reply = frame.into_inner();

            match n {
                1 => (),
                3 => {
                    let socket = socket.try_clone().unwrap();

                    thread::spawn(move || {
                        thread::sleep(PDU_TIMEOUT * 2);

                        let _ = socket.send(&reply);
                    });
                }
                5 => {
                    let _ = socket.send(&reply);
                    let _ = socket.send(&reply);
                }
                _ => {
                    let _ = socket.send(&reply);
                }
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn recovers_from_lost_late_and_duplicate_frames() {
        crate::test_logger();

        if let Err(e) = IoUring::new(8) {
            eprintln!("Skipping test, io_uring is not available: {e}");

            return;
        }

        static STORAGE: PduStorage<4, { PduStorage::element_size(64) }> = PduStorage::new();
        let (tx, rx, mut pdu_loop) = STORAGE.try_split().unwrap();

        let (ours, theirs) = UnixDatagram::pair().unwrap();

        thread::spawn(move || subdevice(theirs));

        let tx_rx = thread::spawn(move || run(ours.as_raw_fd(), 1518, tx, rx).map(|_| ()));

        let timeout = Timeouts {
            pdu: PDU_TIMEOUT,
            ..Timeouts::default()
        }
        .pdu();

        let results = (0..12)
            .map(|_| {
                async_io::block_on(pdu_loop.pdu_broadcast_zeros(0x1000, 16, timeout, 0)).is_ok()
            })
            .collect::<Vec<_>>();

        let expected = (0..12).map(|n| n != 1 && n != 3).collect::<Vec<_>>();

        assert_eq!(results, expected);

        pdu_loop.reset_all();

        tx_rx
            .join()
            .expect("TX/RX thread panicked")
            .expect("TX/RX loop failed");
    }

    /// Wait for `BATCH` frames, then reply to them in reverse order.
    fn subdevice_reversed<const BATCH: usize>(socket: UnixDatagram) {
        let mut buf = [0u8; 1518];
        let mut batch = Vec::with_capacity(BATCH);

        loop {
            let Ok(len) = socket.recv(&mut buf) else {
                return;
            };

            let mut frame = EthernetFrame::new_checked(buf[..len].to_vec()).unwrap();
            frame.set_src_addr(EthernetAddress([0x12, 0x10, 0x10, 0x10, 0x10, 0x10]));
            batch.push(frame.into_inner());

            if batch.len() == BATCH {
                for reply in batch.drain(..).rev() {
                    let _ = socket.send(&reply);
                }
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn out_of_order_responses() {
        crate::test_logger();

        if let Err(e) = IoUring::new(8) {
            eprintln!("Skipping test, io_uring is not available: {e}");

            return;
        }

        const BATCH: usize = 3;

        static STORAGE: PduStorage<4, { PduStorage::element_size(64) }> = PduStorage::new();
        let (tx, rx, mut pdu_loop) = STORAGE.try_split().unwrap();

        let (ours, theirs) = UnixDatagram::pair().unwrap();

        thread::spawn(move || subdevice_reversed::<BATCH>(theirs));

        let tx_rx = thread::spawn(move || run(ours.as_raw_fd(), 1518, tx, rx).map(|_| ()));

        let timeout = Timeouts {
            pdu: Duration::from_secs(1),
            ..Timeouts::default()
        }
        .pdu();

        // Send a frame with a unique payload, returning the payload of the response it receives.
        let send = |payload: [u8; 4]| {
            let pdu_loop = &pdu_loop;

            async move {
                let mut frame = pdu_loop.alloc_frame()?;

                let handle = frame.push_pdu(Command::fpwr(0x1000, 0x1234).into(), payload, None)?;

                let frame = frame.mark_sendable(pdu_loop, timeout, 0);

                pdu_loop.wake_sender();

                let response = frame.await?.first_pdu(handle)?;

                Ok::<_, Error>(response.to_vec())
            }
        };

        for round in 0..4u8 {
            let payloads = [[round, 0, 0, 0], [round, 1, 1, 1], [round, 2, 2, 2]];

            let (a, (b, c)) = async_io::block_on(futures_lite::future::zip(
                send(payloads[0]),
                futures_lite::future::zip(send(payloads[1]), send(payloads[2])),
            ));

            assert_eq!(
                [a.unwrap(), b.unwrap(), c.unwrap()],
                payloads.map(|p| p.to_vec()),
                "round {round}"
            );
        }

        pdu_loop.reset_all();

        tx_rx
            .join()
            .expect("TX/RX thread panicked")
            .expect("TX/RX loop failed");
    }
}
