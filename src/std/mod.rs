//! Items required for running in `std` environments.

#[cfg(all(target_os = "linux", feature = "io-uring"))]
mod io_uring;
#[cfg(unix)]
mod unix;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(all(target_os = "linux", feature = "xdp"))]
mod xdp;

use std::{
    sync::Arc,
    task::Wake,
    thread::{self, Thread},
};

#[cfg(target_os = "windows")]
pub use self::windows::{TxRxTaskConfig, ethercat_now, tx_rx_task_blocking};
#[cfg(unix)]
pub use unix::{ethercat_now, tx_rx_task};
// io_uring is Linux-only
#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub use io_uring::tx_rx_task_io_uring;
#[cfg(all(target_os = "linux", feature = "xdp"))]
pub use xdp::tx_rx_task_xdp;

// Only used by the Windows TX/RX loop.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
struct ParkSignal {
    current_thread: Thread,
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
impl ParkSignal {
    fn new() -> Self {
        Self {
            current_thread: thread::current(),
        }
    }

    fn wait(&self) {
        thread::park();
    }

    // fn wait_timeout(&self, timeout: Duration) {
    //     thread::park_timeout(timeout)
    // }
}

impl Wake for ParkSignal {
    fn wake(self: Arc<Self>) {
        self.current_thread.unpark();
    }
}
