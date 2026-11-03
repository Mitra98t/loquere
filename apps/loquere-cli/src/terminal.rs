use std::io::{self, Write};
use zeroize::Zeroizing;

#[cfg(unix)]
pub(super) fn read_hidden(prompt: &str) -> io::Result<Zeroizing<String>> {
    use std::io::BufRead;
    let fd = libc::STDIN_FILENO;
    // SAFETY: `termios` is a plain C struct initialized by `tcgetattr` before use.
    let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
    // SAFETY: fd refers to the process stdin descriptor and original is writable.
    if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut hidden = original;
    hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
    // SAFETY: both pointers are valid termios structs and fd is the stdin tty.
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &hidden) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let _restore = UnixEchoGuard { fd, original };
    print!("{prompt}");
    io::stdout().flush()?;
    let mut passphrase = Zeroizing::new(String::new());
    io::stdin().lock().read_line(&mut passphrase)?;
    println!();
    if passphrase.ends_with('\n') {
        passphrase.pop();
        if passphrase.ends_with('\r') {
            passphrase.pop();
        }
    }
    Ok(passphrase)
}

#[cfg(unix)]
struct UnixEchoGuard {
    fd: libc::c_int,
    original: libc::termios,
}

#[cfg(unix)]
impl Drop for UnixEchoGuard {
    fn drop(&mut self) {
        // SAFETY: original was read from this descriptor before echo was changed.
        let _ = unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original) };
    }
}

#[cfg(windows)]
pub(super) fn read_hidden(prompt: &str) -> io::Result<Zeroizing<String>> {
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, GetConsoleMode, GetStdHandle,
        STD_INPUT_HANDLE, SetConsoleMode,
    };

    // SAFETY: querying the standard input console handle requires no pointer arguments.
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if handle == 0 || handle == -1isize {
        return Err(io::Error::last_os_error());
    }
    let mut original = 0;
    // SAFETY: handle is checked above and original points to writable storage.
    if unsafe { GetConsoleMode(handle, &mut original) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let hidden = (original | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT) & !ENABLE_ECHO_INPUT;
    // SAFETY: handle refers to the input console and hidden is a valid mode bitmask.
    if unsafe { SetConsoleMode(handle, hidden) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _restore = WindowsEchoGuard { handle, original };
    print!("{prompt}");
    io::stdout().flush()?;
    let mut passphrase = Zeroizing::new(String::new());
    io::stdin().read_line(&mut passphrase)?;
    println!();
    while passphrase.ends_with(['\n', '\r']) {
        passphrase.pop();
    }
    Ok(passphrase)
}

#[cfg(windows)]
struct WindowsEchoGuard {
    handle: windows_sys::Win32::Foundation::HANDLE,
    original: u32,
}

#[cfg(windows)]
impl Drop for WindowsEchoGuard {
    fn drop(&mut self) {
        // SAFETY: the saved mode belongs to the still-open process standard console handle.
        let _ = unsafe {
            windows_sys::Win32::System::Console::SetConsoleMode(self.handle, self.original)
        };
    }
}

#[cfg(not(any(unix, windows)))]
pub(super) fn read_hidden(_prompt: &str) -> io::Result<Zeroizing<String>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "input passphrase nascosto non supportato su questa piattaforma",
    ))
}
