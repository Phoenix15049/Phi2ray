//! Reads links from the clipboard, so they never have to be typed into the command line, where
//! the shell keeps them in its history file (PowerShell does, in plain text).

#[cfg(windows)]
pub fn text() -> Result<String, String> {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard};
    use windows_sys::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};

    /// CF_UNICODETEXT: text as UTF-16.
    const UNICODE_TEXT: u32 = 13;

    // Another program may hold the clipboard for a moment.
    let mut opened = false;
    for _ in 0..10 {
        if unsafe { OpenClipboard(std::ptr::null_mut()) } != 0 {
            opened = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if !opened {
        return Err("cannot open the clipboard".into());
    }
    let result = (|| {
        let data: HANDLE = unsafe { GetClipboardData(UNICODE_TEXT) };
        if data.is_null() {
            return Err("the clipboard has no text. Copy the links first.".to_string());
        }
        let ptr = unsafe { GlobalLock(data) } as *const u16;
        if ptr.is_null() {
            return Err("cannot read the clipboard".to_string());
        }
        // Never past the end of the block, even if the text isn't terminated.
        let max = unsafe { GlobalSize(data) } / 2;
        let len = (0..max).take_while(|&i| unsafe { *ptr.add(i) } != 0).count();
        let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) });
        unsafe { GlobalUnlock(data) };
        Ok(text)
    })();
    unsafe { CloseClipboard() };
    result
}

#[cfg(not(windows))]
pub fn text() -> Result<String, String> {
    Err("reading the clipboard is only supported on Windows for now; pipe the links in with `phi2ray add -`".into())
}
