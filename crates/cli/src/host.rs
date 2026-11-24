//! The names of the host the tool runs on, as its system tells them: the
//! short one a digest says it was sent from, and the full one a run is known
//! by among the hosts of a configuration several of them share (`runners`).

use std::ffi::{CStr, CString};
use std::ptr;

/// The name of this host; `an unknown host` when the system does not tell it.
pub fn hostname() -> String {
    let mut name = [0u8; 256];
    // SAFETY: the buffer is writable for its whole length, which is the length given.
    #[expect(unsafe_code, reason = "the name of the host is only known to libc")]
    let status = unsafe { libc::gethostname(name.as_mut_ptr().cast(), name.len()) };
    let end = name.iter().position(|byte| *byte == 0).unwrap_or(name.len());
    if status != 0 || end == 0 {
        return "an unknown host".to_owned();
    }
    String::from_utf8_lossy(&name[..end]).into_owned()
}

/// The full name of this host, as `hostname -f` tells it; why the system
/// gives none otherwise.
///
/// It is the canonical name the system gives to the short one (`getaddrinfo`
/// with `AI_CANONNAME`): the first name of the first line of `/etc/hosts`
/// that holds the short one, or what the DNS answers. A system that only knows the short
/// name gives it back as it is: nothing is added to it here.
pub fn full_name() -> Result<String, String> {
    let short = hostname();
    let unnamed = "the system does not tell the name of this host";
    let node = match CString::new(short.as_str()) {
        Ok(node) if short != "an unknown host" => node,
        _ => return Err(unnamed.to_owned()),
    };
    // What `hostname -f` asks: the canonical name, whatever the family of the address.
    let hints = libc::addrinfo {
        ai_flags: libc::AI_CANONNAME,
        ai_family: libc::AF_UNSPEC,
        ai_socktype: libc::SOCK_DGRAM,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_canonname: ptr::null_mut(),
        ai_addr: ptr::null_mut(),
        ai_next: ptr::null_mut(),
    };
    let mut answers: *mut libc::addrinfo = ptr::null_mut();
    // SAFETY: the name is a C string that outlives the call, the hints are a
    // whole `addrinfo`, and `answers` is where the list is handed back.
    #[expect(unsafe_code, reason = "the canonical name of the host is only known to libc")]
    let status = unsafe { libc::getaddrinfo(node.as_ptr(), ptr::null(), &raw const hints, &raw mut answers) };
    if status != 0 {
        // SAFETY: gai_strerror gives a static C string for any status.
        #[expect(unsafe_code, reason = "the reason of the refusal is only known to libc")]
        let reason = unsafe { CStr::from_ptr(libc::gai_strerror(status)) }.to_string_lossy().into_owned();
        return Err(format!("the system gives no full name to {short}: {reason}"));
    }
    // SAFETY: on success `answers` is a list `getaddrinfo` allocated, read
    // before it is freed, once; the canonical name is on its first element,
    // a C string when it is not null.
    #[expect(unsafe_code, reason = "the answer of getaddrinfo is a list of libc")]
    let name = unsafe {
        let name = match answers.as_ref() {
            Some(first) if !first.ai_canonname.is_null() => {
                Some(CStr::from_ptr(first.ai_canonname).to_string_lossy().into_owned())
            }
            _ => None,
        };
        if !answers.is_null() {
            libc::freeaddrinfo(answers);
        }
        name
    };
    match name {
        Some(name) if !name.is_empty() => Ok(name),
        _ => Err(format!("the system gives no full name to {short}: no canonical name")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hostname_is_the_name_of_this_host() {
        let name = hostname();
        assert!(!name.is_empty() && !name.contains('\0'), "{name:?}");
    }

    // What the system answers is the system's: a name, as one is written, or
    // the reason there is none, never an empty text a run would compare.
    #[test]
    fn the_full_name_is_a_name_or_an_error_that_says_why() {
        match full_name() {
            Ok(name) => {
                assert!(!name.is_empty() && !name.contains(|c: char| c == '\0' || c.is_whitespace()), "{name:?}");
            }
            Err(error) => {
                let said = error.starts_with("the system gives no full name to ")
                    || error == "the system does not tell the name of this host";
                assert!(said, "{error:?}");
            }
        }
    }
}
