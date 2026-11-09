//! Bounded local descriptor handoff. No serializable authority is accepted.
use std::{
    io,
    mem::{self, size_of},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::net::{UnixDatagram, UnixListener, UnixStream},
    },
};
const FRAME: &[u8] = b"R7AUX1";

/// Receive exactly four descriptors in one datagram, then require a transfer-complete datagram on
/// the handoff channel. The sender must drop its transport aliases before
/// sending that barrier. Root driver remains in the declared trusted boundary.
pub(super) fn receive(
    socket: UnixDatagram,
) -> io::Result<(UnixListener, UnixStream, UnixListener, UnixStream)> {
    let mut fds = receive_exact(socket, FRAME, 4)?.into_iter();
    Ok((
        UnixListener::from(fds.next().unwrap()),
        UnixStream::from(fds.next().unwrap()),
        UnixListener::from(fds.next().unwrap()),
        UnixStream::from(fds.next().unwrap()),
    ))
}
/// Native relay already owns control sockets; only raw listener/stream move.
#[allow(dead_code)] // Used by library runtime; legacy binary shares this module.
pub(super) fn receive_raw(socket: UnixDatagram) -> io::Result<(UnixListener, UnixStream)> {
    let mut fds = receive_exact(socket, b"R7RAW1", 2)?.into_iter();
    Ok((
        UnixListener::from(fds.next().unwrap()),
        UnixStream::from(fds.next().unwrap()),
    ))
}
fn receive_exact(socket: UnixDatagram, frame: &[u8], count: usize) -> io::Result<Vec<OwnedFd>> {
    let mut kind: libc::c_int = 0;
    let mut size = size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut size,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if size as usize != size_of::<libc::c_int>() || kind != libc::SOCK_DGRAM {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "datagram handoff required",
        ));
    }
    let mut bytes = [0u8; 64];
    // usize gives cmsghdr alignment. Space deliberately exceeds four FDs so
    // extras can be adopted and closed on rejection, rather than leaked.
    let mut control = [0usize; 64];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: all pointers below refer to live writable buffers for recvmsg.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = mem::size_of_val(&control) as _;
    #[cfg(target_os = "linux")]
    let flags = libc::MSG_CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = 0;
    let read = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, flags) };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut received = Vec::new();
    let mut malformed = false;
    // Adopt every installed SCM_RIGHTS descriptor before inspecting the frame,
    // so all error paths close ownership. Kernel closes truncated excess rights.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            let base = libc::CMSG_LEN(0) as usize;
            if ((*header).cmsg_len as usize) < base {
                malformed = true;
                break;
            }
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let bytes = (*header).cmsg_len as usize - base;
                malformed |= !bytes.is_multiple_of(size_of::<libc::c_int>());
                for index in 0..bytes / size_of::<libc::c_int>() {
                    let fd = libc::CMSG_DATA(header)
                        .cast::<libc::c_int>()
                        .add(index)
                        .read_unaligned();
                    received.push(OwnedFd::from_raw_fd(fd));
                }
            } else {
                malformed = true;
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if malformed
        || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || read as usize != frame.len()
        || &bytes[..frame.len()] != frame
        || received.len() != count
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "exact scoped auxiliary descriptor handoff required",
        ));
    }
    for fd in &received {
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        if flags < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    // SOCK_DGRAM has no EOF on peer close. An exact second datagram is the
    // sender's transfer-complete barrier, sent only after dropping all aliases.
    let mut done = [0u8; 16];
    if socket.recv(&mut done)? != 4 || &done[..4] != b"DONE" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "auxiliary transfer barrier differs",
        ));
    }
    Ok(received)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    fn send(socket: &UnixDatagram, frame: &[u8], fds: &[i32]) {
        let mut iov = libc::iovec {
            iov_base: frame.as_ptr().cast_mut().cast(),
            iov_len: frame.len(),
        };
        let mut control = [0usize; 64];
        unsafe {
            let mut message: libc::msghdr = mem::zeroed();
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            if !fds.is_empty() {
                message.msg_control = control.as_mut_ptr().cast();
                message.msg_controllen = libc::CMSG_SPACE(mem::size_of_val(fds) as _) as _;
                let header = libc::CMSG_FIRSTHDR(&message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN(mem::size_of_val(fds) as _) as _;
                std::ptr::copy_nonoverlapping(
                    fds.as_ptr().cast::<u8>(),
                    libc::CMSG_DATA(header),
                    mem::size_of_val(fds),
                );
            }
            assert_eq!(
                libc::sendmsg(socket.as_raw_fd(), &message, 0),
                frame.len() as isize
            );
        }
    }
    #[test]
    fn actual_rights_transfer_cloexec_and_bounded_rejection() {
        let file = File::open("/dev/null").unwrap();
        let fd = file.as_raw_fd();
        for (frame, count, done, pass) in [
            (FRAME, 4, b"DONE".as_slice(), true),
            (FRAME, 0, b"DONE", false),
            (FRAME, 3, b"DONE", false),
            (FRAME, 5, b"DONE", false),
            (b"wrong!", 4, b"DONE", false),
            (FRAME, 4, b"NOPE", false),
        ] {
            let (tx, rx) = UnixDatagram::pair().unwrap();
            rx.set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .unwrap();
            send(&tx, frame, &vec![fd; count]);
            tx.send(done).unwrap();
            let result = receive(rx);
            assert_eq!(result.is_ok(), pass);
            if let Ok((a, b, c, d)) = result {
                for fd in [a.as_raw_fd(), b.as_raw_fd(), c.as_raw_fd(), d.as_raw_fd()] {
                    assert_ne!(
                        unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
                        0
                    );
                }
            }
        }
    }
}
