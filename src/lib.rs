mod binding;
use binding::{
    cn_msg, nlmsghdr, proc_cn_mcast_op, sockaddr_nl, CN_IDX_PROC, NETLINK_CONNECTOR,
    PROC_CN_MCAST_LISTEN,
};
use libc;
use std::io::{Error, Result};

// these are some macros defined in netlink.h

fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

fn nlmsg_hdrlen() -> usize {
    nlmsg_align(std::mem::size_of::<nlmsghdr>())
}

fn nlmsg_length(len: usize) -> usize {
    len + nlmsg_hdrlen()
}

/// Events we are interested
#[derive(Debug)]
pub enum PidEvent {
    ///  PROC_EVENT_EXEC
    Exec(libc::c_int),
    ///  PROC_EVENT_FORK
    Fork(libc::c_int),
    /// PROC_EVENT_COREDUMP
    Coredump(libc::c_int),
    /// PROC_EVENT_EXIT
    Exit(libc::c_int),
}

/// Pid Monitor
#[derive(Debug)]
pub struct PidMonitor {
    fd: libc::c_int,
    id: u32,
}

impl PidMonitor {
    /// Creates a new PidMonitor
    pub fn new() -> Result<PidMonitor> {
        PidMonitor::from_id(std::process::id())
    }

    /// Creates a new PidMonitor, the netlink socket will be created
    /// with the given id instead of `std::process::id()`
    pub fn from_id(id: u32) -> Result<PidMonitor> {
        let fd = unsafe {
            libc::socket(
                libc::PF_NETLINK,
                libc::SOCK_DGRAM,
                // for some reason bindgen doesn't make this
                // a libc::c_int
                NETLINK_CONNECTOR as i32,
            )
        };
        let mut nl = unsafe { std::mem::zeroed::<sockaddr_nl>() };
        nl.nl_pid = id;
        // Again this is an issue of bindgen vs libc
        nl.nl_family = libc::AF_NETLINK as u16;
        nl.nl_groups = CN_IDX_PROC;
        if unsafe {
            libc::bind(
                fd,
                &nl as *const sockaddr_nl as _,
                std::mem::size_of_val(&nl) as _,
            )
        } < 0
        {
            return Err(Error::last_os_error());
        }
        return Ok(PidMonitor { fd, id });
    }

    /// Signals to the kernel we are ready for listening to events
    // TODO: We should really set this so than no ENOBUFS get sent
    // our way
    pub fn listen(&mut self) -> Result<()> {
        let val = true as libc::c_int;
        if unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_NETLINK,
                binding::NETLINK_NO_ENOBUFS as i32,
                &val as *const libc::c_int as _,
                std::mem::size_of_val(&val) as _,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let mut iov_vec = Vec::<libc::iovec>::new();
        // Set nlmsghdr
        let mut msghdr: nlmsghdr = unsafe { std::mem::zeroed() };
        msghdr.nlmsg_len =
            nlmsg_length(std::mem::size_of::<cn_msg>() + std::mem::size_of::<proc_cn_mcast_op>())
                as u32;
        msghdr.nlmsg_pid = self.id;
        //Another mismatch
        msghdr.nlmsg_type = binding::NLMSG_DONE as u16;
        iov_vec.push(libc::iovec {
            iov_len: std::mem::size_of_val(&msghdr),
            iov_base: &msghdr as *const nlmsghdr as _,
        });
        // Set cn_msg
        let mut cnmesg: cn_msg = unsafe { std::mem::zeroed() };
        cnmesg.id.idx = CN_IDX_PROC;
        cnmesg.id.val = binding::CN_VAL_PROC;
        cnmesg.len = std::mem::size_of::<proc_cn_mcast_op>() as u16;
        iov_vec.push(libc::iovec {
            iov_len: std::mem::size_of_val(&cnmesg),
            iov_base: &cnmesg as *const cn_msg as _,
        });
        let op = PROC_CN_MCAST_LISTEN;
        iov_vec.push(libc::iovec {
            iov_len: std::mem::size_of_val(&op),
            iov_base: &op as *const proc_cn_mcast_op as _,
        });
        if unsafe { libc::writev(self.fd, iov_vec.as_ptr() as _, 3) } < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Gets the next event or events comming the netlink socket
    pub fn get_events(&self) -> Result<Vec<PidEvent>> {
        let page_size = std::cmp::min(unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) as usize }, 8192);
        let mut buffer = Vec::<u32>::with_capacity(page_size);
        let buff_size = buffer.capacity();
        unsafe {
            buffer.set_len(buff_size);
        }
        let len = unsafe { libc::recv(self.fd, buffer.as_mut_ptr() as _, buff_size * 4, 0) };
        if len < 0 {
            return Err(Error::last_os_error());
        }
        let mut header = buffer.as_ptr() as *const nlmsghdr;
        let mut pidevents = Vec::<PidEvent>::new();
        let mut len = len as usize;
        loop {
            // NLMSG_OK
            if len < nlmsg_hdrlen() {
                break;
            }
            let msg_len = unsafe { (*header).nlmsg_len } as usize;
            if len < msg_len {
                break;
            }
            let msg_type = unsafe { (*header).nlmsg_type } as u32;
            match msg_type {
                binding::NLMSG_ERROR | binding::NLMSG_NOOP => continue,
                _ => {
                    if let Some(pidevent) = unsafe { parse_msg(header) } {
                        pidevents.push(pidevent)
                    }
                }
            };
            // NLSMSG_NEXT
            let aligned_len = nlmsg_align(msg_len);
            header = (header as usize + aligned_len) as *const nlmsghdr;
            len = match len.checked_sub(aligned_len) {
                Some(v) => v,
                None => break,
            };
        }
        Ok(pidevents)
    }
}

unsafe fn parse_msg(header: *const nlmsghdr) -> Option<PidEvent> {
    let msg = (header as usize + nlmsg_length(0)) as *const cn_msg;
    if (*msg).id.idx != binding::CN_IDX_PROC || (*msg).id.val != binding::CN_VAL_PROC {
        return None;
    };
    let proc_ev = (*msg).data.as_ptr() as *const binding::proc_event;
    match (*proc_ev).what {
        binding::PROC_EVENT_FORK => {
            let pid = (*proc_ev).event_data.fork.child_pid;
            Some(PidEvent::Fork(pid))
        }
        binding::PROC_EVENT_EXEC => {
            let pid = (*proc_ev).event_data.exec.process_pid;
            Some(PidEvent::Exec(pid))
        }
        binding::PROC_EVENT_EXIT => {
            let pid = (*proc_ev).event_data.exit.process_pid;
            Some(PidEvent::Exit(pid))
        }
        binding::PROC_EVENT_COREDUMP => {
            let pid = (*proc_ev).event_data.coredump.process_pid;
            Some(PidEvent::Coredump(pid))
        }
        _ => None,
    }
}

impl Drop for PidMonitor {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {}
}
