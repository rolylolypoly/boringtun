use libc::*;

pub const TFD_NONBLOCK: c_int = 0x800;
pub const EFD_NONBLOCK: c_int = 0o4000;
pub const SFD_NONBLOCK: c_int = 0o4000;

#[repr(C)]
pub struct itimerspec {
    pub it_interval: libc::timespec,
    pub it_value: libc::timespec,
}

// User level ioctl format for ioctl that go downstream I_STR
#[repr(C)]
pub struct strioctl {
    pub ic_cmd: c_int,     /* command */
    pub ic_timout: c_int,  /* timeout value */
    pub ic_len: c_int,     /* length of data */
    pub ic_dp: *mut c_int, /* pointer to data */
}

#[repr(C)]
pub struct strbuf {
    pub maxlen: c_int,
    pub len: c_int,
    pub buf: *const c_void,
}

#[repr(C)]
pub union lifru1 {
    pub addrlen: c_int,
    pub ppa: c_uint,
}

#[repr(C)]
pub struct lifreq {
    pub lifr_name: [u8; 32],
    pub lifr_lifru1: lifru1,
    pub lifr_type: c_uint,
    pub lifr_lifru: [u8; 336],
}

extern "C" {
    // timerfd
    pub fn timerfd_create(clockid: c_int, flags: c_int) -> c_int;
    pub fn timerfd_settime(
        fd: c_int,
        flags: c_int,
        new_value: *const itimerspec,
        old_value: *mut itimerspec,
    ) -> c_int;

    // eventfd
    pub fn eventfd(init: c_uint, flags: c_int) -> c_int;

    // signalfd
    pub fn signalfd(fd: c_int, mask: *const sigset_t, flags: c_int) -> c_int;

    // STREAMS
    pub fn getmsg(fd: c_int, ctlptr: *mut strbuf, dataptr: *mut strbuf, flags: *mut c_int)
        -> c_int;
    pub fn putmsg(fd: c_int, ctlptr: *const strbuf, dataptr: *const strbuf, flags: c_int) -> c_int;
}
