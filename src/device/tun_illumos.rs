use super::illumos_ffi::*;
use super::Error;
use libc::*;
use std::os::unix::io::{AsRawFd, RawFd};

/*
 * WARNING this was largely a translation from jclulow's work to get the wireguard-go project
 * working on illumos. This file currently lacks comments until proper cleanup happens.
 *
 * For reference see:
 * https://github.com/jclulow/wireguard-go-illumos-wip/blob/jclulow/tun/tun_illumos.go
 */

// STREAMS ioctl
const I_STR: c_int = 0x5308;
const I_PUSH: c_int = 0x5302;
const I_PLINK: c_int = 0x5316;
const I_PUNLINK: c_int = 0x5317;

const IF_UNITSEL: c_uint = 0x80047336;
const SIOCSLIFMUXID: c_uint = 0x80786984;
const SIOCGIFMTU: c_uint = 0xc0206916;

const TUNNEWPPA: c_int = 0x540001;

pub fn errno() -> i32 {
    unsafe { *___errno() }
}

pub fn errno_str() -> String {
    let strerr = unsafe { strerror(errno()) };
    let c_str = unsafe { std::ffi::CStr::from_ptr(strerr) };
    c_str.to_string_lossy().into_owned()
}

#[derive(Default, Debug)]
pub struct TunSocket {
    fd: RawFd,
    ip_fd: RawFd,
    muxid: i32,
    name: String,
}

impl Drop for TunSocket {
    fn drop(&mut self) {
        let _ = punlink(self.ip_fd, self.muxid);
        unsafe { close(self.ip_fd) };
        unsafe { close(self.fd) };
    }
}

impl AsRawFd for TunSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

// On illumos the tunnel can only be named tun[0-9]+ and the idx is given out via PPA
fn verify_tun_name(name: &str) -> Result<(), Error> {
    if name != "tun" {
        return Err(Error::InvalidTunnelName);
    }
    Ok(())
}

fn tun_new_ppa(fd: RawFd) -> Result<i32, Error> {
    let mut ppa: i32;
    for i in 0..128 {
        ppa = i;
        let strioc = strioctl {
            ic_cmd: TUNNEWPPA,
            ic_timout: 0,
            ic_len: 4,
            ic_dp: &mut ppa as *mut _,
        };

        let new_ppa = match unsafe { ioctl(fd, I_STR, &strioc) } {
            -1 => match std::io::Error::last_os_error().raw_os_error().unwrap() {
                EEXIST => continue,
                // XXX grabbing the error above may break errno_str?
                _ => return Err(Error::IOCtl(errno_str())),
            },
            ppa => ppa,
        };

        return Ok(new_ppa);
    }
    Ok(0)
}

fn push_ip(fd: RawFd) -> Result<(), Error> {
    let modname = b"ip\0";
    match unsafe { ioctl(fd, I_PUSH, modname.as_ptr()) } {
        -1 => Err(Error::IOCtl(errno_str())),
        _ => Ok(()),
    }
}

fn unit_select(fd: RawFd, ppa: i32) -> Result<(), Error> {
    match unsafe { ioctl(fd, IF_UNITSEL as c_int, &ppa) } {
        -1 => Err(Error::IOCtl(errno_str())),
        _ => Ok(()),
    }
}

fn plink(fd: RawFd, other_fd: RawFd) -> Result<i32, Error> {
    match unsafe { ioctl(fd, I_PLINK, other_fd as usize) } {
        -1 => Err(Error::IOCtl(errno_str())),
        muxid => Ok(muxid),
    }
}

fn punlink(fd: RawFd, muxid: i32) -> Result<(), Error> {
    match unsafe { ioctl(fd, I_PUNLINK, muxid as usize) } {
        -1 => Err(Error::IOCtl(errno_str())),
        _ => Ok(()),
    }
}

fn set_ip_muxid(fd: RawFd, name: &str, muxid: i32) -> Result<(), Error> {
    let ifname: &[u8] = name.as_ref();

    let mut ifr: lifreq = unsafe { std::mem::zeroed() };
    ifr.lifr_name[..ifname.len()].copy_from_slice(ifname);
    ifr.lifr_lifru[..4].copy_from_slice(&muxid.to_le_bytes());

    match unsafe { ioctl(fd, SIOCSLIFMUXID as c_int, &ifr) } {
        -1 => Err(Error::IOCtl(errno_str())),
        _ => Ok(()),
    }
}

impl TunSocket {
    pub fn new(name: &str) -> Result<TunSocket, Error> {
        verify_tun_name(name)?;

        let ip_fd = match unsafe { open(b"/dev/udp\0".as_ptr() as _, O_RDWR) } {
            -1 => return Err(Error::IpNode(errno_str())),
            fd @ _ => fd,
        };

        let tun_fd = match unsafe { open(b"/dev/tun\0".as_ptr() as _, O_RDWR) } {
            -1 => {
                unsafe { close(ip_fd) };
                return Err(Error::Socket(errno_str()));
            }
            fd @ _ => fd,
        };

        let ppa = match tun_new_ppa(tun_fd) {
            Ok(ppa) => ppa,
            Err(e) => {
                unsafe { close(tun_fd) };
                unsafe { close(ip_fd) };
                return Err(e);
            }
        };

        let name = format!("tun{}", ppa);

        let if_fd = match unsafe { open(b"/dev/tun\0".as_ptr() as _, O_RDWR) } {
            -1 => {
                unsafe { close(tun_fd) };
                unsafe { close(ip_fd) };
                return Err(Error::Socket(errno_str()));
            }
            fd @ _ => fd,
        };

        if let Err(e) = push_ip(if_fd) {
            unsafe { close(if_fd) };
            unsafe { close(tun_fd) };
            unsafe { close(ip_fd) };
            return Err(e);
        }

        if let Err(e) = unit_select(if_fd, ppa) {
            unsafe { close(if_fd) };
            unsafe { close(tun_fd) };
            unsafe { close(ip_fd) };
            return Err(e);
        }

        let ip_muxid = match plink(ip_fd, if_fd) {
            Ok(muxid) => muxid,
            Err(e) => {
                unsafe { close(if_fd) };
                unsafe { close(tun_fd) };
                unsafe { close(ip_fd) };
                return Err(e);
            }
        };

        unsafe { close(if_fd) };
        drop(if_fd);

        if let Err(e) = set_ip_muxid(ip_fd, &name, ip_muxid) {
            if let Err(e) = punlink(ip_fd, ip_muxid) {
                return Err(e);
            }
            unsafe { close(tun_fd) };
            unsafe { close(ip_fd) };
            return Err(e);
        }

        Ok(TunSocket {
            fd: tun_fd,
            ip_fd: ip_fd,
            name,
            muxid: ip_muxid,
        })
    }

    pub fn name(&self) -> Result<String, Error> {
        Ok(self.name.clone())
    }

    pub fn set_non_blocking(self) -> Result<TunSocket, Error> {
        match unsafe { fcntl(self.fd, F_GETFL) } {
            -1 => Err(Error::FCntl(errno_str())),
            flags @ _ => match unsafe { fcntl(self.fd, F_SETFL, flags | O_NONBLOCK) } {
                -1 => Err(Error::FCntl(errno_str())),
                _ => Ok(self),
            },
        }
    }

    /// Get the current MTU value
    pub fn mtu(&self) -> Result<usize, Error> {
        let ifname: &[u8] = self.name.as_ref();

        // illumos struct ifreq
        let mut ifr = [0; 32];
        // ifreq.ifr_name[0; 16]
        ifr[..ifname.len()].copy_from_slice(ifname);

        match unsafe { ioctl(self.ip_fd, SIOCGIFMTU as c_int, &mut ifr) } {
            -1 => Err(Error::IOCtl(errno_str())),
            _ => {
                let mut bytes = [0; 4];
                // ifreq.ifr_ifru.ifru_mtu is the first 4 bytes of ifr_ifru.
                bytes.copy_from_slice(&ifr[16..16 + 4]);
                let mtu = u32::from_le_bytes(bytes);
                Ok(mtu as usize)
            }
        }
    }

    pub fn write4(&self, src: &[u8]) -> usize {
        self.write(src)
    }

    pub fn write6(&self, src: &[u8]) -> usize {
        self.write(src)
    }

    fn write(&self, buf: &[u8]) -> usize {
        let sbuf = strbuf {
            maxlen: 0,
            len: buf.len() as i32,
            buf: buf.as_ptr() as *const c_void,
        };

        match unsafe { putmsg(self.fd, std::ptr::null(), &sbuf, 0) } {
            // Well ignoring this error is kind of lame
            -1 => 0,
            _ => buf.len(),
        }
    }

    pub fn read<'a>(&self, dst: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        let mut flags: i32 = 0;

        let mut sbuf = strbuf {
            maxlen: dst.len() as i32,
            len: 0,
            buf: dst.as_mut_ptr() as *const c_void,
        };

        match unsafe { getmsg(self.fd, std::ptr::null_mut(), &mut sbuf, &mut flags) } {
            -1 => Err(Error::IfaceRead(errno())),
            _ => {
                // The man page says that -1 is a possible return value for strbuf.len and that it
                // indicates no data is present in the message. So just return a slice of 0 bytes?
                let mut bytes_read = 0;
                if sbuf.len >= 0 {
                    bytes_read = sbuf.len
                };
                Ok(&mut dst[..bytes_read as usize])
            }
        }
    }
}
