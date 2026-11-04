// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{
    ffi::CString,
    fs::{create_dir, remove_file},
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
    os::unix::{
        io::{AsRawFd, FromRawFd},
        net::{UnixListener, UnixStream},
    },
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use hex::encode as encode_hex;
use libc::*;

use super::{
    AllowedIP, Device, Error, SocketAddr, dev_lock::LockReadGuard, drop_privileges::get_saved_ids,
};
use crate::{device::Action, serialization::KeyBytes, x25519};

const SOCK_DIR: &str = "/var/run/wireguard/";

// Each control exchange has a total deadline, not a timeout that a slowly
// streaming client can renew forever while holding the device lock.
#[derive(Clone, Copy)]
struct DeadlineStream<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
}
impl DeadlineStream<'_> {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "UAPI exchange timed out"))
    }
}
impl Read for DeadlineStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buf)
    }
}
impl Write for DeadlineStream<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
fn read_line(reader: &mut impl BufRead, line: &mut String) -> io::Result<usize> {
    let count = Read::take(reader, 4097).read_line(line)?;
    if line.len() > 4096 || !line.ends_with('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete or oversized UAPI line",
        ));
    }
    Ok(count)
}

fn create_sock_dir() {
    let _ = create_dir(SOCK_DIR); // Create the directory if it does not exist

    if let Ok((saved_uid, saved_gid)) = get_saved_ids() {
        unsafe {
            let c_path = CString::new(SOCK_DIR).unwrap();
            // The directory is under the root user, but we want to be able to
            // delete the files there when we exit, so we need to change the owner
            chown(
                c_path.as_bytes_with_nul().as_ptr().cast(),
                saved_uid,
                saved_gid,
            );
        }
    }
}

impl Device {
    /// Register the api handler for this Device. The api handler receives stream connections on a Unix socket
    /// with a known path: /var/run/wireguard/{tun_name}.sock.
    pub fn register_api_handler(&mut self) -> Result<(), Error> {
        let path = format!("{SOCK_DIR}/{}.sock", self.iface.name()?);

        create_sock_dir();

        let _ = remove_file(&path); // Attempt to remove the socket if already exists

        let api_listener = UnixListener::bind(&path).map_err(Error::ApiSocket)?; // Bind a new socket to the path

        self.cleanup_paths.push(path.clone());

        self.queue.new_event(
            api_listener.as_raw_fd(),
            Box::new(move |d, _| {
                // This is the closure that listens on the api unix socket
                let Ok((api_conn, _)) = api_listener.accept() else {
                    return Action::Continue;
                };

                let stream = DeadlineStream {
                    stream: &api_conn,
                    deadline: Instant::now() + Duration::from_secs(2),
                };
                let mut reader = BufReader::new(stream.take(1024 * 1024));
                let mut writer = BufWriter::new(stream);
                let mut cmd = String::new();
                if read_line(&mut reader, &mut cmd).is_ok() {
                    cmd.pop(); // pop the new line character
                    let status = match cmd.as_ref() {
                        // Only two commands are legal according to the protocol, get=1 and set=1.
                        "get=1" => api_get(&mut writer, d),
                        "set=1" => api_set(&mut reader, d),
                        _ => EIO,
                    };
                    // The protocol requires to return an error code as the response, or zero on success
                    writeln!(writer, "errno={status}\n").ok();
                }
                Action::Continue // Indicates the worker thread should continue as normal
            }),
        )?;

        self.register_monitor(path)?;
        self.register_api_signal_handlers()
    }

    pub fn register_api_fd(&mut self, fd: i32) -> Result<(), Error> {
        let io_file = unsafe { UnixStream::from_raw_fd(fd) };

        self.queue.new_event(
            io_file.as_raw_fd(),
            Box::new(move |d, _| {
                // This is the closure that listens on the api file descriptor

                let stream = DeadlineStream {
                    stream: &io_file,
                    deadline: Instant::now() + Duration::from_secs(2),
                };
                let mut reader = BufReader::new(stream.take(1024 * 1024));
                let mut writer = BufWriter::new(stream);
                let mut cmd = String::new();
                if read_line(&mut reader, &mut cmd).is_ok() {
                    cmd.pop(); // pop the new line character
                    let status = match cmd.as_ref() {
                        // Only two commands are legal according to the protocol, get=1 and set=1.
                        "get=1" => api_get(&mut writer, d),
                        "set=1" => api_set(&mut reader, d),
                        _ => EIO,
                    };
                    // The protocol requires to return an error code as the response, or zero on success
                    writeln!(writer, "errno={status}\n").ok();
                } else {
                    // The remote side is likely closed; we should trigger an exit.
                    d.trigger_exit();
                    return Action::Exit;
                }

                Action::Continue // Indicates the worker thread should continue as normal
            }),
        )?;

        Ok(())
    }

    fn register_monitor(&self, path: String) -> Result<(), Error> {
        self.queue.new_periodic_event(
            Box::new(move |d, _| {
                // This is not a very nice hack to detect if the control socket was removed
                // and exiting nicely as a result. We check every 3 seconds in a loop if the
                // file was deleted by stating it.
                // The problem is that on linux inotify can be used quite beautifully to detect
                // deletion, and kqueue EVFILT_VNODE can be used for the same purpose, but that
                // will require introducing new events, for no measurable benefit.
                // TODO: Could this be an issue if we restart the service too quickly?
                let path = std::path::Path::new(&path);
                if !path.exists() {
                    d.trigger_exit();
                    return Action::Exit;
                }

                // Periodically read the mtu of the interface in case it changes
                if let Ok(mtu) = d.iface.mtu() {
                    d.mtu.store(mtu, Ordering::Relaxed);
                }

                Action::Continue
            }),
            std::time::Duration::from_secs(1),
        )?;

        Ok(())
    }

    fn register_api_signal_handlers(&self) -> Result<(), Error> {
        self.queue
            .new_signal_event(SIGINT, Box::new(move |_, _| Action::Exit))?;

        self.queue
            .new_signal_event(SIGTERM, Box::new(move |_, _| Action::Exit))?;

        Ok(())
    }
}

#[allow(unused_must_use)]
fn api_get(writer: &mut impl Write, d: &Device) -> i32 {
    // get command requires an empty line, but there is no reason to be religious about it
    if let Some(ref k) = d.key_pair {
        writeln!(writer, "private_key={}", encode_hex(k.0.as_bytes()));
    }

    if d.listen_port != 0 {
        writeln!(writer, "listen_port={}", d.listen_port);
    }

    if let Some(fwmark) = d.fwmark {
        writeln!(writer, "fwmark={fwmark}");
    }

    for (k, p) in &d.peers {
        let p = p.lock();
        writeln!(writer, "public_key={}", encode_hex(k.as_bytes()));

        if let Some(ref key) = p.preshared_key() {
            writeln!(writer, "preshared_key={}", encode_hex(key));
        }

        if let Some(keepalive) = p.persistent_keepalive() {
            writeln!(writer, "persistent_keepalive_interval={keepalive}");
        }

        if let Some(ref addr) = p.endpoint().addr {
            writeln!(writer, "endpoint={addr}");
        }

        for (ip, cidr) in p.allowed_ips() {
            writeln!(writer, "allowed_ip={ip}/{cidr}");
        }

        if let Some(time) = p.last_handshake_time() {
            writeln!(writer, "last_handshake_time_sec={}", time.as_secs());
            writeln!(writer, "last_handshake_time_nsec={}", time.subsec_nanos());
        }

        let (_, tx_bytes, rx_bytes, ..) = p.tunnel.stats();

        writeln!(writer, "rx_bytes={rx_bytes}");
        writeln!(writer, "tx_bytes={tx_bytes}");
    }
    0
}

fn api_set(reader: &mut impl BufRead, d: &mut LockReadGuard<Device>) -> i32 {
    d.try_writeable(super::Device::trigger_yield, |device| {
        device.cancel_yield();

        let mut cmd = String::new();

        while read_line(reader, &mut cmd).is_ok() {
            cmd.pop(); // remove newline if any
            if cmd.is_empty() {
                return 0; // Done
            }
            {
                let parsed_cmd: Vec<&str> = cmd.split('=').collect();
                if parsed_cmd.len() != 2 {
                    return EPROTO;
                }

                let (key, val) = (parsed_cmd[0], parsed_cmd[1]);

                match key {
                    "private_key" => match val.parse::<KeyBytes>() {
                        Ok(key_bytes) => {
                            device.set_key(&x25519::StaticSecret::from(key_bytes.0));
                        }
                        Err(_) => return EINVAL,
                    },
                    "listen_port" => match val.parse::<u16>() {
                        Ok(port) => match device.open_listen_socket(port) {
                            Ok(()) => {}
                            Err(_) => return EADDRINUSE,
                        },
                        Err(_) => return EINVAL,
                    },
                    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                    "fwmark" => match val.parse::<u32>() {
                        Ok(mark) => match device.set_fwmark(mark) {
                            Ok(()) => {}
                            Err(_) => return EADDRINUSE,
                        },
                        Err(_) => return EINVAL,
                    },
                    "replace_peers" => match val.parse::<bool>() {
                        Ok(true) => device.clear_peers(),
                        Ok(false) => {}
                        Err(_) => return EINVAL,
                    },
                    "public_key" => match val.parse::<KeyBytes>() {
                        // Indicates a new peer section
                        Ok(key_bytes) => {
                            return api_set_peer(
                                reader,
                                device,
                                x25519::PublicKey::from(key_bytes.0),
                            );
                        }
                        Err(_) => return EINVAL,
                    },
                    _ => return EINVAL,
                }
            }
            cmd.clear();
        }

        EPROTO
    })
    .unwrap_or(EIO)
}

fn api_set_peer(reader: &mut impl BufRead, d: &mut Device, pub_key: x25519::PublicKey) -> i32 {
    let mut cmd = String::new();

    let mut remove = false;
    let mut replace_ips = false;
    let mut endpoint = None;
    let mut keepalive = None;
    let mut public_key = pub_key;
    let mut preshared_key = None;
    let mut allowed_ips: Vec<AllowedIP> = Vec::new();
    while read_line(reader, &mut cmd).is_ok() {
        cmd.pop(); // remove newline if any
        if cmd.is_empty() {
            return d.update_peer(
                public_key,
                remove,
                replace_ips,
                endpoint,
                allowed_ips.as_slice(),
                keepalive,
                preshared_key,
            );
        }
        {
            let parsed_cmd: Vec<&str> = cmd.splitn(2, '=').collect();
            if parsed_cmd.len() != 2 {
                return EPROTO;
            }
            let (key, val) = (parsed_cmd[0], parsed_cmd[1]);
            match key {
                "remove" => match val.parse::<bool>() {
                    Ok(true) => remove = true,
                    Ok(false) => remove = false,
                    Err(_) => return EINVAL,
                },
                "preshared_key" => match val.parse::<KeyBytes>() {
                    Ok(key_bytes) => preshared_key = Some(key_bytes.0),
                    Err(_) => return EINVAL,
                },
                "endpoint" => match val.parse::<SocketAddr>() {
                    Ok(addr) => endpoint = Some(addr),
                    Err(_) => return EINVAL,
                },
                "persistent_keepalive_interval" => match val.parse::<u16>() {
                    Ok(interval) => keepalive = Some(interval),
                    Err(_) => return EINVAL,
                },
                "replace_allowed_ips" => match val.parse::<bool>() {
                    Ok(true) => replace_ips = true,
                    Ok(false) => replace_ips = false,
                    Err(_) => return EINVAL,
                },
                "allowed_ip" => match val.parse::<AllowedIP>() {
                    Ok(ip) => allowed_ips.push(ip),
                    Err(_) => return EINVAL,
                },
                "public_key" => {
                    // Indicates a new peer section. Commit changes for current peer, and continue to next peer
                    let errno = d.update_peer(
                        public_key,
                        remove,
                        replace_ips,
                        endpoint,
                        allowed_ips.as_slice(),
                        keepalive,
                        preshared_key,
                    );
                    if errno != 0 {
                        return errno;
                    }
                    allowed_ips.clear();
                    remove = false;
                    replace_ips = false;
                    endpoint = None;
                    keepalive = None;
                    preshared_key = None;
                    match val.parse::<KeyBytes>() {
                        Ok(key_bytes) => public_key = key_bytes.0.into(),
                        Err(_) => return EINVAL,
                    }
                }
                "protocol_version" => match val.parse::<u32>() {
                    Ok(1) => {} // Only version 1 is legal
                    _ => return EINVAL,
                },
                _ => return EINVAL,
            }
        }
        cmd.clear();
    }
    EPROTO
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uapi_lines_require_newline_and_have_a_size_limit() {
        for input in ["command", "", &"x".repeat(4097)] {
            assert!(read_line(&mut io::Cursor::new(input), &mut String::new()).is_err());
        }
        let mut line = String::new();
        assert_eq!(
            read_line(&mut io::Cursor::new("get=1\n"), &mut line).unwrap(),
            6
        );
        assert_eq!(line, "get=1\n");
    }

    #[test]
    fn deadline_is_total_even_when_client_keeps_sending() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let sending = std::thread::spawn(move || {
            for _ in 0..40 {
                if sender.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        let start = Instant::now();
        let mut stream = DeadlineStream {
            stream: &receiver,
            deadline: start + Duration::from_millis(40),
        };
        let mut byte = [0];
        while stream.read(&mut byte).is_ok_and(|n| n != 0) {}
        assert!(start.elapsed() < Duration::from_millis(300));
        drop(receiver);
        sending.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Linux root in isolated network and mount namespaces"]
    fn datagram_before_key_configuration_does_not_kill_a_worker() {
        use crate::device::{DeviceConfig, DeviceHandle};
        assert!(
            std::process::Command::new("ip")
                .args(["link", "set", "lo", "up"])
                .status()
                .unwrap()
                .success()
        );
        let name = format!("wgkey{}", std::process::id());
        let device = DeviceHandle::new(&name, DeviceConfig::default()).unwrap();
        let mut socket = UnixStream::connect(format!("/var/run/wireguard/{name}.sock")).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket.write_all(b"get=1\n\n").unwrap();
        let mut reader = BufReader::new(socket);
        let mut port = None;
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() != 0);
            if let Some(value) = line.strip_prefix("listen_port=") {
                port = Some(value.trim().parse::<u16>().unwrap());
            }
            if line == "errno=0\n" {
                break;
            }
        }
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .send_to(&[0u8; 148], (std::net::Ipv4Addr::LOCALHOST, port.unwrap()))
            .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(device.threads.iter().all(|thread| !thread.is_finished()));
        drop(device);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Linux root in isolated network and mount namespaces"]
    fn shutdown_releases_tun_and_udp_with_stalled_and_queued_clients() {
        use crate::device::{DeviceConfig, DeviceHandle};
        let name = format!("wgdrop{}", std::process::id());
        let path = format!("/var/run/wireguard/{name}.sock");
        for (count, prefix) in [
            (0, ""),
            (1, "get="),
            (1, "set=1\nprivate_key="),
            (32, "set=1\nprivate_key="),
        ] {
            let device = DeviceHandle::new(&name, DeviceConfig::default()).unwrap();
            let mut configure = UnixStream::connect(&path).unwrap();
            configure
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            write!(
                configure,
                "set=1\nprivate_key={}\nlisten_port=24777\n\n",
                "01".repeat(32)
            )
            .unwrap();
            let mut reply = String::new();
            BufReader::new(configure).read_line(&mut reply).unwrap();
            assert_eq!(reply, "errno=0\n");
            let mut clients = Vec::new();
            for _ in 0..count {
                let mut client = UnixStream::connect(&path).unwrap();
                client.write_all(prefix.as_bytes()).unwrap();
                clients.push(client);
            }
            std::thread::sleep(Duration::from_millis(100));
            let start = Instant::now();
            drop(device);
            assert!(start.elapsed() < Duration::from_secs(5));
            let cname = CString::new(name.as_str()).unwrap();
            assert_eq!(unsafe { libc::if_nametoindex(cname.as_ptr()) }, 0);
            assert!(std::net::UdpSocket::bind("0.0.0.0:24777").is_ok());
            assert!(!std::path::Path::new(&path).exists());
            drop(clients);
            // Reuse precisely the same TUN and socket names after shutdown.
            drop(DeviceHandle::new(&name, DeviceConfig::default()).unwrap());
        }
    }

    // Run within an isolated network/mount namespace. The control socket may
    // expose fixture keys, so never run this on a shared host namespace.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Linux root in isolated network and mount namespaces"]
    fn peer_sections_do_not_inherit_endpoint_keepalive_psk_or_remove() {
        use crate::device::{DeviceConfig, DeviceHandle};
        let name = format!("wgat{}", std::process::id());
        let device = DeviceHandle::new(&name, DeviceConfig::default()).unwrap();
        let path = format!("/var/run/wireguard/{name}.sock");
        let exchange = |request: String| {
            let mut socket = UnixStream::connect(&path).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket.write_all(request.as_bytes()).unwrap();
            let mut reader = BufReader::new(socket);
            let mut response = String::new();
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).unwrap() != 0);
                response.push_str(&line);
                if line == "errno=0\n" {
                    break;
                }
            }
            response
        };
        let (first, second, third) = ("02".repeat(32), "03".repeat(32), "04".repeat(32));
        exchange(format!(
            "set=1\nprivate_key={}\npublic_key={first}\nendpoint=192.0.2.1:4477\npersistent_keepalive_interval=25\npreshared_key={}\nallowed_ip=10.88.0.2/32\npublic_key={second}\nallowed_ip=10.88.0.3/32\n\n",
            "01".repeat(32),
            "05".repeat(32)
        ));
        let response = exchange("get=1\n\n".into());
        let section = response
            .split(&format!("public_key={second}\n"))
            .nth(1)
            .unwrap()
            .split("public_key=")
            .next()
            .unwrap();
        assert!(!section.contains("endpoint="));
        assert!(!section.contains("persistent_keepalive_interval=25"));
        assert!(!section.contains(&"05".repeat(32)));
        assert!(!section.contains("allowed_ip=10.88.0.2/32"));
        exchange(format!(
            "set=1\npublic_key={first}\nremove=true\npublic_key={third}\nallowed_ip=10.88.0.4/32\n\n"
        ));
        let response = exchange("get=1\n\n".into());
        assert!(!response.contains(&format!("public_key={first}\n")));
        assert!(response.contains(&format!("public_key={third}\n")));
        drop(device);
    }
}
