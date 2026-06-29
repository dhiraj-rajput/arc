//! Local network discovery and IP address gathering.

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use tracing::{debug, error, info};

/// Returns the local device's active routed IP addresses (both IPv4 and IPv6).
pub fn get_local_ips() -> Vec<IpAddr> {
    let (probe_ipv4, probe_ipv6) = match crate::storage::load_config() {
        Ok(cfg) => (cfg.dns_probe_ipv4, cfg.dns_probe_ipv6),
        Err(_) => (
            "8.8.8.8:80".to_string(),
            "[2001:4860:4860::8888]:80".to_string(),
        ),
    };

    let mut ips = Vec::new();

    // Probe IPv4 local address by binding and dummy-connecting
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        if socket.connect(&probe_ipv4).is_ok() {
            if let Ok(local_addr) = socket.local_addr() {
                let ip = local_addr.ip();
                if !ip.is_loopback() && !ip.is_unspecified() {
                    ips.push(ip);
                }
            }
        }
    }

    // Probe IPv6 local address by binding and dummy-connecting
    if let Ok(socket) = UdpSocket::bind("[::]:0") {
        if socket.connect(&probe_ipv6).is_ok() {
            if let Ok(local_addr) = socket.local_addr() {
                let ip = local_addr.ip();
                if !ip.is_loopback() && !ip.is_unspecified() {
                    ips.push(ip);
                }
            }
        }
    }

    // If active network interfaces are not connected to the internet,
    // default to loopback so local transfers still work.
    if ips.is_empty() {
        ips.push(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    ips
}

/// Daemon to register our service and discover other peers on the local subnet.
pub struct DiscoveryManager {
    daemon: ServiceDaemon,
    service_type: &'static str,
    registered_fullname: std::sync::Mutex<Option<String>>,
}

impl DiscoveryManager {
    /// Creates a new `DiscoveryManager`.
    pub fn new() -> Result<Self, anyhow::Error> {
        let daemon = ServiceDaemon::new()?;
        Ok(Self {
            daemon,
            service_type: "_arc._udp.local.",
            registered_fullname: std::sync::Mutex::new(None),
        })
    }

    /// Registers the local device's service with a custom name and listening UDP port.
    pub fn register_service(
        &self,
        instance_name: &str,
        port: u16,
        device_id: &[u8; 32],
    ) -> Result<(), anyhow::Error> {
        let local_ips = get_local_ips();
        let ip_to_use = local_ips
            .first()
            .copied()
            .unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        // BUG-5: Add unique suffix using device_id to ensure unique mDNS instance name
        let unique_instance_name = format!("{}-{}", instance_name, &hex::encode(device_id)[..6]);

        // Create properties map
        let mut properties = std::collections::HashMap::new();
        properties.insert("device_id".to_string(), hex::encode(device_id));
        properties.insert("port".to_string(), port.to_string());

        let host_name = format!("{}.local.", unique_instance_name);
        let service_info = ServiceInfo::new(
            self.service_type,
            &unique_instance_name,
            &host_name,
            ip_to_use,
            port,
            Some(properties),
        )?;

        let fullname = service_info.get_fullname().to_string();
        info!(
            "Registering mDNS service: {} with IP: {} and port: {}",
            fullname, ip_to_use, port
        );
        self.daemon.register(service_info)?;

        if let Ok(mut guard) = self.registered_fullname.lock() {
            *guard = Some(fullname);
        }
        Ok(())
    }

    /// Browses for other peers of the `_arc._udp.local.` type on the local subnet.
    ///
    /// Returns a list of discovered candidate peer `SocketAddr`s.
    pub fn discover_peers(&self, timeout: Duration) -> Vec<SocketAddr> {
        let mut candidates = Vec::new();
        match self.daemon.browse(self.service_type) {
            Ok(receiver) => {
                let start = std::time::Instant::now();
                while start.elapsed() < timeout {
                    if let Ok(ServiceEvent::ServiceResolved(info)) =
                        receiver.recv_timeout(Duration::from_millis(50))
                    {
                        let port = info.get_port();
                        for ip in info.get_addresses() {
                            let addr = SocketAddr::new(ip.to_ip_addr(), port);
                            if !candidates.contains(&addr) {
                                debug!("mDNS discovered peer candidate: {}", addr);
                                candidates.push(addr);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to browse for mDNS services: {:?}", e);
            }
        }
        candidates
    }

    /// Discover active peers with detailed information (fullname, address, device ID).
    pub fn discover_detailed_peers(&self, timeout: Duration) -> Vec<(String, SocketAddr, String)> {
        let mut resolved = Vec::new();
        if let Ok(receiver) = self.daemon.browse(self.service_type) {
            let start = std::time::Instant::now();
            while start.elapsed() < timeout {
                if let Ok(ServiceEvent::ServiceResolved(info)) =
                    receiver.recv_timeout(Duration::from_millis(50))
                {
                    let name = info.get_fullname().to_string();
                    let port = info.get_port();
                    let device_id = info
                        .get_properties()
                        .get("device_id")
                        .map(|v| v.val_str().to_string())
                        .unwrap_or_default();
                    for ip in info.get_addresses() {
                        let addr = SocketAddr::new(ip.to_ip_addr(), port);
                        if !resolved.iter().any(|(_, a, _)| *a == addr) {
                            resolved.push((name.clone(), addr, device_id.clone()));
                        }
                    }
                }
            }
        }
        resolved
    }

    /// Browses for a specific peer by device ID on the local network.
    pub fn discover_device(
        &self,
        target_device_id: &[u8; 32],
        timeout: Duration,
    ) -> Option<SocketAddr> {
        let target_hex = hex::encode(target_device_id);
        if let Ok(receiver) = self.daemon.browse(self.service_type) {
            let start = std::time::Instant::now();
            while start.elapsed() < timeout {
                if let Ok(ServiceEvent::ServiceResolved(info)) =
                    receiver.recv_timeout(Duration::from_millis(50))
                {
                    if let Some(prop) = info.get_properties().get("device_id") {
                        if prop.val_str() == target_hex {
                            let port = info.get_port();
                            if let Some(ip) = info.get_addresses().iter().next() {
                                return Some(SocketAddr::new(ip.to_ip_addr(), port));
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Gracefully unregisters all services registered by this manager.
    pub fn unregister_all(&self) -> Result<(), anyhow::Error> {
        self.daemon.stop_browse(self.service_type)?;
        let fullname = if let Ok(mut guard) = self.registered_fullname.lock() {
            guard.take()
        } else {
            None
        };
        if let Some(name) = fullname {
            let _ = self.daemon.unregister(&name);
        }
        Ok(())
    }
}
