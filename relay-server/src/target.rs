//! Fail-closed policy for the only outbound operation: an HTTP-01 challenge.
use reqwest::Url;
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
};

#[derive(Clone)]
pub struct TargetPolicy {
    gateways: HashSet<String>,
}

impl TargetPolicy {
    pub fn new(domains: &str) -> Result<Self, String> {
        let gateways: HashSet<_> = domains
            .split(',')
            .map(str::trim)
            .map(str::to_owned)
            .collect();
        if gateways.is_empty()
            || gateways.iter().any(|d| {
                !valid_domain(d) || d.parse::<IpAddr>().is_ok() || !d.ends_with(".phala.network")
            })
        {
            return Err("ALLOWED_GATEWAY_DOMAINS must list exact lowercase gateway DNS names under phala.network".into());
        }
        Ok(Self { gateways })
    }

    pub fn gateway(&self, domain: &str) -> Result<(), String> {
        if self.gateways.contains(domain) {
            Ok(())
        } else {
            Err("gateway is not explicitly permitted".into())
        }
    }

    pub fn host(&self, host: &str) -> Result<(), String> {
        let (app, gateway) = host.split_once('.').ok_or("missing gateway")?;
        if !valid_app(app) {
            return Err("invalid app ID (port selectors are forbidden)".into());
        }
        self.gateway(gateway)
    }

    pub fn url(&self, app: &str, gateway: &str, path: &str) -> Result<Url, String> {
        self.gateway(gateway)?;
        if !valid_app(app) {
            return Err("invalid app ID (port selectors are forbidden)".into());
        }
        validate_path(path)?;
        let host = format!("{app}.{gateway}");
        let mut url = Url::parse("https://placeholder.invalid/").map_err(|e| e.to_string())?;
        url.set_host(Some(&host)).map_err(|e| e.to_string())?;
        url.set_path(path);
        // Check parsed components, not a suffix on an unparsed URL string.
        if url.host_str() != Some(host.as_str())
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.query().is_some()
            || url.port().is_some()
            || url.path() != path
        {
            return Err("non-canonical challenge URL".into());
        }
        Ok(url)
    }
}

pub fn valid_domain(domain: &str) -> bool {
    domain.len() <= 253
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}

fn valid_app(app: &str) -> bool {
    app.len() == 40
        && app
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub fn validate_path(path: &str) -> Result<(), String> {
    let token = path
        .strip_prefix("/.well-known/acme-challenge/")
        .ok_or("not a challenge path")?;
    if token.len() < 22
        || token.len() > 256
        || !token
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
        return Err("invalid base64url challenge token".into());
    }
    Ok(())
}

/// Conservative public-unicast policy. Reject mixed public/private DNS answers too.
/// IPv6 transition mechanisms are deliberately unsupported to prevent IPv4 tunnelling.
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => {
            let s = ip.segments();
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && s[1] < 0x0200)
                && !(s[0] == 0x2001 && s[1] == 0x0db8)
                && s[0] != 0x2002
                && s[0] != 0x3ffe
                && !(s[0] == 0x3fff && (s[1] & 0xf000) == 0)
        }
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99)))
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113))
}

#[cfg(test)]
mod tests {
    use super::*;
    const APP: &str = "5b912f5cec6c02d851db76bc20f410700f01fc65";
    const GW: &str = "dstack-pha-prod2.phala.network";
    const PATH: &str = "/.well-known/acme-challenge/abcdefghijklmnopqrstuvwxyz_0123456789-ABCDEF";

    // target behavior: exact hostname and canonical challenge URL, default guest port 80.
    #[test]
    fn canonical_target() {
        let p = TargetPolicy::new(GW).unwrap();
        assert_eq!(
            p.url(APP, GW, PATH).unwrap().as_str(),
            format!("https://{APP}.{GW}{PATH}")
        );
    }

    // regression: reconstructed incident URL shapes; exact original TXT/CNAME pairs unavailable.
    #[test]
    fn reject_interpolation_attacks() {
        let p = TargetPolicy::new(GW).unwrap();
        for app in [
            "www.google.com#",
            "127.0.0.1#",
            "localhost#",
            "httpbin.org/redirect-to?url=http://127.0.0.1#",
            "user@evil.com#",
            "foo/../bar",
            "foo%23",
            "foo\\evil.com",
            "5b912f5cec6c02d851db76bc20f410700f01fc65-8090",
        ] {
            assert_eq!(
                p.url(app, GW, PATH).unwrap_err(),
                "invalid app ID (port selectors are forbidden)"
            );
        }
        for gateway in [
            "evil.com",
            "dstack-pha-prod2.phala.network.evil.com",
            "www.google.com#.dstack-pha-prod2.phala.network",
            "user@dstack-pha-prod2.phala.network",
            "localhost",
            "127.0.0.1",
            "dstack-pha-prod4.phala.network",
        ] {
            assert_eq!(
                p.url(APP, gateway, PATH).unwrap_err(),
                "gateway is not explicitly permitted"
            );
        }
    }

    // invariant: no path traversal, queries, fragments, encoded delimiters or arbitrary paths.
    #[test]
    fn challenge_path_only() {
        for path in [
            "/logs/foo",
            "/",
            "/.well-known/acme-challenge/..",
            "/.well-known/acme-challenge/abc%2fdef",
            "/.well-known/acme-challenge/abcdefghijklmnopqrstuvwxyz?x=y",
            "/.well-known/acme-challenge/abcdefghijklmnopqrstuvwxyz#x",
        ] {
            assert!(validate_path(path).is_err(), "{path}");
        }
        assert!(validate_path(PATH).is_ok());
    }

    // invariant: reserved/local/transition destinations rejected, representative public IPs accepted.
    #[test]
    fn public_addresses_only() {
        for addr in [
            "0.0.0.0",
            "10.0.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.17.0.3",
            "192.168.1.1",
            "100.64.0.1",
            "198.18.0.1",
            "203.0.113.10",
            "224.0.0.1",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2002:7f00:1::1",
            "64:ff9b::7f00:1",
            "3ffe::1",
        ] {
            assert!(!public_ip(addr.parse().unwrap()), "{addr}");
        }
        for addr in ["66.220.6.102", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(public_ip(addr.parse().unwrap()), "{addr}");
        }
    }
}
