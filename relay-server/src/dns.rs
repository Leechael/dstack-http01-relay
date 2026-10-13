use crate::target::{public_ip, valid_domain, TargetPolicy};
use hickory_resolver::{
    config::{LookupIpStrategy, ResolverConfig, ResolverOpts},
    proto::rr::RecordType,
    TokioAsyncResolver,
};
use reqwest::{
    dns::{Addrs, Name, Resolve, Resolving},
    Url,
};
use std::{error::Error, net::SocketAddr, sync::Arc};

type DnsError = Box<dyn Error + Send + Sync>;

/// DNS configuration is operator-owned; DNS records themselves are untrusted.
pub struct DnsResolver {
    resolver: TokioAsyncResolver,
    policy: TargetPolicy,
}

impl DnsResolver {
    pub fn new() -> Result<Self, DnsError> {
        let policy = TargetPolicy::new(&std::env::var("ALLOWED_GATEWAY_DOMAINS")?)?;
        Ok(Self {
            resolver: TokioAsyncResolver::tokio(ResolverConfig::default(), resolver_options()),
            policy,
        })
    }

    async fn lookup_app_address(&self, domain: &str) -> Result<String, DnsError> {
        let response = self
            .resolver
            .txt_lookup(format!("_dstack-app-address.{domain}"))
            .await?;
        let mut records = response.iter();
        let record = records.next().ok_or("missing app TXT record")?;
        if records.next().is_some() {
            return Err("ambiguous app TXT records".into());
        }
        // DNS TXT strings may be split into chunks. Concatenate raw bytes, not escaped Display.
        let bytes: Vec<u8> = record
            .txt_data()
            .iter()
            .flat_map(|part| part.iter().copied())
            .collect();
        let value = String::from_utf8(bytes)?;
        let (app, port) = value.split_once(':').ok_or("expected app-id:port")?;
        // The legacy relay ignored this port and reached the gateway's default guest port 80.
        // Keep that routing, but don't accept arbitrary strings in either field.
        let port = port.parse::<u16>()?;
        if port == 0 {
            return Err("invalid app port".into());
        }
        Ok(app.to_owned())
    }

    async fn lookup_gateway_domain(&self, domain: &str) -> Result<String, DnsError> {
        // Lookup failure is an error, never permission to use a fallback gateway.
        let response = self.resolver.lookup(domain, RecordType::CNAME).await?;
        let mut records = response.record_iter().filter(|record| {
            record
                .name()
                .to_string()
                .trim_end_matches('.')
                .eq_ignore_ascii_case(domain)
                && record.data().and_then(|data| data.as_cname()).is_some()
        });
        let record = records.next().ok_or("missing direct CNAME")?;
        if records.next().is_some() {
            return Err("ambiguous direct CNAME records".into());
        }
        let cname = record
            .data()
            .and_then(|data| data.as_cname())
            .ok_or("expected CNAME")?
            .to_string();
        self.gateway_from_cname(&cname)
    }

    fn gateway_from_cname(&self, cname: &str) -> Result<String, DnsError> {
        // DNS names are case-insensitive; accept one DNS root dot, not arbitrary suffixes.
        let cname = cname
            .strip_suffix('.')
            .unwrap_or(cname)
            .to_ascii_lowercase();
        let gateway = cname
            .strip_prefix("_.")
            .ok_or("CNAME must be _.<approved gateway>")?;
        // Exact membership validates the entire remainder, not a regex/suffix fragment.
        self.policy.gateway(gateway)?;
        Ok(gateway.to_owned())
    }

    pub async fn resolve_app_url(&self, custom_domain: &str, path: &str) -> Result<Url, DnsError> {
        let domain = custom_domain.to_ascii_lowercase();
        if !valid_domain(&domain) || domain.parse::<std::net::IpAddr>().is_ok() {
            return Err("invalid custom domain".into());
        }
        let app = self.lookup_app_address(&domain).await?;
        let gateway = self.lookup_gateway_domain(&domain).await?;
        Ok(self.policy.url(&app, &gateway, path)?)
    }
}

fn resolver_options() -> ResolverOpts {
    let mut options = ResolverOpts::default();
    options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    options
}

/// Validate DNS results in the connector itself: no check-then-resolve rebinding gap.
impl Resolve for DnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.resolver.clone();
        let policy = self.policy.clone();
        let host = name.as_str().to_owned();
        Box::pin(async move {
            policy.host(&host)?;
            let response = resolver.lookup_ip(host).await?;
            checked_addresses(response.iter().map(|ip| SocketAddr::new(ip, 0)).collect())
        })
    }
}

fn checked_addresses(addresses: Vec<SocketAddr>) -> Result<Addrs, DnsError> {
    if addresses.is_empty() || addresses.iter().any(|a| !public_ip(a.ip())) {
        return Err("DNS destination is not exclusively public unicast".into());
    }
    Ok(Box::new(addresses.into_iter()))
}

pub fn http_client(resolver: Arc<DnsResolver>) -> Result<reqwest::Client, reqwest::Error> {
    http_client_builder().dns_resolver(resolver).build()
}

pub fn http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .https_only(true)
        .no_proxy() // Environment proxies would bypass the checked destination resolver.
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn resolver() -> DnsResolver {
        DnsResolver {
            resolver: TokioAsyncResolver::tokio(ResolverConfig::default(), resolver_options()),
            policy: TargetPolicy::new("dstack-pha-prod2.phala.network").unwrap(),
        }
    }

    // invariant: only the exact _.<approved gateway> DNS name is accepted; no fallback.
    #[tokio::test]
    async fn cname_policy() {
        let r = resolver();
        assert_eq!(
            r.gateway_from_cname("_.dstack-pha-prod2.phala.network")
                .unwrap(),
            "dstack-pha-prod2.phala.network"
        );
        assert_eq!(
            r.gateway_from_cname("_.DSTACK-PHA-PROD2.PHALA.NETWORK.")
                .unwrap(),
            "dstack-pha-prod2.phala.network"
        );
        for cname in [
            "_.google.com#.dstack-pha-prod2.phala.network",
            "_.user@dstack-pha-prod2.phala.network",
            "_.evil.phala.network",
            "_.localhost#.dstack-pha-prod2.phala.network",
            "tdx-lab-pub.phala.systems",
            "dstack-pha-prod2.phala.network",
            "_.dstack-pha-prod2.phala.network.evil.com",
            "extra._.dstack-pha-prod2.phala.network",
            "_.dstack-pha-prod2.phala.network..",
            "_.dstack-pha-prod2.phala.network:443",
            "_.dstack-pha-prod2.phala.network/",
        ] {
            assert!(r.gateway_from_cname(cname).is_err(), "{cname}");
        }
    }

    // invariant: the production Resolve implementation sees both families and rejects
    // rebinding/mixed/private answers; no external DNS or network targets are used.
    #[tokio::test]
    async fn connector_dns_policy_with_local_dns() {
        use hickory_resolver::{
            config::NameServerConfigGroup,
            proto::{
                op::{Message, MessageType},
                rr::{
                    rdata::{A, AAAA},
                    RData, Record,
                },
            },
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let phase = Arc::new(AtomicUsize::new(0));
        let p = phase.clone();
        let server = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            loop {
                let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let query = Message::from_vec(&buffer[..len]).unwrap();
                let q = query.queries()[0].clone();
                let mut answer = Message::new();
                answer
                    .set_id(query.id())
                    .set_message_type(MessageType::Response)
                    .set_recursion_desired(true)
                    .set_recursion_available(true)
                    .add_query(q.clone());
                let data = match (p.load(Ordering::SeqCst), q.query_type()) {
                    (1, RecordType::A) => Some(RData::A(A("127.0.0.1".parse().unwrap()))),
                    (_, RecordType::A) => Some(RData::A(A("66.220.6.102".parse().unwrap()))),
                    (2, RecordType::AAAA) => Some(RData::AAAA(AAAA("::1".parse().unwrap()))),
                    (_, RecordType::AAAA) => {
                        Some(RData::AAAA(AAAA("2606:4700:4700::1111".parse().unwrap())))
                    }
                    _ => None,
                };
                if let Some(data) = data {
                    answer.add_answer(Record::from_rdata(q.name().clone(), 0, data));
                }
                socket
                    .send_to(&answer.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let mut r = resolver();
        let mut opts = resolver_options();
        opts.cache_size = 0;
        r.resolver = TokioAsyncResolver::tokio(
            ResolverConfig::from_parts(
                None,
                vec![],
                NameServerConfigGroup::from_ips_clear(&["127.0.0.1".parse().unwrap()], port, false),
            ),
            opts,
        );
        let host = "5b912f5cec6c02d851db76bc20f410700f01fc65.dstack-pha-prod2.phala.network";
        let addresses = r
            .resolve(host.parse().unwrap())
            .await
            .unwrap()
            .collect::<Vec<_>>();
        assert_eq!(addresses.len(), 2);
        assert!(addresses.iter().any(|a| a.is_ipv4()));
        assert!(addresses.iter().any(|a| a.is_ipv6()));
        phase.store(1, Ordering::SeqCst);
        assert_eq!(
            r.resolve(host.parse().unwrap())
                .await
                .err()
                .unwrap()
                .to_string(),
            "DNS destination is not exclusively public unicast"
        );
        phase.store(2, Ordering::SeqCst);
        assert_eq!(
            r.resolve(host.parse().unwrap())
                .await
                .err()
                .unwrap()
                .to_string(),
            "DNS destination is not exclusively public unicast"
        );
        // Actual reqwest connector must fail before connecting to the returned loopback A.
        phase.store(1, Ordering::SeqCst);
        let sink = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sink_port = sink.local_addr().unwrap().port();
        let client = http_client(Arc::new(r)).unwrap();
        // Explicit port is test-only, to count connections; production TargetPolicy rejects ports.
        let error = client
            .get(format!(
                "https://{host}:{sink_port}/.well-known/acme-challenge/abcdefghijklmnopqrstuvwxyz"
            ))
            .send()
            .await
            .unwrap_err();
        assert!(error.is_connect());
        assert!(format!("{error:?}").contains("DNS destination is not exclusively public unicast"));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), sink.accept())
                .await
                .is_err()
        );
        server.abort();
    }

    // invariant: mixed DNS answers fail closed, not just a filtered subset.
    #[test]
    fn dns_answers() {
        let good = "66.220.6.102:443".parse().unwrap();
        let bad = "127.0.0.1:443".parse().unwrap();
        assert_eq!(
            checked_addresses(vec![good]).unwrap().collect::<Vec<_>>(),
            vec![good]
        );
        assert!(checked_addresses(vec![good, bad]).is_err());
        assert!(checked_addresses(vec![]).is_err());
    }
}
