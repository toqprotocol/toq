use crate::constants::{DEFAULT_PORT, DNS_PROTOCOL_ID, DNS_SERVICE_PREFIX};
use crate::error::Error;
use crate::types::Address;

/// A parsed toq DNS TXT record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub agent_name: String,
    pub public_key_b64: String,
    pub port: u16,
}

/// An agent discovered via DNS or mDNS.
#[derive(Debug, Clone)]
pub struct DiscoveredAgent {
    pub address: Address,
    pub public_key_b64: String,
}

/// Build the DNS query name for a domain: `_toq._tcp.<domain>`
pub fn query_name(domain: &str) -> String {
    format!("{DNS_SERVICE_PREFIX}{domain}")
}

/// Parse a toq TXT record value.
/// Format: `v=toq1; key=<base64>; port=9009; agent=<name>`
pub fn parse_txt_record(txt: &str) -> Result<DnsRecord, Error> {
    let mut version = None;
    let mut key = None;
    let mut port = DEFAULT_PORT;
    let mut agent = None;

    for part in txt.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            match k.trim() {
                "v" => version = Some(v.trim().to_string()),
                "key" => key = Some(v.trim().to_string()),
                "port" => {
                    port = v
                        .trim()
                        .parse()
                        .map_err(|_| Error::InvalidAddress("invalid port in DNS record".into()))?;
                }
                "agent" => agent = Some(v.trim().to_string()),
                _ => {} // ignore unknown fields
            }
        }
    }

    let version =
        version.ok_or_else(|| Error::InvalidAddress("missing v= in DNS record".into()))?;
    if version != DNS_PROTOCOL_ID {
        return Err(Error::InvalidAddress(format!(
            "unsupported DNS protocol version: {version}"
        )));
    }

    let public_key_b64 =
        key.ok_or_else(|| Error::InvalidAddress("missing key= in DNS record".into()))?;
    let agent_name =
        agent.ok_or_else(|| Error::InvalidAddress("missing agent= in DNS record".into()))?;

    Ok(DnsRecord {
        agent_name,
        public_key_b64,
        port,
    })
}

/// Convert a parsed DNS record into a DiscoveredAgent for a given domain.
pub fn to_discovered_agent(domain: &str, record: &DnsRecord) -> Result<DiscoveredAgent, Error> {
    let address = Address::with_port(domain, record.port, &record.agent_name)?;
    Ok(DiscoveredAgent {
        address,
        public_key_b64: record.public_key_b64.clone(),
    })
}
