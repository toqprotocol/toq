//! DNS TXT record lookup for agent discovery.

use crate::discovery::{DnsRecord, parse_txt_record};
use crate::error::Error;

/// Look up all toq TXT records for a domain.
///
/// Queries `_toq._tcp.<domain>` and parses each valid record.
/// Returns an empty vec if no records are found or DNS lookup fails.
pub async fn lookup_txt(domain: &str) -> Result<Vec<DnsRecord>, Error> {
    let query = crate::discovery::query_name(domain);

    let resolver = hickory_resolver::Resolver::builder_tokio()
        .map_err(|e| Error::Io(format!("DNS resolver init failed: {e}")))?
        .build();

    let response = resolver
        .txt_lookup(&query)
        .await
        .map_err(|e| Error::Io(format!("DNS TXT lookup failed for {query}: {e}")))?;

    let mut records = Vec::new();
    for txt in response.iter() {
        let value = txt.to_string();
        if let Ok(record) = parse_txt_record(&value) {
            records.push(record);
        }
    }

    Ok(records)
}

/// Look up a specific agent's DNS record at a domain.
///
/// Returns `None` if no matching record is found.
pub async fn lookup_agent(domain: &str, agent_name: &str) -> Result<Option<DnsRecord>, Error> {
    let records = lookup_txt(domain).await?;
    Ok(records.into_iter().find(|r| r.agent_name == agent_name))
}
