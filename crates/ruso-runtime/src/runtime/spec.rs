//! Declarative description of what a program sends: its probes and the check's
//! metadata. The compiler fills these in; the executor reads them.

use crate::contract::{HttpMethod, ObjectBody};

/// One HTTP probe, as declared by an `http` block.
///
/// Every `Option` field means "not stated in the script" and falls back to the
/// executor's configuration rather than to a hardcoded default here. At most
/// one of the body fields is set — the grammar allows only one body form per
/// probe.
#[derive(Debug, Clone, PartialEq)]
pub struct HttpRequestSpec {
    /// Request method. Defaults to `GET`.
    pub method: HttpMethod,
    /// Request path, resolved against the scan target's base URL. May contain
    /// `{{ var }}` placeholders.
    pub path: String,
    /// Per-probe timeout as a duration literal (`"5s"`); `None` uses the
    /// executor's timeout.
    pub timeout: Option<String>,
    /// Whether to follow redirects; `None` uses the executor's setting.
    pub follow_redirect: Option<bool>,
    /// Whether to verify the TLS certificate; `None` uses the executor's
    /// setting. Set to `false` only for checks that must reach a host with a
    /// broken chain.
    pub verify_ssl: Option<bool>,
    /// Proxy URL for this probe; `None` uses the executor's proxy, if any.
    pub proxy: Option<String>,
    /// `User-Agent` override for this probe.
    pub user_agent: Option<String>,
    /// Extra request headers, in source order.
    pub headers: Vec<(String, String)>,
    /// Request cookies, in source order.
    pub cookies: Vec<(String, String)>,
    /// Query-string parameters appended to `path`, in source order.
    pub queries: Vec<(String, String)>,
    /// A `data { … }` body, sent form-urlencoded.
    pub data_body: Option<ObjectBody>,
    /// A `json { … }` body, sent as `application/json`.
    pub json_body: Option<ObjectBody>,
    /// A raw string body, sent verbatim.
    pub raw_body: Option<String>,
    /// A hex-encoded byte body, for non-UTF-8 payloads.
    pub body_bytes: Option<String>,
    /// A `multipart { … }` body, sent as `multipart/form-data`.
    pub multipart_body: Option<ObjectBody>,
}

impl Default for HttpRequestSpec {
    fn default() -> Self {
        Self {
            method: HttpMethod::Get,
            path: "/".into(),
            timeout: None,
            follow_redirect: None,
            verify_ssl: None,
            proxy: None,
            user_agent: None,
            headers: Vec::new(),
            cookies: Vec::new(),
            queries: Vec::new(),
            data_body: None,
            json_body: None,
            raw_body: None,
            body_bytes: None,
            multipart_body: None,
        }
    }
}

/// Generic socket options (shared by dns/tcp/udp probes).
#[derive(Debug, Clone, PartialEq)]
pub struct SocketProbeSpec {
    /// Target host. Often `{{scan_host}}` so it follows the CLI `--target`.
    pub host: String,
    /// Target port. Required at runtime for `tcp`/`udp`; for `dns`, its
    /// presence selects wire mode over the OS resolver.
    pub port: Option<u16>,
    /// Optional payload bytes to send on connect.
    pub payload: Option<Vec<u8>>,
    /// TLS handshake before application data (TCP only).
    pub tls: bool,
    /// Keep connection open across multiple `send` on the same probe name.
    pub session: bool,
    /// Maximum bytes to read per exchange (default 65536).
    pub read_max: u32,
    /// After first read, keep reading until idle for this many ms (0 = single read).
    pub read_idle_ms: u32,
}

impl Default for SocketProbeSpec {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: None,
            payload: None,
            tls: false,
            session: false,
            read_max: 65_536,
            read_idle_ms: 0,
        }
    }
}

/// A probe definition, tagged by transport.
#[derive(Debug, Clone, PartialEq)]
pub enum ProbeKind {
    /// HTTP/HTTPS request.
    Http(HttpRequestSpec),
    /// DNS probe — OS resolver or wire mode (see [`SocketProbeSpec`]).
    Dns(SocketProbeSpec),
    /// Raw TCP (optionally TLS).
    Tcp(SocketProbeSpec),
    /// Raw UDP.
    Udp(SocketProbeSpec),
}

/// The `metadata { … }` block of a check — describes the finding it emits.
///
/// Only `name` is required to emit a finding; the rest enriches the report and
/// is needed to publish to the registry.
#[derive(Debug, Clone, Default)]
pub struct CheckMetadata {
    /// Short finding title (the registry slug derives from this).
    pub name: Option<String>,
    /// What the check does.
    pub description: Option<String>,
    /// The risk if the check is positive.
    pub impact: Option<String>,
    /// Finding severity (defaults to `Info` when unset).
    pub severity: Option<crate::contract::Severity>,
    /// Check author.
    pub author: Option<String>,
    /// Associated CVE identifiers.
    pub cve: Vec<String>,
    /// Associated CWE identifiers.
    pub cwe: Vec<String>,
    /// Reference URLs (advisories, docs).
    pub references: Vec<String>,
    /// CVSS vector strings (e.g. base + temporal).
    pub cvss: Vec<String>,
    /// CVSS numeric scores.
    pub cvss_score: Vec<String>,
    /// Single free-text remediation note. The language rejects more than one
    /// `mitigation` line per script at compile time (unlike `cve`/`cwe`/
    /// `references`/`tags`, which accumulate into lists).
    pub mitigation: Option<String>,
    /// Free-form discovery labels (many per check).
    pub tags: Vec<String>,
    /// SemVer string; required at publish time, optional for local use.
    pub version: Option<String>,
    /// Single curated category (e.g. `web`, `network`, `database`).
    /// Distinct from `tags`: one-per-script, used for "scan everything
    /// in this family" selection. The allowed set is enforced by the
    /// registry at publish time, not here.
    pub family: Option<String>,
}

/// The non-executable part of a compiled program: the probe table and the
/// finding metadata. The instruction stream lives in [`BytecodeProgram`].
///
/// [`BytecodeProgram`]: crate::BytecodeProgram
#[derive(Debug, Clone)]
pub struct ProgramSpec {
    /// Probes keyed by their script name (e.g. `home`, `redis`).
    pub probes: std::collections::HashMap<String, ProbeKind>,
    /// The check's finding metadata.
    pub metadata: CheckMetadata,
}

impl SocketProbeSpec {
    /// True when this spec uses the OS resolver (a `dns` probe with neither
    /// `port` nor `payload`) rather than DNS wire mode.
    pub fn is_dns_resolver_mode(&self) -> bool {
        self.port.is_none() && self.payload.is_none()
    }
}
