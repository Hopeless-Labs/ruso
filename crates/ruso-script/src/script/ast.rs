//! The abstract syntax tree the parser produces and the compiler consumes.
//!
//! An RSL script is a flat list of [`Stmt`]s executed top to bottom; the only
//! nesting comes from `if` and `for`, which carry their own bodies. Everything
//! that also has to survive into bytecode — matchers, bodies, severities — is
//! re-exported from [`ruso_runtime::contract`] rather than redefined here, so
//! the parser and the VM cannot drift apart.

pub use ruso_runtime::contract::{
    BodyValue, CmpOp, CmpValue, EvidenceKind, ExtractSource, FieldKind, HttpMethod, InlinePart,
    InlinePartBody, MatchPredicate, ObjectBody, QualifiedField, QualifiedMatch, Severity,
};

/// A parsed script: every statement in source order.
#[derive(Debug, Clone, PartialEq)]
pub struct Program {
    /// Top-level statements, including metadata and probe definitions.
    pub statements: Vec<Stmt>,
}

/// Generic socket probe fields shared by `dns`, `tcp`, and `udp`.
#[derive(Debug, Clone, PartialEq)]
pub struct SocketProbe {
    /// The probe's name, used to reference its response (`p.response`).
    pub name: String,
    /// Target host. May be a `{{ var }}` placeholder such as `{{scan_host}}`,
    /// resolved from the scan target at send time.
    pub host: String,
    /// Target port. `None` on a `dns` probe means resolver mode (ask the system
    /// resolver) rather than a wire-protocol query to a specific port.
    pub port: Option<u16>,
    /// UTF-8 text or raw bytes (from `payload "..."` or `payload "aabbcc"` hex).
    pub payload: Option<Vec<u8>>,
    /// Wrap the connection in TLS.
    pub tls: bool,
    /// Keep the connection open after this probe so later sends to the same
    /// probe reuse it, instead of reconnecting.
    pub session: bool,
    /// Maximum number of response bytes to read.
    pub read_max: u32,
    /// How long to wait for more data, in milliseconds, before treating the
    /// response as complete.
    pub read_idle_ms: u32,
}

/// The right-hand side of a `set`.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// A single string, possibly containing `{{ var }}` placeholders.
    String(String),
    /// A list literal.
    List(Vec<String>),
}

/// What a `for … in …` loop iterates over.
#[derive(Debug, Clone, PartialEq)]
pub enum ListSource {
    /// An inline list literal: `for p in ["/a", "/b"]`.
    Literal(Vec<String>),
    /// A previously `set` list variable: `for p in paths`.
    Variable(String),
}

/// One statement of a script.
///
/// The first group of variants is metadata — declarations that describe the
/// check rather than doing anything — and is recognized by
/// [`Stmt::is_metadata`]. The rest define probes, control flow, matching, and
/// the finding the check emits.
#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    /// `name "…"` — the finding's title.
    Name(String),
    /// `description "…"` — what the check looks for.
    Description(String),
    /// `impact "…"` — what an affected target is exposed to.
    Impact(String),
    /// `severity …` — the finding's severity; defaults to `info` when absent.
    Severity(Severity),
    /// `author "…"` — who wrote the check.
    Author(String),
    /// `cve "…"` — a CVE id the check detects. May be repeated.
    Cve(String),
    /// `cwe "…"` — a CWE id for the weakness class. May be repeated.
    Cwe(String),
    /// `reference "…"` — a supporting URL. May be repeated.
    Reference(String),
    /// `cvss "…"` — a CVSS vector string. May be repeated.
    Cvss(String),
    /// `cvss_score "…"` — a numeric CVSS score. May be repeated.
    CvssScore(String),
    /// `mitigation "…"` — how to fix the issue.
    Mitigation(String),
    /// `tag "…"` — a search tag in the registry. May be repeated.
    Tag(String),
    /// `version "…"` — the check's own version.
    Version(String),
    /// `family "…"` — the family the check belongs to, as used by
    /// `ruso scan --family`.
    Family(String),

    /// `set <name> = <value>` — bind a variable.
    Set {
        /// Variable name.
        name: String,
        /// The value bound to it.
        value: Value,
    },

    /// `for <item> in <list> { … }` — iterate, rebinding `item` each pass.
    ForIn {
        /// The loop variable.
        item: String,
        /// What is iterated.
        list: ListSource,
        /// Statements run per iteration.
        body: Vec<Stmt>,
    },

    /// `http <name> { … }` — define an HTTP probe.
    Http {
        /// The probe's name, used to reference its response (`p.status`).
        name: String,
        /// The probe's settings, in source order.
        items: Vec<HttpItem>,
    },
    /// `dns <name> { … }` — define a DNS probe.
    Dns(SocketProbe),
    /// `tcp <name> { … }` — define a TCP probe.
    Tcp(SocketProbe),
    /// `udp <name> { … }` — define a UDP probe.
    Udp(SocketProbe),
    /// `send <probe>` — fire a defined probe, optionally overriding its body.
    Send {
        /// Name of the probe to send.
        probe: String,
        /// Payload that replaces the probe's own body for this send.
        payload: Option<Vec<u8>>,
    },
    /// `break` — leave the enclosing `for`.
    Break,

    /// `match …` — evaluate one condition; a false result clears the run's
    /// match state so no finding is emitted, but execution continues.
    Match(QualifiedMatch),
    /// `match_all [ … ]` — true only if every condition holds.
    MatchAll(Vec<QualifiedMatch>),
    /// `match_any [ … ]` — true if any condition holds.
    MatchAny(Vec<QualifiedMatch>),
    /// `assert …` — like `match`, but a false result aborts the script.
    Assert(QualifiedMatch),

    /// `extract <name> from …` — bind part of a response to a variable.
    Extract {
        /// Variable to bind.
        name: String,
        /// Where the value comes from: a body regex or a named header.
        source: ExtractSource,
    },

    /// `if <condition> { … }` — run the body only when the condition holds.
    If {
        /// The condition tested.
        condition: QualifiedMatch,
        /// Statements run when it holds.
        body: Vec<Stmt>,
    },

    /// `save <request> as <alias>` — make a response reachable under a second
    /// name, so a later matcher can refer to an earlier probe's result.
    Save {
        /// The probe whose response is saved.
        request: String,
        /// The additional name it becomes reachable under.
        alias: String,
    },

    /// `evidence <probe>.body | .response | .header "…"` — attach proof to the
    /// finding, optionally narrowed by a regex.
    Evidence(EvidenceKind),

    /// `stop` — end the run without emitting a finding.
    Stop,
    /// `fail` — end the run and mark it failed.
    Fail,
    /// `continue` — skip to the next iteration of the enclosing `for`.
    Continue,
    /// `exit` — end the run immediately.
    Exit,

    /// `retry <request> <count>` — re-send a probe while it keeps failing.
    Retry {
        /// The probe to re-send.
        request: String,
        /// Maximum number of attempts.
        count: u32,
    },
    /// `retry_delay "<duration>"` — wait between retry attempts.
    RetryDelay(String),
    /// `sleep "<duration>"` — pause the run.
    Sleep(String),
}

impl Stmt {
    /// Whether this statement only describes the check (its name, severity,
    /// references, …) rather than doing anything at run time.
    ///
    /// The compiler collects these into the program's metadata instead of
    /// emitting instructions for them.
    pub fn is_metadata(&self) -> bool {
        matches!(
            self,
            Self::Name(_)
                | Self::Description(_)
                | Self::Impact(_)
                | Self::Severity(_)
                | Self::Author(_)
                | Self::Cve(_)
                | Self::Cwe(_)
                | Self::Reference(_)
                | Self::Cvss(_)
                | Self::CvssScore(_)
                | Self::Mitigation(_)
                | Self::Tag(_)
                | Self::Version(_)
                | Self::Family(_)
        )
    }

    /// Whether this statement defines a probe (`http`, `dns`, `tcp`, `udp`).
    ///
    /// Probe definitions go into the program's probe table; they do not run
    /// until a `send` names them.
    pub fn is_probe_definition(&self) -> bool {
        matches!(
            self,
            Self::Http { .. } | Self::Dns(_) | Self::Tcp(_) | Self::Udp(_)
        )
    }
}

/// One setting inside an `http` block.
///
/// Items appear in source order and are folded into the runtime's
/// `HttpRequestSpec` by the compiler. Anything not stated falls back to the
/// executor's configuration.
#[derive(Debug, Clone, PartialEq)]
pub enum HttpItem {
    /// `method GET` — the request method. Defaults to `GET`.
    Method(HttpMethod),
    /// `path "/…"` — the request path, resolved against the scan target.
    Path(String),
    /// `timeout "5s"` — a per-probe timeout.
    Timeout(String),
    /// `follow_redirect true|false` — whether to follow redirects.
    FollowRedirect(bool),
    /// `verify_ssl true|false` — whether to verify the TLS certificate.
    VerifySsl(bool),
    /// `proxy "…"` — route this probe through a proxy.
    Proxy(String),
    /// `user_agent "…"` — override the `User-Agent`.
    UserAgent(String),
    /// `header "<name>" "<value>"` — add a request header.
    Header {
        /// Header name.
        name: String,
        /// Header value; may interpolate variables.
        value: String,
    },
    /// `cookie "<name>" "<value>"` — add a request cookie.
    Cookie {
        /// Cookie name.
        name: String,
        /// Cookie value; may interpolate variables.
        value: String,
    },
    /// `query "<name>" "<value>"` — add a query-string parameter.
    Query {
        /// Parameter name.
        name: String,
        /// Parameter value; may interpolate variables.
        value: String,
    },
    /// `data { … }` — a form-urlencoded body.
    Data(ObjectBody),
    /// `json { … }` — a JSON body.
    Json(ObjectBody),
    /// `raw "…"` — a body sent verbatim.
    Raw(String),
    /// `body_bytes "aabbcc"` — a hex-encoded binary body.
    BodyBytes(String),
    /// `multipart { … }` — a `multipart/form-data` body.
    Multipart(ObjectBody),
}
