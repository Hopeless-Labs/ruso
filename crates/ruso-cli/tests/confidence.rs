//! End-to-end checks for the `confidence` metadata field: the real `ruso`
//! binary scans a throwaway HTTP server on loopback, and the field has to
//! survive source → bytecode → finding → console/report.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A loopback HTTP server that answers every request with `200 OK`. Returns
/// its base URL; the accept thread lives until the test process exits.
fn spawn_ok_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let body = "ruso-e2e-ok";
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
    format!("http://127.0.0.1:{port}")
}

/// A fresh, empty directory unique to one test.
fn scratch_dir(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ruso-confidence-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// Write a check that always detects against [`spawn_ok_server`], declaring
/// `confidence` when given one.
fn write_script(dir: &Path, name: &str, confidence: Option<&str>) -> PathBuf {
    let confidence = confidence
        .map(|level| format!("    confidence {level}\n"))
        .unwrap_or_default();
    let source = format!(
        "metadata {{\n    name \"{name}\"\n    severity high\n{confidence}}}\n\n\
         http home {{\n    method GET\n    path \"/\"\n    timeout 5s\n}}\n\n\
         send home\n\nmatch home.body contains \"ruso-e2e-ok\"\n"
    );
    let path = dir.join(format!("{name}.rsl"));
    std::fs::write(&path, source).expect("write script");
    path
}

fn ruso(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ruso"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("run ruso")
}

/// The `findings` of the single target in a JSON report.
fn findings(report: &Path) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(report).expect("read report");
    let json: serde_json::Value = serde_json::from_str(&text).expect("report is JSON");
    json["targets"][0]["findings"]
        .as_array()
        .expect("findings array")
        .clone()
}

#[test]
fn scan_carries_confidence_to_console_json_and_csv() {
    let target = spawn_ok_server();
    let dir = scratch_dir("report");
    let script = write_script(&dir, "firm-check", Some("firm"));
    let json = dir.join("out.json");
    let csv = dir.join("out.csv");

    let out = ruso(&[
        "scan",
        "--script",
        script.to_str().unwrap(),
        "--target",
        &target,
        "--report",
        json.to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("firm-check  (firm)"),
        "finding line should end with the confidence, got:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let found = findings(&json);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["name"], "firm-check");
    assert_eq!(found[0]["confidence"], "firm");

    ruso(&[
        "scan",
        "--script",
        script.to_str().unwrap(),
        "--target",
        &target,
        "--report",
        csv.to_str().unwrap(),
    ]);
    let csv_text = std::fs::read_to_string(&csv).expect("read csv");
    let mut lines = csv_text.lines();
    let header: Vec<&str> = lines.next().expect("csv header").split(',').collect();
    let row: Vec<&str> = lines.next().expect("csv row").split(',').collect();
    let column = header
        .iter()
        .position(|h| *h == "confidence")
        .expect("confidence column");
    assert_eq!(row[column], "firm");
}

#[test]
fn scan_omits_confidence_when_the_script_declares_none() {
    let target = spawn_ok_server();
    let dir = scratch_dir("unset");
    let script = write_script(&dir, "plain-check", None);
    let json = dir.join("out.json");

    let out = ruso(&[
        "scan",
        "--script",
        script.to_str().unwrap(),
        "--target",
        &target,
        "--report",
        json.to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("plain-check"), "got:\n{stdout}");
    assert!(!stdout.contains("plain-check  ("), "got:\n{stdout}");

    let found = findings(&json);
    assert_eq!(found.len(), 1);
    assert!(found[0].get("confidence").is_none());
}

#[test]
fn min_confidence_runs_only_scripts_at_or_above_the_level() {
    let target = spawn_ok_server();
    let dir = scratch_dir("filter");
    let scripts = dir.join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    write_script(&scripts, "tentative-check", Some("tentative"));
    write_script(&scripts, "firm-check", Some("firm"));
    write_script(&scripts, "certain-check", Some("certain"));
    write_script(&scripts, "plain-check", None);
    let json = dir.join("out.json");

    let out = ruso(&[
        "scan",
        "--script",
        scripts.to_str().unwrap(),
        "--target",
        &target,
        "--min-confidence",
        "firm",
        "--report",
        json.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("skipped 2 of 4 script(s)"),
        "expected a skip warning, got:\n{stderr}"
    );

    let mut names: Vec<String> = findings(&json)
        .iter()
        .map(|f| f["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    assert_eq!(names, ["certain-check", "firm-check"]);
}

#[test]
fn exec_honours_min_confidence_on_compiled_bytecode() {
    let target = spawn_ok_server();
    let dir = scratch_dir("exec");
    let script = write_script(&dir, "tentative-check", Some("tentative"));
    let compiled = ruso(&["compile", "--script", script.to_str().unwrap()]);
    assert!(compiled.status.success(), "compile failed");
    let bytecode = script.with_extension("rbc");
    let json = dir.join("out.json");

    // Below the threshold: nothing runs.
    let out = ruso(&[
        "exec",
        "--bytecode",
        bytecode.to_str().unwrap(),
        "--target",
        &target,
        "--min-confidence",
        "certain",
    ]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("skipped 1 of 1 script(s)"));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("tentative-check"));

    // At the threshold: it runs, and the level survived the bytecode round trip.
    ruso(&[
        "exec",
        "--bytecode",
        bytecode.to_str().unwrap(),
        "--target",
        &target,
        "--min-confidence",
        "tentative",
        "--report",
        json.to_str().unwrap(),
    ]);
    let found = findings(&json);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["confidence"], "tentative");
}
