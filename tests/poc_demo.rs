use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[test]
fn test_poc_demo_command() {
    let socket = "/tmp/lokalvault-test.sock";
    let _ = std::fs::remove_file(socket);

    let mut daemon = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .arg("daemon-poc")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    for _ in 0..100 {
        if Path::new(socket).exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    let output = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .args([
            "run",
            "--",
            "python3",
            "-c",
            "import os; print(os.environ.get('OPENAI_KEY'))",
        ])
        .output()
        .unwrap();

    daemon.kill().unwrap();
    let _ = daemon.wait();
    let _ = std::fs::remove_file(socket);

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "test-value-123\n");
}
