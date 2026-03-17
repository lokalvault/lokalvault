use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn wait_for_socket_or_exit(socket: &Path, child: &mut std::process::Child) -> bool {
    for _ in 0..100 {
        if socket.exists() {
            return true;
        }
        if child.try_wait().unwrap().is_some() {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn test_poc_demo_command() {
    let socket = Path::new("/tmp").join(format!("lokalvault-poc-demo-{}.sock", std::process::id()));
    let socket_string = socket.to_string_lossy().to_string();
    let _ = std::fs::remove_file(&socket);
    unsafe { std::env::set_var("LOKALVAULT_TEST_POC_SOCKET", &socket_string) };

    let mut daemon = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .arg("daemon-poc")
        .stdout(Stdio::null())
        .env("LOKALVAULT_TEST_POC_SOCKET", &socket_string)
        .spawn()
        .unwrap();

    if !wait_for_socket_or_exit(&socket, &mut daemon) {
        let _ = daemon.wait();
        let _ = std::fs::remove_file(&socket);
        unsafe { std::env::remove_var("LOKALVAULT_TEST_POC_SOCKET") };
        return;
    }

    let output = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .env("LOKALVAULT_TEST_POC_SOCKET", &socket_string)
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
    let _ = std::fs::remove_file(&socket);
    unsafe { std::env::remove_var("LOKALVAULT_TEST_POC_SOCKET") };

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "test-value-123\n");
}
