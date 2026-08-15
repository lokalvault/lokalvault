use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

/// Why the test stopped waiting for the `daemon-poc` socket.
///
/// Anything other than [`SocketWait::Ready`] means the end-to-end path was
/// never exercised, so the test must fail loudly rather than skip silently.
#[derive(Debug)]
enum SocketWait {
    Ready,
    DaemonExited(std::process::ExitStatus),
    TimedOut,
}

fn wait_for_socket_or_exit(socket: &Path, child: &mut std::process::Child) -> SocketWait {
    for _ in 0..100 {
        if socket.exists() {
            return SocketWait::Ready;
        }
        if let Some(status) = child.try_wait().unwrap() {
            return SocketWait::DaemonExited(status);
        }
        thread::sleep(Duration::from_millis(20));
    }
    SocketWait::TimedOut
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

    let wait_result = wait_for_socket_or_exit(&socket, &mut daemon);
    if !matches!(wait_result, SocketWait::Ready) {
        // Kill before waiting: on the timeout path the daemon is still alive,
        // and a bare wait() would block forever.
        let _ = daemon.kill();
        let _ = daemon.wait();
        let _ = std::fs::remove_file(&socket);
        unsafe { std::env::remove_var("LOKALVAULT_TEST_POC_SOCKET") };
        panic!(
            "daemon-poc never exposed its socket at {}, so the POC end-to-end \
             path was never exercised ({})",
            socket.display(),
            match wait_result {
                SocketWait::DaemonExited(status) => format!("daemon exited early with {status}"),
                SocketWait::TimedOut => "timed out after 2s".to_string(),
                SocketWait::Ready => unreachable!(),
            }
        );
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
