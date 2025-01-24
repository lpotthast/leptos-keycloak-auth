use std::env;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio_process_tools::{Inspector, TerminateOnDrop};

pub struct Frontend {
    #[expect(unused)]
    cargo_leptos_process: TerminateOnDrop,
    #[expect(unused)]
    stdout_replay: Inspector,
    #[expect(unused)]
    stderr_replay: Inspector,
}

pub async fn start_frontend(keycloak_port: u16) -> Frontend {
    let fe_dir = env::current_dir()
        .unwrap()
        .join("../test-frontend")
        .canonicalize()
        .unwrap();

    let dotenv = fe_dir.join(".env");
    tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(dotenv)
        .await
        .unwrap()
        .write_all(format!("KEYCLOAK_PORT={keycloak_port}").as_bytes())
        .await
        .unwrap();

    tracing::info!("Starting frontend in {:?}", fe_dir);
    let mut cmd = Command::new("cargo");
    cmd.arg("leptos")
        .arg("watch") // serve
        .current_dir(fe_dir);

    let fe_process = tokio_process_tools::ProcessHandle::spawn("cargo leptos serve", cmd).unwrap();

    //let stdout_replay = fe_process.stdout().inspect(|line| tracing::info!(line, "cargo leptos out log"));
    //let stderr_replay = fe_process.stderr().inspect(|line| tracing::info!(line, "cargo leptos err log"));
    let stdout_replay = fe_process.stdout().inspect(|line| println!("{line}"));
    let stderr_replay = fe_process.stderr().inspect(|line| eprintln!("{line}"));

    // TODO: Also wait for stderr_line: "warning: build failed, waiting for other jobs to finish..." and fail if it occurs.

    let fe_start_timeout = Duration::from_secs(60 * 10);
    tracing::info!("Waiting {fe_start_timeout:?} for frontend to start...");
    match fe_process
        .stdout()
        .wait_for_with_timeout(
            |line| line.contains("listening on http://127.0.0.1:3000"),
            fe_start_timeout,
        )
        .await
    {
        Ok(_wait_for) => {}
        Err(_elapsed) => {
            tracing::error!("Frontend failed to start in {fe_start_timeout:?}. Expected to see 'listening on http://127.0.0.1:3000' on stdout. Compilation might not be ready yet. A restart might work as it will pick up the previously done compilation work.");
        }
    };
    let fe = fe_process.terminate_on_drop(Duration::from_secs(4), Duration::from_secs(10));

    tracing::info!("Frontend started!");
    Frontend {
        cargo_leptos_process: fe,
        stdout_replay,
        stderr_replay,
    }
}
