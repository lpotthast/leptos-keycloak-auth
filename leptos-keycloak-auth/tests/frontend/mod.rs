use std::env;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio_process_tools::TerminateOnDrop;

pub async fn start_frontend(keycloak_port: u16) -> TerminateOnDrop {
    let fe_dir = env::current_dir().unwrap().join("../test-frontend").canonicalize().unwrap();

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
    let fe = Command::new("cargo")
        .arg("leptos")
        .arg("watch") // serve
        .current_dir(fe_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let fe_process =
        tokio_process_tools::ProcessHandle::new_from_child_with_piped_io("cargo leptos serve", fe);

    let _out_inspector = fe_process
        .stdout()
        .inspect(|stdout_line| tracing::info!(stdout_line, "cargo leptos log"));
    let _err_inspector = fe_process
        .stderr()
        .inspect(|stderr_line| tracing::info!(stderr_line, "cargo leptos log"));

    // TODO: Also wait for stderr_line: "warning: build failed, waiting for other jobs to finish..." and fail it it occurs.

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
    let fe =
        fe_process.terminate_on_drop(Some(Duration::from_secs(10)), Some(Duration::from_secs(10)));

    tracing::info!("Frontend started!");
    fe
}
