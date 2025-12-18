use std::env;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio_process_tools::broadcast::BroadcastOutputStream;
use tokio_process_tools::{Inspector, LineParsingOptions, Next, Process, TerminateOnDrop};

pub struct Frontend {
    #[expect(unused)]
    cargo_leptos_process: TerminateOnDrop<BroadcastOutputStream>,
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

    tracing::info!("Starting frontend in {fe_dir:?}");
    let mut cmd = Command::new("cargo");
    cmd.arg("leptos")
        .arg("watch") // serve
        .current_dir(fe_dir);

    let fe_process = Process::new(cmd)
        .spawn_broadcast()
        .unwrap()
        .terminate_on_drop(Duration::from_secs(3), Duration::from_secs(8));

    let stdout_replay = fe_process.stdout().inspect_lines(
        |line| {
            // Only visible when tests are run with the `--nocapture` flag.
            println!("{line}");
            Next::Continue
        },
        LineParsingOptions::default(),
    );
    let stderr_replay = fe_process.stderr().inspect_lines(
        |line| {
            // Only visible when tests are run with the `--nocapture` flag.
            eprintln!("{line}");
            Next::Continue
        },
        LineParsingOptions::default(),
    );

    // TODO: Also wait for stderr_line: "warning: build failed, waiting for other jobs to finish..." and fail if it occurs.

    let fe_start_timeout = Duration::from_secs(60 * 10);
    tracing::info!("Waiting {fe_start_timeout:?} for frontend to start...");
    match fe_process
        .stdout()
        .wait_for_line_with_timeout(
            |line| line.contains("listening on http://127.0.0.1:3000"),
            LineParsingOptions::default(),
            fe_start_timeout,
        )
        .await
    {
        Ok(_wait_for) => {}
        Err(_elapsed) => {
            tracing::error!(
                "Frontend failed to start in {fe_start_timeout:?}. Expected to see 'listening on http://127.0.0.1:3000' on stdout. Compilation might not be ready yet. A restart might work as it will pick up the previously done compilation work."
            );
        }
    }

    tracing::info!("Frontend started!");
    Frontend {
        cargo_leptos_process: fe_process,
        stdout_replay,
        stderr_replay,
    }
}
