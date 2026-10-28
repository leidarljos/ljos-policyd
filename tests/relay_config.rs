//! The relay the config file names may hand its python one secret, from
//! the vault, and only to read. With no config file there is no relay.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn verdict(dir: &Path, config: &Path, seat: &str, line: &str) -> String {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ljos-policyd"))
        .args(["check", "--", "bash", "-c", line])
        .current_dir(dir)
        .stdin(std::process::Stdio::null())
        .env("PHRONESIS_STATE_DIR", dir.join("state"))
        .env("LJOS_POLICYD_CONFIG", config)
        .env("LJOS_SEAT", seat)
        .env_remove("PHRONESIS_WORKSPACE")
        .env_remove("PHRONESIS_JANET_PACK")
        .env_remove("PHRONESIS_PREFIX")
        .env_remove("PHRONESIS_PACK_ROOT")
        .env_remove("CDPATH")
        .env_remove("BASH_ENV")
        .env_remove("ENV")
        .output()
        .expect("spawn check");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn the_configured_relay_reads_its_secret_from_the_vault() {
    let base = std::env::temp_dir().join(format!("relay-config-{}", std::process::id()));
    let dir = base.join("relay");
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    let config = base.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "[relay]\nseat = \"relay\"\ndir = \"{}\"\nsecret = \"EXAMPLE_TOKEN\"\n",
            dir.display()
        ),
    )
    .unwrap();
    let mode = |m: u32| std::fs::set_permissions(&config, std::fs::Permissions::from_mode(m));
    mode(0o600).unwrap();
    let read = r#"import os; t = os.environ["EXAMPLE_TOKEN"]"#;
    let run =
        |code: &str| format!("nimvault run --env EXAMPLE_TOKEN relay/token python3 -c '{code}'");
    let used = run(&format!("{read}; print(len(t))"));
    assert_eq!(verdict(&dir, &config, "relay", &used), "allow");

    let refused = |dir: &Path, config: &Path, seat: &str, line: &str| {
        let v = verdict(dir, config, seat, line);
        assert!(v.starts_with("deny"), "{line}: {v}");
        v
    };
    let shown = refused(
        &dir,
        &config,
        "relay",
        &run(r#"import os; print(os.environ["EXAMPLE_TOKEN"])"#),
    );
    assert!(shown.contains("shows-secret"), "{shown}");
    for line in [
        format!("cd . && {used}"),
        format!("python3 -c '{read}; print(len(t))'"),
        format!(". ./env && python3 -c '{read}; print(len(t))'"),
        used.replace("python3 -c", "/usr/bin/python3 -c"),
        used.replace("EXAMPLE_TOKEN", "OTHER_TOKEN"),
    ] {
        refused(&dir, &config, "relay", &line);
    }
    refused(&dir, &config, "other", &used);
    refused(&dir.join("sub"), &config, "relay", &used);
    refused(&dir, &base.join("missing.toml"), "relay", &used);
    mode(0o620).unwrap();
    refused(&dir, &config, "relay", &used);
    mode(0o602).unwrap();
    refused(&dir, &config, "relay", &used);
    let _ = std::fs::remove_dir_all(&base);
}
