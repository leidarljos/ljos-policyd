//! Approved force-with-lease pushes from the Oct 31 deny log.

use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ljos_policyd::{verdict_with, Context};

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "Test User")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Test User")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .status()
        .unwrap();
    assert!(status.success(), "{args:?} in {}", dir.display());
}

fn repo(dir: &Path, url: &str, head: &str) {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    git(dir, &["init", "-q", "-b", "main"]);
    git(dir, &["remote", "add", "origin", url]);
    git(dir, &["commit", "-q", "--allow-empty", "-m", "empty"]);
    git(dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    git(
        dir,
        &["update-ref", &format!("refs/remotes/origin/{head}"), "HEAD"],
    );
    git(
        dir,
        &[
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            &format!("refs/remotes/origin/{head}"),
        ],
    );
}

fn words(line: &str) -> Vec<String> {
    line.split_whitespace().map(str::to_string).collect()
}

fn py(script: &str) -> Vec<String> {
    vec!["python3".into(), "-c".into(), script.into()]
}

fn check(argv: &[String], consent: Option<&Path>) -> String {
    let ctx = Context {
        consent_file: consent.map(Path::to_path_buf),
        person_tty: Some(false),
        ..Context::default()
    };
    verdict_with(argv, &ctx)
}

fn consent(path: &Path, repo: &str, git_ref: &str) {
    consent_sha(path, repo, git_ref, None);
}

fn consent_sha(path: &Path, repo: &str, git_ref: &str, sha: Option<&str>) {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    if path.exists() {
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).unwrap();
    }
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let mut line = format!(
        "{{\"repo\":\"{repo}\",\"ref\":\"{git_ref}\",\"action\":\"git-force-push\",\"exp\":{exp}"
    );
    if let Some(sha) = sha {
        line.push_str(&format!(",\"sha\":\"{sha}\""));
    }
    line.push_str("}\n");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    file.write_all(line.as_bytes()).unwrap();
}

fn seal(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o400);
    std::fs::set_permissions(path, perms).unwrap();
}

#[test]
fn approved_lease_pushes_follow_the_remote_head_and_consent() {
    let root = std::env::temp_dir().join(format!("policyd-approved-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let eon = root.join("eon");
    let policyd = root.join("policyd-rw");
    let develop_default = root.join("develop-default");
    repo(&eon, "https://github.com/TheochemUI/eOn.git", "main");
    repo(
        &policyd,
        "https://github.com/leidarljos/ljos-policyd.git",
        "main",
    );
    repo(
        &develop_default,
        "https://example.test/develop-default.git",
        "develop",
    );
    // The real log used /tmp/eon-sobfix and /tmp/cs/policyd-rw.
    let eon_link = Path::new("/tmp/eon-sobfix");
    let policyd_link = Path::new("/tmp/cs/policyd-rw");
    let _ = std::fs::remove_dir_all(eon_link);
    let _ = std::fs::remove_dir_all(policyd_link);
    std::fs::create_dir_all("/tmp/cs").unwrap();
    copy_repo(&eon, eon_link);
    copy_repo(&policyd, policyd_link);

    let eon_push = py(
        "import subprocess\nr=subprocess.run([\"git\",\"-c\",\"credential.helper=\",\"push\",\"--force-with-lease=develop:abc\",\"https://github.com/TheochemUI/eOn.git\",\"abc:refs/heads/develop\"],capture_output=True)",
    );
    let eon_cwd = py(
        "import subprocess\nr=subprocess.run(['git','-c','credential.helper=','push','--force-with-lease=refs/heads/develop:abc','origin','abc:refs/heads/develop'],cwd='/tmp/eon-sobfix')",
    );
    let eon_origin = py(
        "import subprocess\nr=subprocess.run(['git','-c','credential.helper=','push','--force-with-lease=refs/heads/develop:abc','origin','abc:refs/heads/develop'])",
    );
    let policyd_push =
        words("git -C /tmp/cs/policyd-rw push --force-with-lease=main:add2bdcc origin main");
    let reach = py(
        "import subprocess\nr=subprocess.run([\"git\",\"-c\",\"credential.helper=\",\"push\",\"--force-with-lease=main:abc\",\"https://github.com/example/app\",\"abc:refs/heads/main\"])",
    );

    let bare = check(&eon_push, None);
    assert!(
        bare.starts_with("allow\twarn\tgit-force-push"),
        "eOn develop is not the default: {bare}"
    );
    assert!(check(&eon_cwd, None).starts_with("allow\twarn\tgit-force-push"));
    assert!(check(&eon_origin, None).starts_with("allow"));
    assert!(check(&policyd_push, None).starts_with("deny\tgit-force-push"));
    assert!(check(&reach, None).starts_with("deny\tgit-force-push"));

    let file = root.join("consent.json");
    consent(&file, "https://github.com/TheochemUI/eOn.git", "develop");
    consent(
        &file,
        "https://github.com/leidarljos/ljos-policyd.git",
        "main",
    );
    consent(&file, "https://github.com/example/app", "main");
    seal(&file);

    assert!(check(&eon_push, Some(&file)).starts_with("allow"));
    assert!(check(&eon_cwd, Some(&file)).starts_with("allow"));
    assert!(check(&eon_origin, Some(&file)).starts_with("allow"));
    let with = check(&policyd_push, Some(&file));
    assert!(
        with.starts_with("allow\tconsent\t"),
        "policyd main needs the matching consent: {with}"
    );
    let reach_ok = check(&reach, Some(&file));
    assert!(
        reach_ok.starts_with("allow\tconsent\t"),
        "example app main: {reach_ok}"
    );

    let only_eon = root.join("eon-only.json");
    consent(
        &only_eon,
        "https://github.com/TheochemUI/eOn.git",
        "develop",
    );
    seal(&only_eon);
    assert!(
        check(&reach, Some(&only_eon)).starts_with("deny\tgit-force-push"),
        "eOn consent does not unlock the example app"
    );
    assert!(check(&policyd_push, Some(&only_eon)).starts_with("deny\tgit-force-push"));

    let only_reach = root.join("reach-only.json");
    consent(&only_reach, "https://github.com/example/app.git", "main");
    seal(&only_reach);
    assert!(check(&policyd_push, Some(&only_reach)).starts_with("deny\tgit-force-push"));
    assert!(check(&reach, Some(&only_reach)).starts_with("allow\tconsent\t"));

    let dev_push = words(&format!(
        "git -C {} push --force-with-lease origin develop",
        develop_default.display()
    ));
    assert!(
        check(&dev_push, None).starts_with("deny\tgit-force-push"),
        "develop is the default when the remote HEAD says so"
    );
    let dev_consent = root.join("dev.json");
    consent(
        &dev_consent,
        "https://example.test/develop-default.git",
        "develop",
    );
    seal(&dev_consent);
    assert!(check(&dev_push, Some(&dev_consent)).starts_with("allow\tconsent\t"));

    let cwd_only = root.join("cwd-only.json");
    consent(
        &cwd_only,
        "https://github.com/leidarljos/ljos-policyd.git",
        "main",
    );
    seal(&cwd_only);
    let other = root.join("other-url");
    repo(&other, "https://example.test/other.git", "main");
    let other_push = words(&format!(
        "git -C {} push --force origin main",
        other.display()
    ));
    assert!(
        check(&other_push, Some(&cwd_only)).starts_with("deny\tgit-force-push"),
        "cwd origin does not match a push whose -C names another repo"
    );
    let stray = py(&format!(
        "import subprocess\nr=subprocess.run([\"git\",\"-C\",\"{}\",\"push\",\"--force\",\"https://example.test/other.git\",\"main\"])\nprint(\"https://github.com/leidarljos/ljos-policyd.git\")",
        other.display()
    ));
    assert!(
        check(&stray, Some(&cwd_only)).starts_with("deny\tgit-force-push"),
        "a :// word that is not the remote does not match"
    );
    let sha = String::from_utf8(
        Command::new("git")
            .args(["-C", other.to_str().unwrap(), "rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let sha = sha.trim().to_string();
    let sha_file = root.join("sha.json");
    consent_sha(
        &sha_file,
        "https://example.test/other.git",
        "main",
        Some(&sha),
    );
    seal(&sha_file);
    assert!(
        check(&other_push, Some(&sha_file)).starts_with("allow\tconsent\t"),
        "head sha is read in the -C directory"
    );
    let wrong = root.join("wrong-sha.json");
    consent_sha(
        &wrong,
        "https://example.test/other.git",
        "main",
        Some("0123456789abcdef0123456789abcdef01234567"),
    );
    seal(&wrong);
    assert!(check(&other_push, Some(&wrong)).starts_with("deny\tgit-force-push"));

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(eon_link);
    let _ = std::fs::remove_dir_all(policyd_link);
}

fn copy_repo(from: &Path, to: &Path) {
    let _ = std::fs::remove_dir_all(to);
    let status = Command::new("cp")
        .args(["-a", from.to_str().unwrap(), to.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());
}
