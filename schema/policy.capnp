# Argv-plane subset of phronesis schema/policy.capnp.
# Decision, PolicyReason, PolicyDecision, and checkShell(argv) follow
# that file. Seat / model / audio / AgentId are not in this crate.
#
# Copyright 2026 indynull, HaoZeke (phronesis, MIT).
# Copyright 2026 leiðarljós contributors (this subset).

@0x9b7c4d2e1a0f83c1;

enum Decision {
  deny @0;
  allow @1;
  prompt @2;
}

enum PolicyReason {
  unspecified @0;
  emptyArgv @1;
  shellPrivilegeDenied @2;
  shellRemoteExec @3;
  rmRfOutsideTmp @4;
  shellGitDangerous @5;
  chmodSetuid @6;
  rawDisk @7;
}

struct PolicyDecision {
  decision @0 :Decision;
  reason @1 :Text;
  code @2 :PolicyReason;
}

struct ShellCheck {
  argv @0 :List(Text);
}

interface Policyd {
  checkShell @0 (check :ShellCheck) -> (decision :PolicyDecision);
}
