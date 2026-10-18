/* Build a phronesis ShellCheck with c-capnproto and call phronesis_check_shell.
 * Rust capnp::serialize is a different wire than capn_init_mem.
 *
 * phronesis copies every argv word into a char[PHRONESIS_PATH_MAX] (512,
 * src/policy_janet.c phronesis_build_shell_view) and refuses a Cap'n body
 * over PHRONESIS_CAPNP_MAX_BODY (64 KiB, src/capnp_api.c open_in). A word
 * is not a path. build.rs weakens those two symbols and the definitions
 * at the bottom of this file replace them, so a long word is judged on
 * its text. Past ARG_MAX the answer is field-too-long, which the Rust
 * side names with a reason.
 */
#include <capnp_c.h>
#include <phronesis/supervisor.h>
#include <policy.capnp.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <util.capnp.h>

/* Linux ARG_MAX. One word may be this long; the Cap'n body may be a
 * small multiple, for framing and the other words. */
#define LJOS_ARG_MAX (128 * 1024)
#define LJOS_SHELL_BODY_MAX (LJOS_ARG_MAX * 4)
/* The pack's own ceilings (policy_janet.c). An argc past this, or a
 * word past LJOS_ARG_MAX, is field-too-long. */
#define LJOS_SHELL_ARGV_MAX 256
#define LJOS_SHELL_PROBE_MAX 32
#define LJOS_SHELL_HEAD_MAX 8192

static capn_text ctext(const char *s)
{
	capn_text t;
	size_t len;

	if (!s)
		s = "";
	len = strlen(s);
	t.len = (int)len;
	t.str = s;
	t.seg = NULL;
	return t;
}

static int write_msg(struct capn *c, uint8_t **out, size_t *out_len)
{
	uint8_t *buf = NULL;
	size_t cap = 8192U;
	int64_t n;

	*out = NULL;
	*out_len = 0;
	for (;;) {
		buf = malloc(cap);
		if (!buf)
			return -1;
		n = capn_write_mem(c, buf, cap, 0);
		if (n >= 0)
			break;
		free(buf);
		if (cap > 1024U * 1024U / 2U)
			return -1;
		cap *= 2U;
	}
	*out = buf;
	*out_len = (size_t)n;
	return 0;
}

int ljos_phronesis_check_shell(phronesis_supervisor_t *sup, const char *cwd,
			       const char *const *argv, int argc,
			       uint8_t **out, size_t *out_len)
{
	struct capn c;
	struct ShellCheck sc;
	ShellCheck_ptr root;
	capn_ptr list;
	uint8_t *in = NULL;
	size_t in_len = 0;
	int i;

	if (!out || !out_len)
		return -1;
	*out = NULL;
	*out_len = 0;
	memset(&c, 0, sizeof(c));
	capn_init_malloc(&c);
	memset(&sc, 0, sizeof(sc));
	sc.agentId.p = new_AgentId(capn_root(&c).seg).p;
	{
		struct AgentId id = { .hi = 0, .lo = 1 };

		write_AgentId(&id, (AgentId_ptr){ .p = sc.agentId.p });
	}
	sc.cwd = ctext(cwd ? cwd : "");
	list = capn_new_ptr_list(capn_root(&c).seg, argc);
	for (i = 0; i < argc; i++)
		capn_set_text(list, i, ctext(argv[i] ? argv[i] : ""));
	sc.argv.p = list;
	root = new_ShellCheck(capn_root(&c).seg);
	write_ShellCheck(&sc, root);
	if (capn_setp(capn_root(&c), 0, root.p) != 0) {
		capn_free(&c);
		return -1;
	}
	if (write_msg(&c, &in, &in_len) != 0) {
		capn_free(&c);
		return -1;
	}
	capn_free(&c);
	phronesis_check_shell(sup, in, in_len, out, out_len);
	free(in);
	return (*out && *out_len) ? 0 : -1;
}

int ljos_phronesis_read_decision(const uint8_t *in, size_t in_len, uint16_t *decision,
				 uint16_t *code, char *reason, size_t reason_len)
{
	struct capn c;
	struct PolicyDecision d;
	PolicyDecision_ptr root;

	if (!in || !in_len || !decision || !code)
		return -1;
	if (reason && reason_len)
		reason[0] = '\0';
	memset(&c, 0, sizeof(c));
	if (capn_init_mem(&c, in, in_len, 0) != 0)
		return -1;
	root.p = capn_getp(capn_root(&c), 0, 1);
	read_PolicyDecision(&d, root);
	*decision = (uint16_t)d.decision;
	*code = (uint16_t)d.code;
	/* The pack's own words for the decision, cut to fit. */
	if (reason && reason_len && d.reason.str && d.reason.len > 0) {
		size_t n = (size_t)d.reason.len;

		if (n > reason_len - 1)
			n = reason_len - 1;
		memcpy(reason, d.reason.str, n);
		reason[n] = '\0';
	}
	capn_free(&c);
	return 0;
}

void phronesis_shell_pack(const char *workspace, const char *cwd, capn_ptr argv,
			  uint8_t **out, size_t *out_len);
int phronesis_policy_eval(const char *workspace, const char *tool, const char *action,
			  const char *path, phronesis_policy_result_t *out);
void phronesis_agent_id_to_hex(uint64_t hi, uint64_t lo, char out[PHRONESIS_ID_MAX]);
int phronesis_resolve_script(const char *cwd, const char *script, char *out, size_t out_n);
int phronesis_policy_deny_all(void);

static capn_text ctext_len(const char *s, size_t len)
{
	capn_text t;

	if (!s) {
		s = "";
		len = 0;
	}
	if (len > (size_t)INT_MAX)
		len = (size_t)INT_MAX;
	t.len = (int)len;
	t.str = s;
	t.seg = NULL;
	return t;
}

static int path_under_workspace(const char *workspace, const char *path)
{
	size_t wl;

	if (!workspace || !workspace[0] || !path || !path[0])
		return 0;
	if (path[0] != '/')
		return 0;
	wl = strlen(workspace);
	while (wl > 1 && workspace[wl - 1] == '/')
		wl--;
	if (strncmp(path, workspace, wl) != 0)
		return 0;
	return path[wl] == '\0' || path[wl] == '/';
}

static void read_agent(AgentId_ptr p, struct AgentId *out)
{
	if (p.p.type == CAPN_NULL) {
		out->hi = 0;
		out->lo = 0;
		return;
	}
	read_AgentId(out, p);
}

static AgentId_ptr put_agent(struct capn_segment *seg, uint64_t hi, uint64_t lo)
{
	struct AgentId id = { .hi = hi, .lo = lo };
	AgentId_ptr p = new_AgentId(seg);

	write_AgentId(&id, p);
	return p;
}

static void emit_result(const phronesis_policy_result_t *pr, struct AgentId agent,
			uint8_t **out, size_t *out_len)
{
	struct capn c;
	struct PolicyDecision d;
	PolicyDecision_ptr dp;

	if (!out || !out_len)
		return;
	*out = NULL;
	*out_len = 0;
	memset(&c, 0, sizeof(c));
	capn_init_malloc(&c);
	memset(&d, 0, sizeof(d));
	d.decision = (enum Decision)pr->decision;
	d.reason = ctext("");
	d.agentId = put_agent(capn_root(&c).seg, agent.hi, agent.lo);
	d.code = (enum PolicyReason)pr->code;
	dp = new_PolicyDecision(capn_root(&c).seg);
	write_PolicyDecision(&d, dp);
	if (capn_setp(capn_root(&c), 0, dp.p) != 0) {
		capn_free(&c);
		return;
	}
	(void)write_msg(&c, out, out_len);
	capn_free(&c);
}

static void deny_code(struct AgentId agent, phronesis_policy_reason_t code, uint8_t **out,
		      size_t *out_len)
{
	phronesis_policy_result_t pr;

	phronesis_policy_result_set(&pr, PHRONESIS_DECISION_DENY, code);
	emit_result(&pr, agent, out, out_len);
}

static const char *workspace_of(phronesis_supervisor_t *sup, struct AgentId id, char *ws_buf,
				size_t ws_len)
{
	char hex[PHRONESIS_ID_MAX];
	phronesis_agent_status_t st;

	if (!ws_buf || ws_len == 0)
		return NULL;
	ws_buf[0] = '\0';
	phronesis_agent_id_to_hex(id.hi, id.lo, hex);
	if (!hex[0])
		return NULL;
	if (phronesis_supervisor_status(sup, hex, &st) != PHRONESIS_OK)
		return NULL;
	if (!st.workspace[0])
		return NULL;
	snprintf(ws_buf, ws_len, "%s", st.workspace);
	return ws_buf;
}

struct argv_word {
	char *s;
	size_t n;
};

struct path_probe {
	char arg[PHRONESIS_PATH_MAX];
	char resolved[PHRONESIS_PATH_MAX];
	int exists;
	char head[LJOS_SHELL_HEAD_MAX];
};

static void free_words(struct argv_word *w, int n)
{
	int i;

	if (!w)
		return;
	for (i = 0; i < n; i++)
		free(w[i].s);
	free(w);
}

/* Strong definition. The archive's copy is weak (build.rs). shell_pack
 * calls this name; a word is stored at its own length, not in a path slot.
 */
__attribute__((used)) int phronesis_build_shell_view(const char *workspace, const char *cwd,
						     capn_ptr argv, uint8_t **flat_out,
						     size_t *flat_len)
{
	struct capn c;
	struct ShellView view;
	ShellView_ptr root;
	struct argv_word *words = NULL;
	struct path_probe *probes = NULL;
	capn_text empty = { 0, "", NULL };
	char abs[PHRONESIS_PATH_MAX];
	int under, n, i, argv_n = 0, pcount = 0, probe_cap = 0;
	int rc = -1;
	int capn_live = 0;

	if (!flat_out || !flat_len)
		return -1;
	*flat_out = NULL;
	*flat_len = 0;
	under = cwd && cwd[0] && path_under_workspace(workspace, cwd);

	capn_resolve(&argv);
	if (argv.type != CAPN_NULL && argv.len > 0) {
		n = argv.len;
		if (n > LJOS_SHELL_ARGV_MAX) {
			rc = -2;
			goto out;
		}
		words = calloc((size_t)n, sizeof(*words));
		if (!words)
			goto out;
		for (i = 0; i < n; i++) {
			capn_text t = capn_get_text(argv, i, empty);

			if (t.len < 0)
				goto out;
			/* A content word, not a path. Past ARG_MAX the
			 * caller answers field-too-long. */
			if ((size_t)t.len > (size_t)LJOS_ARG_MAX) {
				rc = -2;
				goto out;
			}
			words[i].s = calloc((size_t)t.len + 1, 1);
			if (!words[i].s)
				goto out;
			if (t.len > 0 && t.str)
				memcpy(words[i].s, t.str, (size_t)t.len);
			words[i].n = (size_t)t.len;
			argv_n++;
		}
	}

	if (argv_n > 0) {
		probe_cap = argv_n < LJOS_SHELL_PROBE_MAX ? argv_n : LJOS_SHELL_PROBE_MAX;
		probes = calloc((size_t)probe_cap, sizeof(*probes));
		if (!probes)
			goto out;
	}
	for (i = 0; i < argv_n && pcount < probe_cap; i++) {
		const char *tok = words[i].s;
		FILE *f;
		size_t nr;

		if (!tok || !tok[0] || tok[0] == '-')
			continue;
		/* Only a path that fits the library's path buffer is
		 * probed. A longer word is still in the argv the pack reads. */
		if (words[i].n >= PHRONESIS_PATH_MAX)
			continue;
		if (!strchr(tok, '/') && !strchr(tok, '.'))
			continue;
		if (phronesis_resolve_script(cwd, tok, abs, sizeof(abs)) != 0)
			continue;
		if (!path_under_workspace(workspace, abs))
			continue;
		memcpy(probes[pcount].arg, tok, words[i].n + 1);
		memcpy(probes[pcount].resolved, abs, strlen(abs) + 1);
		f = fopen(abs, "rb");
		if (!f) {
			probes[pcount].exists = 0;
			probes[pcount].head[0] = '\0';
			pcount++;
			continue;
		}
		probes[pcount].exists = 1;
		nr = fread(probes[pcount].head, 1, LJOS_SHELL_HEAD_MAX - 1, f);
		probes[pcount].head[nr] = '\0';
		fclose(f);
		pcount++;
	}

	memset(&c, 0, sizeof(c));
	capn_init_malloc(&c);
	capn_live = 1;
	memset(&view, 0, sizeof(view));
	view.underWorkspace = under ? 1 : 0;
	view.cwd = ctext(cwd ? cwd : "");
	view.argv.p = capn_new_ptr_list(capn_root(&c).seg, argv_n);
	for (i = 0; i < argv_n; i++) {
		if (capn_set_text(view.argv.p, i, ctext_len(words[i].s, words[i].n)) != 0)
			goto out;
	}
	view.pathProbes = new_PathProbe_list(capn_root(&c).seg, pcount);
	for (i = 0; i < pcount; i++) {
		struct PathProbe pp;

		memset(&pp, 0, sizeof(pp));
		pp.arg = ctext(probes[i].arg);
		pp.resolved = ctext(probes[i].resolved);
		pp.exists = probes[i].exists ? 1 : 0;
		pp.head = ctext(probes[i].head);
		set_PathProbe(&pp, view.pathProbes, i);
	}
	root = new_ShellView(capn_root(&c).seg);
	write_ShellView(&view, root);
	if (capn_setp(capn_root(&c), 0, root.p) != 0)
		goto out;
	if (write_msg(&c, flat_out, flat_len) != 0)
		goto out;
	rc = 0;
out:
	if (capn_live)
		capn_free(&c);
	free(probes);
	free_words(words, argv_n);
	return rc;
}

/* Strong definition. The archive's copy is weak. A body over 64 KiB is
 * read here; the library's open_in refused it unread.
 */
__attribute__((used)) void phronesis_check_shell(phronesis_supervisor_t *sup, const uint8_t *in,
						 size_t in_len, uint8_t **out, size_t *out_len)
{
	struct capn c;
	struct ShellCheck sc;
	struct AgentId agent;
	char ws_buf[PHRONESIS_PATH_MAX];
	char cwd[PHRONESIS_PATH_MAX];
	const char *ws;
	phronesis_policy_result_t pr;
	ShellCheck_ptr root;
	size_t cl;

	if (!out || !out_len)
		return;
	*out = NULL;
	*out_len = 0;
	memset(&agent, 0, sizeof(agent));
	if (!in || in_len == 0 || in_len > (size_t)LJOS_SHELL_BODY_MAX) {
		if (in && in_len > (size_t)LJOS_SHELL_BODY_MAX)
			deny_code(agent, PHRONESIS_REASON_FIELD_TOO_LONG, out, out_len);
		else
			deny_code(agent, PHRONESIS_REASON_INVALID_MESSAGE, out, out_len);
		return;
	}
	memset(&c, 0, sizeof(c));
	if (capn_init_mem(&c, in, in_len, 0) != 0) {
		deny_code(agent, PHRONESIS_REASON_INVALID_MESSAGE, out, out_len);
		return;
	}
	root.p = capn_getp(capn_root(&c), 0, 1);
	read_ShellCheck(&sc, root);
	read_agent(sc.agentId, &agent);
	if (phronesis_policy_deny_all()) {
		capn_free(&c);
		deny_code(agent, PHRONESIS_REASON_DENY_ALL, out, out_len);
		return;
	}
	ws = workspace_of(sup, agent, ws_buf, sizeof(ws_buf));
	cl = sc.cwd.len > 0 ? (size_t)sc.cwd.len : 0;
	if (cl >= sizeof(cwd) || (cl > 0 && !sc.cwd.str)) {
		capn_free(&c);
		deny_code(agent, PHRONESIS_REASON_FIELD_TOO_LONG, out, out_len);
		return;
	}
	if (cl)
		memcpy(cwd, sc.cwd.str, cl);
	cwd[cl] = '\0';
	(void)phronesis_policy_eval(ws, "shell", "exec", cwd[0] ? cwd : NULL, &pr);
	if (pr.decision != PHRONESIS_DECISION_ALLOW) {
		capn_free(&c);
		emit_result(&pr, agent, out, out_len);
		return;
	}
	{
		capn_ptr argv = sc.argv.p;

		if (argv.type == CAPN_FAR_POINTER)
			capn_resolve(&argv);
		if (argv.len > 0) {
			uint8_t *pack_out = NULL;
			size_t pack_len = 0;

			phronesis_shell_pack(ws, cwd, argv, &pack_out, &pack_len);
			capn_free(&c);
			if (pack_out && pack_len) {
				*out = pack_out;
				*out_len = pack_len;
				return;
			}
			deny_code(agent, PHRONESIS_REASON_PACK_BAD_RESULT, out, out_len);
			return;
		}
	}
	capn_free(&c);
	emit_result(&pr, agent, out, out_len);
}
