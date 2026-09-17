/* Build a phronesis ShellCheck with c-capnproto and call phronesis_check_shell.
 * Rust capnp::serialize is a different wire than capn_init_mem. */
#include <capnp_c.h>
#include <phronesis/supervisor.h>
#include <policy.capnp.h>
#include <stdlib.h>
#include <string.h>
#include <util.capnp.h>

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
				 uint16_t *code)
{
	struct capn c;
	struct PolicyDecision d;
	PolicyDecision_ptr root;

	if (!in || !in_len || !decision || !code)
		return -1;
	memset(&c, 0, sizeof(c));
	if (capn_init_mem(&c, in, in_len, 0) != 0)
		return -1;
	root.p = capn_getp(capn_root(&c), 0, 1);
	read_PolicyDecision(&d, root);
	*decision = (uint16_t)d.decision;
	*code = (uint16_t)d.code;
	capn_free(&c);
	return 0;
}
