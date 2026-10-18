"""
Unit tests for analysis/extraction/c_types.py (the struct-type reader used
to match function-pointer calls by type). Run from the project folder:

    .venv\\Scripts\\python.exe -m unittest discover tests
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analysis/extraction"))
from c_types import (Scope, StructTable, body_variables, expression_type, initializer_registrations,
                     operand_before, parameter_variables)

HEADER = """
struct nft_expr_ops {
	void (*eval)(const struct nft_expr *expr, struct nft_regs *regs);
	int (*init)(const struct nft_ctx *ctx);
	const struct nft_expr_type *type;
};
struct nft_expr {
	const struct nft_expr_ops	*ops;
	unsigned char			data[] __aligned(8);
};
struct nf_hook_entry { nf_hookfn *hook; void *priv; };
struct nf_hook_entries {
	u16 num_hook_entries;
	struct nf_hook_entry hooks[];
};
struct ip_set_type_variant {
	int (*adt[IPSET_ADT_MAX])(struct ip_set *set, void *value);
};
struct ip_set {
	const struct ip_set_type_variant *variant;
	union { struct nft_expr *anon_expr; int other; };
};
struct nfnl_callback { int (*call)(struct sk_buff *skb); const struct nla_policy *policy; };
"""


class CTypesTest(unittest.TestCase):
    def setUp(self):
        self.structs = StructTable()
        self.structs.add_text(HEADER)

    def test_field_types(self):
        self.assertEqual(self.structs.field("nft_expr", "ops"), ("nft_expr_ops", False))
        self.assertEqual(self.structs.field("nf_hook_entries", "hooks"), ("nf_hook_entry", True))
        self.assertEqual(self.structs.field("ip_set", "anon_expr")[0], "nft_expr")   # anonymous union

    def test_expression_types(self):
        scope = Scope(parameter_variables("void f(const struct nft_expr *expr, struct ip_set *set)"))
        self.assertEqual(expression_type("expr->ops", scope, self.structs), "nft_expr_ops")
        self.assertEqual(expression_type("set->variant", scope, self.structs), "ip_set_type_variant")
        self.assertEqual(expression_type("rcu_dereference(expr->ops)", scope, self.structs), "nft_expr_ops")
        self.assertEqual(expression_type("((struct nft_expr *)p)->ops", scope, self.structs), "nft_expr_ops")
        self.assertEqual(expression_type("container_of(x, struct nft_expr, list)->ops", scope, self.structs),
                         "nft_expr_ops")
        self.assertIsNone(expression_type("unknown->ops", scope, self.structs))

    def test_array_index_and_locals(self):
        body = "struct nf_hook_entries *e = x; const struct nft_expr *a, *b;"
        scope = Scope(body_variables(body))
        self.assertEqual(expression_type("&e->hooks[i]", scope, self.structs), "nf_hook_entry")
        self.assertEqual(scope.get("b"), "nft_expr")

    def test_operand_before(self):
        text = "\treturn expr->ops->eval(expr, regs);"
        end = text.index("->eval")
        self.assertEqual(operand_before(text, end), "expr->ops")
        text = "ret = set->variant->adt[adt](set, value);"
        self.assertEqual(operand_before(text, text.index("->adt")), "set->variant")

    def test_initializers(self):
        code = """
static const struct nft_expr_ops nft_payload_ops = {
	.type		= &nft_payload_type,
	.eval		= nft_payload_eval,
	.init		= nft_payload_init,
};
static const struct nfnl_callback nf_tables_cb[NFT_MSG_MAX] = {
	[NFT_MSG_NEWTABLE] = {
		.call		= nf_tables_newtable,
		.policy		= nft_table_policy,
	},
	[NFT_MSG_GETTABLE] = { .call = nf_tables_gettable },
};
static const struct ip_set_type_variant bitmap_ip = {
	.adt	= {
		[IPSET_ADD] = bitmap_ip_add,
		[IPSET_DEL] = bitmap_ip_del,
	},
};
"""
        found = {(s, f, v) for s, f, v, _ in initializer_registrations(code, self.structs)}
        self.assertIn(("nft_expr_ops", "eval", "nft_payload_eval"), found)
        self.assertIn(("nfnl_callback", "call", "nf_tables_newtable"), found)
        self.assertIn(("nfnl_callback", "call", "nf_tables_gettable"), found)
        self.assertIn(("ip_set_type_variant", "adt", "bitmap_ip_add"), found)
        self.assertNotIn(("nfnl_callback", "call", "nft_payload_eval"), found)


if __name__ == "__main__":
    unittest.main()
