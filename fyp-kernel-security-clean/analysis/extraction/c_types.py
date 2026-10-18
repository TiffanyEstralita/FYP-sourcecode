"""
Shared helper for extract_indirect_calls.py: a small, approximate reader of
C struct TYPES. It is not a compiler - it understands the patterns the
kernel uses most and says "unknown" for everything else.

What it can answer:
  - struct definitions:   struct nft_expr { const struct nft_expr_ops *ops; ... }
                          -> field `ops` of struct nft_expr has type struct nft_expr_ops
  - variable types:       const struct nft_expr *expr   (parameters, locals, globals)
  - expression types:     expr->ops   -> struct nft_expr_ops
                          ((struct foo *)p)->x, rcu_dereference(x->ops),
                          container_of(p, struct foo, member), &e->hooks[i] ...
  - struct initializers:  static const struct nft_expr_ops nft_payload_ops = {
                              .eval = nft_payload_eval, ...
                          -> (struct nft_expr_ops, field eval) = nft_payload_eval
                          incl. arrays of structs, nested structs and slot tables
                          (.adt = { [IPSET_ADD] = bitmap_ip_add }).

Struct names are stored without the word "struct" ("nft_expr_ops").
None always means "type not known".
"""

import re
from collections import defaultdict

IDENT = re.compile(r"[A-Za-z_]\w*")
KEYWORDS = {"return", "if", "while", "for", "switch", "sizeof", "case", "else", "do", "goto",
            "typeof", "__typeof__", "defined"}
# annotations that may appear inside declarations and mean nothing for the type
ANNOTATIONS = re.compile(r"\b(?:const|volatile|static|extern|inline|__rcu|__percpu|__user|__iomem|"
                         r"__read_mostly|__ro_after_init|__initdata|__initconst|__maybe_unused|"
                         r"__randomize_layout|__packed|____cacheline_aligned(?:_in_smp)?|"
                         r"__aligned\s*\([^)]*\)|__attribute__\s*\(\(.*?\)\)|__counted_by\s*\(\w*\)|"
                         r"__private|__force|unsigned|signed|register)\b")
CAST = re.compile(r"^\s*(?:const\s+)?struct\s+(\w+)\s*(?:const\s*)?\*+\s*$")
# wrappers whose result has the type of their FIRST argument
SAME_TYPE_WRAPPERS = {"rcu_dereference", "rcu_dereference_protected", "rcu_dereference_raw",
                      "rcu_dereference_check", "rcu_dereference_bh", "rcu_access_pointer",
                      "READ_ONCE", "rtnl_dereference", "nfnl_dereference", "nft_dereference",
                      "rcu_dereference_bh_check", "srcu_dereference", "this_cpu_ptr", "per_cpu_ptr",
                      "raw_cpu_ptr", "ERR_CAST"}
# wrappers whose result type is named in an argument: container_of(ptr, struct foo, member)
CONTAINER_WRAPPERS = {"container_of", "container_of_const", "list_entry", "list_first_entry",
                      "list_last_entry", "list_first_entry_or_null", "list_entry_rcu",
                      "list_next_entry", "hlist_entry", "hlist_entry_safe", "rb_entry",
                      "rb_entry_safe", "list_prev_entry", "llist_entry"}


# ---------------------------------------------------------------- text helpers

def strip_comments(text):
    """Remove /* */ and // comments, keeping line breaks (line numbers stay the same)"""
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def strip_strings(text):
    return re.sub(r'"(?:\\.|[^"\\\n])*"', '""', text)


def match_forward(text, open_pos):
    """Index of the bracket that closes the one at open_pos (or None)"""
    pairs = {"(": ")", "[": "]", "{": "}"}
    opener = text[open_pos]
    closer = pairs[opener]
    depth = 0
    for i in range(open_pos, len(text)):
        if text[i] == opener:
            depth += 1
        elif text[i] == closer:
            depth -= 1
            if depth == 0:
                return i
    return None


def match_backward(text, close_pos):
    """Index of the bracket that opens the one at close_pos (or None)"""
    pairs = {")": "(", "]": "[", "}": "{"}
    closer = text[close_pos]
    opener = pairs[closer]
    depth = 0
    for i in range(close_pos, -1, -1):
        if text[i] == closer:
            depth += 1
        elif text[i] == opener:
            depth -= 1
            if depth == 0:
                return i
    return None


def split_top_level(text, sep=","):
    """Split on `sep` characters that are not inside any brackets"""
    parts, depth, current = [], 0, []
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return [p.strip() for p in parts]


def is_ident_char(ch):
    return ch.isalnum() or ch == "_"


# ---------------------------------------------------------------- declarations

def declared_names(declarators):
    """'*a, b[4], *const c = x' -> [('a', False), ('b', True), ('c', False)]
    (name, is_array). Function pointers '(*fn)(...)' are skipped."""
    out = []
    for part in split_top_level(declarators):
        part = part.split("=")[0]
        if "(" in part:          # function pointer or function prototype
            continue
        is_array = "[" in part
        part = re.sub(r"\[.*?\]", "", part)
        part = ANNOTATIONS.sub(" ", part).replace("*", " ")
        words = IDENT.findall(part)
        if words:
            out.append((words[-1], is_array))
    return out


def struct_declaration(statement):
    """
    'const struct nft_expr *expr, *last' -> ('nft_expr', [('expr', False), ('last', False)])
    or None when the statement does not declare struct-typed variables.
    """
    m = re.match(r"^\s*(?:(?:static|extern|const|volatile|register|unsigned|__\w+)\s+)*"
                 r"struct\s+(\w+)\s+(?!\{)(.+)$", statement, flags=re.S)
    if not m:
        return None
    return m.group(1), declared_names(m.group(2))


class StructTable:
    """field types of every struct definition found:
       fields[struct][field] = (struct type or None, is_array)"""

    def __init__(self):
        self.fields = defaultdict(dict)
        self.typedefs = {}            # typedef name -> struct name

    def add_text(self, text):
        text = strip_strings(strip_comments(text))
        for m in re.finditer(r"\bstruct\s+(\w+)\s*\{", text):
            close = match_forward(text, m.end() - 1)
            if close is None:
                continue
            self._add_members(m.group(1), text[m.end():close])
            # typedef struct foo {...} foo_t;
            before = text[max(0, m.start() - 10):m.start()]
            if "typedef" in before:
                after = re.match(r"\s*(\w+)\s*;", text[close + 1:])
                if after:
                    self.typedefs[after.group(1)] = m.group(1)
        for m in re.finditer(r"\btypedef\s+struct\s+(\w+)\s+(\w+)\s*;", text):
            self.typedefs[m.group(2)] = m.group(1)

    def _add_members(self, struct, body):
        # nested anonymous struct/union: its members belong to the outer struct
        flat, i = [], 0
        while i < len(body):
            m = re.compile(r"\b(?:struct|union)\s*\{").search(body, i)
            if not m:
                flat.append(body[i:])
                break
            flat.append(body[i:m.start()])
            close = match_forward(body, m.end() - 1)
            if close is None:
                break
            inner = body[m.end():close]
            self._add_members(struct, inner)
            # skip a possible member name after the anonymous block: "} name;"
            tail = re.match(r"\s*\w*\s*;", body[close + 1:])
            i = close + 1 + (tail.end() if tail else 0)
        for statement in "".join(flat).split(";"):
            statement = statement.strip()
            if not statement or statement.startswith("#"):
                continue
            decl = struct_declaration(statement)
            if decl:
                ftype, names = decl
                for name, is_array in names:
                    self.fields[struct][name] = (ftype, is_array)
            else:
                for name, is_array in declared_names(ANNOTATIONS.sub(" ", statement)):
                    self.fields[struct].setdefault(name, (None, is_array))

    def field(self, struct, name):
        """(type, is_array) of struct.name, or (None, False)"""
        if struct is None:
            return None, False
        struct = self.typedefs.get(struct, struct)
        return self.fields.get(struct, {}).get(name, (None, False))


# ---------------------------------------------------------------- expressions

def operand_before(text, end):
    """
    The expression that ends at text[end] (exclusive), walking backwards over
    identifiers, -> and . and bracket groups. For
        'return  expr->ops->eval'  with end before '->eval'
    it returns 'expr->ops'.
    """
    i, start, want_operand = end, end, True
    while i > 0:
        j = i
        while j > 0 and text[j - 1].isspace():
            j -= 1
        if j == 0:
            break
        ch = text[j - 1]
        if want_operand:
            if ch == "]":
                g = match_backward(text, j - 1)
                if g is None:
                    break
                i = g            # an index: the operand continues before '['
                continue
            if ch == ")":
                g = match_backward(text, j - 1)
                if g is None:
                    break
                k = g
                while k > 0 and text[k - 1].isspace():
                    k -= 1
                w = k
                while w > 0 and is_ident_char(text[w - 1]):
                    w -= 1
                i = w if w < k and text[w:k] not in KEYWORDS else g
                start, want_operand = i, False
                continue
            w = j
            while w > 0 and is_ident_char(text[w - 1]):
                w -= 1
            if w == j or text[w:j] in KEYWORDS:
                break
            i = start = w
            want_operand = False
        else:
            if text[j - 2:j] == "->":
                i, want_operand = j - 2, True
            elif ch == "." and not (j >= 2 and text[j - 2].isdigit()):
                i, want_operand = j - 1, True
            else:
                break
    return text[start:end].strip()


class Scope:
    """Variable -> struct type, looked up innermost first (function, file, headers)"""

    def __init__(self, *layers):
        self.layers = [layer for layer in layers if layer is not None]

    def get(self, name):
        for layer in self.layers:
            if name in layer:
                return layer[name]
        return None


def expression_type(expr, scope, structs, returns=None):
    """Struct type of a C expression (no 'struct' prefix), or None if unknown"""
    expr = expr.strip()
    while expr and expr[0] in "&*":
        expr = expr[1:].strip()
    if not expr:
        return None

    # primary
    if expr[0] == "(":
        close = match_forward(expr, 0)
        if close is None:
            return None
        inner, rest = expr[1:close], expr[close + 1:]
        cast = CAST.match(inner)
        if cast:
            return structs.typedefs.get(cast.group(1), cast.group(1))
        current = expression_type(inner, scope, structs, returns)
    else:
        m = IDENT.match(expr)
        if not m:
            return None
        name, rest = m.group(0), expr[m.end():]
        stripped = rest.lstrip()
        if stripped.startswith("("):
            open_pos = len(rest) - len(stripped)
            close = match_forward(rest, open_pos)
            if close is None:
                return None
            args = split_top_level(rest[open_pos + 1:close])
            rest = rest[close + 1:]
            if name in SAME_TYPE_WRAPPERS and args:
                current = expression_type(args[0], scope, structs, returns)
            elif name in CONTAINER_WRAPPERS and len(args) >= 2:
                t = re.match(r"^\s*(?:const\s+)?struct\s+(\w+)\s*$", args[1])
                current = t.group(1) if t else None
            elif returns and name in returns:
                current = returns[name]
            else:
                return None
        else:
            current = scope.get(name)

    # postfix: ->field  .field  [index]
    pos = 0
    while pos < len(rest):
        if rest[pos].isspace():
            pos += 1
            continue
        if rest[pos] == "[":
            close = match_forward(rest, pos)
            if close is None:
                return None
            pos = close + 1
            continue
        m = re.match(r"(->|\.)\s*(\w+)", rest[pos:])
        if not m:
            return None
        current, _ = structs.field(current, m.group(2))
        if current is None:
            return None
        pos += m.end()
    return structs.typedefs.get(current, current) if current else None


def body_variables(text):
    """{variable: struct type} declared in a block of code (params or locals)"""
    out = {}
    text = strip_strings(text)
    for statement in re.split(r"[;{}()]|\bfor\b", text):
        decl = struct_declaration(statement.replace("\n", " "))
        if decl:
            for name, _ in decl[1]:
                out[name] = decl[0]
    return out


def parameter_variables(signature):
    """{param: struct type} from 'int foo(struct a *x, const struct b *y)'"""
    open_pos = signature.find("(")
    if open_pos < 0:
        return {}
    close = match_forward(signature, open_pos)
    inside = signature[open_pos + 1:close] if close else signature[open_pos + 1:]
    out = {}
    for param in split_top_level(inside):
        decl = struct_declaration(param)
        if decl:
            for name, _ in decl[1]:
                out[name] = decl[0]
    return out


def return_struct_type(signature, name):
    """'static struct foo *bar(' -> 'foo' (for functions returning a struct pointer)"""
    m = re.search(r"\bstruct\s+(\w+)\s*\*+\s*" + re.escape(name) + r"\s*\(", signature)
    return m.group(1) if m else None


# ---------------------------------------------------------------- initializers

def initializer_registrations(text, structs, offset_line=1):
    """
    Find every `... struct T name = { ... }` (global or local, incl. arrays)
    and yield (struct type or None, field, value identifier, line number).
    Nested `.field = { ... }` uses the field's own struct type; a nested
    list without a struct type is a slot table: its entries are registered
    in the enclosing field (`.adt = { [IPSET_ADD] = bitmap_ip_add }`).
    """
    clean = strip_strings(strip_comments(text))
    for m in re.finditer(r"=\s*\{", clean):
        brace = m.end() - 1
        # declaration text before '=': back to the previous ; { } or start
        k = m.start()
        while k > 0 and clean[k - 1] not in ";{}":
            k -= 1
        # last comma-separated piece: inside another initializer this is the
        # designator ('.adt' or '[NFT_MSG_NEWRULE]') - those nested lists are
        # handled by the recursion, so skip them here
        declaration = split_top_level(clean[k:m.start()])[-1]
        if declaration.startswith((".", "[")):
            continue
        t = re.search(r"\bstruct\s+(\w+)", declaration)
        if t is None:
            continue
        struct = structs.typedefs.get(t.group(1), t.group(1))
        is_array = "[" in declaration
        close = match_forward(clean, brace)
        if close is None:
            continue
        line = offset_line + clean.count("\n", 0, brace)
        context = ("array", struct) if is_array else ("struct", struct)
        yield from _walk_initializer(clean[brace + 1:close], context, structs, line)


def _walk_initializer(body, context, structs, line):
    kind = context[0]
    for item in split_top_level(body):
        if not item:
            continue
        designator, value = None, item
        m = re.match(r"^((?:\s*(?:\.\s*\w+|\[[^\]]*\]))+)\s*=\s*(.*)$", item, flags=re.S)
        if m:
            designator, value = m.group(1), m.group(2).strip()
        fields = re.findall(r"\.\s*(\w+)", designator or "")
        value = value.strip()

        if kind == "struct":
            struct = context[1]
            if fields:
                # .a.b = x : walk the designator path
                for f in fields[:-1]:
                    struct, _ = structs.field(struct, f)
                target_struct, field = struct, fields[-1]
            else:
                target_struct, field = None, None
        elif kind == "array":
            target_struct, field = context[1], None
            if fields:          # [i].field = x inside an array of structs
                target_struct, field = context[1], fields[-1]
        else:                   # slot table of (struct, field)
            target_struct, field = context[1], context[2]

        if value.startswith("{"):
            close = match_forward(value, 0)
            inner = value[1:close] if close else value[1:]
            if kind == "array" and field is None:
                yield from _walk_initializer(inner, ("struct", target_struct), structs, line)
            elif field is not None:
                ftype, f_is_array = structs.field(target_struct, field)
                if kind == "slots":
                    sub = ("slots", target_struct, field)
                elif ftype:
                    sub = ("array", ftype) if f_is_array else ("struct", ftype)
                else:
                    sub = ("slots", target_struct, field)
                yield from _walk_initializer(inner, sub, structs, line)
            continue

        if field is None:
            continue
        ident = re.match(r"^&?\s*\(?\s*([A-Za-z_]\w*)\s*\)?$", value)
        if ident:
            yield target_struct, field, ident.group(1), line
