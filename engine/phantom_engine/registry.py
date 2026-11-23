"""Formal tool registry for D-MOON PHANTOM.

Every tool is one function registered with @tool. The registry stores the
unique ID, name, category, description, language, input schema, output schema
and permission requirement. Counts reported by the CLI come from here.
"""

CATEGORIES = {
    "URL": "URL & Phishing Intelligence",
    "DOM": "Domain Intelligence",
    "DNS": "DNS Analysis",
    "TLS": "TLS & SSL Inspection",
    "HTP": "HTTP Security Analysis",
    "NET": "IP & Network Intelligence",
    "FIL": "File Security Analysis",
    "EML": "Email Security Analysis",
    "INT": "Threat Intelligence",
    "RPT": "Security Reporting",
}
EXPECTED = {"URL": 15, "DOM": 12, "DNS": 10, "TLS": 10, "HTP": 12,
            "NET": 12, "FIL": 10, "EML": 8, "INT": 6, "RPT": 5}
PERMISSIONS = ("none", "file-read", "file-write", "network")
TYPES = ("str", "int", "float", "bool", "list", "dict")

REGISTRY = {}   # id -> Tool
BY_NAME = {}    # name -> Tool


class Tool:
    __slots__ = ("id", "name", "category", "description", "language",
                 "inputs", "outputs", "permission", "fn")

    def __init__(self, tid, name, desc, inputs, outputs, perm, fn):
        self.id = tid
        self.name = name
        self.category = CATEGORIES[tid.split("-")[0]]
        self.description = desc
        self.language = "python"
        self.inputs = inputs      # name -> {"type":..., "required":bool, "default":...}
        self.outputs = outputs    # list of result keys always present
        self.permission = perm
        self.fn = fn

    def schema(self):
        return {
            "id": self.id, "name": self.name, "category": self.category,
            "description": self.description, "language": self.language,
            "input_schema": self.inputs, "output_schema": self.outputs,
            "permission": self.permission,
        }


def _default(typ, raw):
    if typ == "int":
        return int(raw)
    if typ == "float":
        return float(raw)
    if typ == "bool":
        return raw.lower() == "true"
    if typ == "list":
        return []
    if typ == "dict":
        return {}
    return raw


def parse_inputs(spec):
    """'url:str, timeout:int=5' -> schema dict."""
    out = {}
    for part in [s.strip() for s in spec.split(",") if s.strip()]:
        name, rest = part.split(":", 1)
        if "=" in rest:
            typ, raw = rest.split("=", 1)
            required, default = False, _default(typ, raw)
        else:
            typ, required, default = rest, True, None
        assert typ in TYPES, "bad type %s" % typ
        out[name] = {"type": typ, "required": required, "default": default}
    return out


def tool(tid, name, desc, inputs, outputs, perm="none"):
    assert perm in PERMISSIONS
    assert tid.split("-")[0] in CATEGORIES, tid

    def deco(fn):
        assert tid not in REGISTRY, "duplicate id " + tid
        assert name not in BY_NAME, "duplicate name " + name
        t = Tool(tid, name, desc, parse_inputs(inputs),
                 [o.strip() for o in outputs.split(",") if o.strip()], perm, fn)
        fn.__doc__ = desc
        REGISTRY[tid] = t
        BY_NAME[name] = t
        return fn
    return deco


def resolve(ref):
    return REGISTRY.get(ref) or BY_NAME.get(ref)


def counts():
    per = {k: 0 for k in CATEGORIES}
    for t in REGISTRY.values():
        per[t.id.split("-")[0]] += 1
    return {"implemented": len(REGISTRY), "per_category": per}
