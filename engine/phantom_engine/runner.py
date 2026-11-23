"""Runs a registered tool and wraps the result in a JSON envelope."""
import importlib

from . import registry
from .common import PhantomError, score

VERSION = "1.0.0"
_MODULES = ("tools_url", "tools_domain", "tools_dns", "tools_tls", "tools_http",
            "tools_net", "tools_file", "tools_email", "tools_intel", "tools_report")
_loaded = [False]
MAX_STR = 8 * 1024 * 1024
MAX_LIST = 100000


def load_all():
    if not _loaded[0]:
        for m in _MODULES:
            importlib.import_module("phantom_engine." + m)
        _loaded[0] = True
    return registry.REGISTRY


def _type_ok(typ, v):
    if typ == "str":
        return isinstance(v, str) and len(v) <= MAX_STR
    if typ == "int":
        return isinstance(v, int) and not isinstance(v, bool)
    if typ == "float":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    if typ == "bool":
        return isinstance(v, bool)
    if typ == "list":
        return isinstance(v, list) and len(v) <= MAX_LIST
    if typ == "dict":
        return isinstance(v, dict)
    return False


def validate(t, params):
    if not isinstance(params, dict):
        raise PhantomError("bad_params", "params must be an object")
    unknown = sorted(set(params) - set(t.inputs) - {"authorized"})
    if unknown:
        raise PhantomError("bad_params", "unknown parameter(s): " + ", ".join(unknown))
    out = {}
    for name, spec in t.inputs.items():
        if name in params:
            v = params[name]
            if not _type_ok(spec["type"], v):
                raise PhantomError("bad_params", "parameter %r must be %s" % (name, spec["type"]))
            if name in ("path", "pem_path") and isinstance(v, str) and "\x00" in v:
                raise PhantomError("bad_params", "path contains a NUL byte")
            out[name] = v
        elif spec["required"]:
            raise PhantomError("bad_params", "missing required parameter %r" % name)
        else:
            d = spec["default"]
            out[name] = list(d) if isinstance(d, list) else dict(d) if isinstance(d, dict) else d
    return out


def run(ref, params=None):
    load_all()
    t = registry.resolve(ref)
    if t is None:
        return {"ok": False, "tool": ref, "error": {"code": "unknown_tool",
                "message": "no such tool: %s" % str(ref)[:80]}}
    base = {"tool_id": t.id, "tool": t.name, "category": t.category,
            "engine_version": VERSION}
    try:
        params = params if params is not None else {}
        p = validate(t, params)
        if t.permission == "network" and params.get("authorized") is not True:
            raise PhantomError("not_authorized",
                               "network tool: pass authorized=true only for targets you "
                               "own or are explicitly permitted to assess")
        result = t.fn(p)
        if not isinstance(result, dict):
            raise PhantomError("internal", "tool returned non-object")
        findings = result.get("findings")
        env = dict(base, ok=True, result=result)
        if findings is not None:
            s, label = score(findings)
            env["risk"] = {"score": s, "label": label,
                           "basis": "heuristic rules unless a finding is marked fact/intel"}
        return env
    except PhantomError as e:
        return dict(base, ok=False, error={"code": e.code, "message": e.message})
    except RecursionError:
        return dict(base, ok=False, error={"code": "internal", "message": "input too deeply nested"})
    except Exception as e:  # never leak a traceback into the protocol
        return dict(base, ok=False, error={"code": "internal",
                    "message": "%s: %s" % (type(e).__name__, str(e)[:200])})
