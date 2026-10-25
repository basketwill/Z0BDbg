"""Worker for the MCP debugger's bounded Python tool mode.

Protocol messages use one JSON object per line on stdin/stdout. The parent
process owns every debugger operation and enforces the MCP tool policy.
"""

import ast
import json
import sys


def send(message):
    sys.stdout.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def read():
    line = sys.stdin.readline()
    if not line:
        raise RuntimeError("Debugger bridge closed")
    return json.loads(line)


def decode_utf16(hex_text):
    data = bytes.fromhex(hex_text)
    end = next((i for i in range(0, len(data) - 1, 2) if data[i:i + 2] == b"\x00\x00"), len(data))
    return data[:end].decode("utf-16-le", errors="replace")


def u32(hex_text, offset=0):
    data = bytes.fromhex(hex_text)
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("u32 offset is outside the byte range")
    return int.from_bytes(data[offset:offset + 4], "little")


def safe_print(*values):
    send({"kind": "print", "text": " ".join(str(value) for value in values)[:2048]})


def safe_append(values, value):
    if not isinstance(values, list):
        raise TypeError("append requires a list")
    values.append(value)


SAFE_FUNCTIONS = {
    "abs": abs, "all": all, "any": any, "bool": bool, "dict": dict,
    "enumerate": enumerate, "get": lambda data, key, default=None: data.get(key, default),
    "hex": hex, "int": int, "len": len, "list": list, "max": max,
    "min": min, "range": range, "str": str, "sum": sum,
    "append": safe_append, "print": safe_print, "u32": u32,
    "decode_utf16": decode_utf16,
}

SAFE_NODES = (
    ast.Module, ast.Expr, ast.Assign, ast.AugAssign, ast.If, ast.For,
    ast.While, ast.Break, ast.Continue, ast.Pass, ast.Name, ast.Load,
    ast.Store, ast.Constant, ast.List, ast.Tuple, ast.Dict, ast.Subscript,
    ast.Slice, ast.Call, ast.keyword, ast.Attribute, ast.Compare, ast.BoolOp,
    ast.BinOp, ast.UnaryOp, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv,
    ast.Mod, ast.BitAnd, ast.BitOr, ast.BitXor, ast.LShift, ast.RShift,
    ast.And, ast.Or, ast.Not, ast.USub, ast.UAdd, ast.Eq, ast.NotEq,
    ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Is, ast.IsNot, ast.In, ast.NotIn,
)


def validate(code, tools):
    tree = ast.parse(code, mode="exec")
    nodes = list(ast.walk(tree))
    if len(nodes) > 500:
        raise ValueError("Script is too complex")
    for node in nodes:
        if not isinstance(node, SAFE_NODES):
            raise ValueError("Unsupported Python syntax: " + type(node).__name__)
        if isinstance(node, ast.Name) and (node.id.startswith("_") or "__" in node.id):
            raise ValueError("Private names are unavailable")
        if isinstance(node, ast.Attribute) and (
            not isinstance(node.value, ast.Name) or node.value.id != "dbg" or node.attr not in tools
        ):
            raise ValueError("Only listed dbg functions are available")
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id not in SAFE_FUNCTIONS:
                raise ValueError("Function is unavailable: " + node.func.id)
            if not isinstance(node.func, (ast.Name, ast.Attribute)):
                raise ValueError("Indirect calls are unavailable")
            if isinstance(node.func, ast.Attribute) and node.args:
                raise ValueError("Debugger functions require named arguments")
            if any(keyword.arg is None for keyword in node.keywords):
                raise ValueError("Expanded keyword arguments are unavailable")
    return tree


class Debugger:
    def __init__(self, tools):
        self.tools = set(tools)

    def __getattr__(self, name):
        if name not in self.tools:
            raise AttributeError(name)

        def call(**arguments):
            send({"kind": "call", "name": name, "arguments": arguments})
            reply = read()
            if reply.get("kind") != "reply":
                raise RuntimeError("Invalid debugger bridge reply")
            if not reply.get("ok"):
                raise RuntimeError(reply.get("error", "Debugger tool failed"))
            return reply["data"]

        return call


def main():
    request = read()
    code = request["code"]
    tools = request["tools"]
    tree = validate(code, set(tools))
    scope = {"__builtins__": SAFE_FUNCTIONS, "dbg": Debugger(tools)}
    scope.update(SAFE_FUNCTIONS)
    exec(compile(tree, "<debug-python>", "exec"), scope, scope)
    send({"kind": "done"})


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        send({"kind": "error", "message": str(error)[:1024]})
