"""Bounded, static observations of Python and JavaScript module-loader syntax.

Python uses AST bindings for importlib/builtins imports and direct aliases. It
does not evaluate expressions or follow aliases across files. JavaScript uses a
lexer, not a complete JS/TS parser: bare require/import and module.require calls
are recognized, including code inside template substitutions. Arbitrary loader
aliases, runtime rebinding and interprocedural dataflow are outside this scope.
An unresolved recognized loader is uncertainty, never evidence of absent use.
"""

from __future__ import annotations

import ast
import re
import warnings
from bisect import bisect_right
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class DynamicImport:
    line: int
    loader: str
    target: str | None
    reason: str = ""


@dataclass(frozen=True)
class _Binding:
    kind: str
    certain: bool = True


def _argument(call: ast.Call, index: int, name: str) -> ast.expr | None:
    if len(call.args) > index:
        return call.args[index]
    return next((keyword.value for keyword in call.keywords if keyword.arg == name), None)


def _literal(node: ast.expr | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


class _PythonLoaders(ast.NodeVisitor):
    def __init__(self) -> None:
        self.bindings = {"__import__": _Binding("__import__")}
        self.observations: list[DynamicImport] = []
        self.conditional_depth = 0

    def _resolve(self, node: ast.expr | None) -> _Binding | None:
        if isinstance(node, ast.Name):
            return self.bindings.get(node.id)
        if isinstance(node, ast.Attribute):
            value = self._resolve(node.value)
            if value is not None:
                if value.kind == "importlib" and node.attr == "import_module":
                    return _Binding("import_module", value.certain)
                if value.kind == "builtins" and node.attr == "__import__":
                    return _Binding("__import__", value.certain)
        return None

    def _assign(self, target: ast.expr, value: _Binding | None) -> None:
        if isinstance(target, ast.Name):
            previous = self.bindings.get(target.id)
            if value is not None:
                self.bindings[target.id] = _Binding(
                    value.kind, value.certain and self.conditional_depth == 0
                )
            elif previous is not None:
                # A known loader name can have been rebound to runtime data.
                self.bindings[target.id] = _Binding(previous.kind, False)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._assign(item, None)
        elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            previous = self.bindings.get(target.value.id)
            if previous is not None:
                self.bindings[target.value.id] = _Binding(previous.kind, False)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name in {"importlib", "builtins"}:
                self.bindings[alias.asname or alias.name] = _Binding(
                    alias.name, self.conditional_depth == 0
                )
            else:
                self._assign(ast.Name(id=alias.asname or alias.name.split(".")[0]), None)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level:
            return
        for alias in node.names:
            if (node.module, alias.name) in {
                ("importlib", "import_module"),
                ("builtins", "__import__"),
            }:
                self.bindings[alias.asname or alias.name] = _Binding(
                    alias.name, self.conditional_depth == 0
                )
            else:
                self._assign(ast.Name(id=alias.asname or alias.name), None)

    def _conditional(self, node: ast.AST) -> None:
        # This is not a control-flow proof. A loader selected in a branch,
        # loop or exception path remains uncertain after linear traversal.
        self.conditional_depth += 1
        if isinstance(node, (ast.For, ast.AsyncFor)):
            self._assign(node.target, None)
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, None)
        self.generic_visit(node)
        self.conditional_depth -= 1

    visit_If = _conditional
    visit_For = _conditional
    visit_AsyncFor = _conditional
    visit_While = _conditional
    visit_Try = _conditional
    visit_TryStar = _conditional
    visit_With = _conditional
    visit_AsyncWith = _conditional
    visit_Match = _conditional

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self._assign(ast.Name(id=node.name), None)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        binding = self._resolve(node.value)
        for target in node.targets:
            self._assign(target, binding)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        self._assign(node.target, self._resolve(node.value))

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._assign(node.target, self._resolve(node.value))

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        self._assign(node.target, None)

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> None:
        if not isinstance(node, ast.Lambda):
            for decorator in node.decorator_list:
                self.visit(decorator)
        for value in [*node.args.defaults, *node.args.kw_defaults]:
            if value is not None:
                self.visit(value)
        if not isinstance(node, ast.Lambda):
            self._assign(ast.Name(id=node.name), None)
        previous = self.bindings
        self.bindings = dict(previous)
        args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        if node.args.vararg is not None:
            args.append(node.args.vararg)
        if node.args.kwarg is not None:
            args.append(node.args.kwarg)
        for arg in args:
            binding = self.bindings.get(arg.arg)
            if binding is not None:
                self.bindings[arg.arg] = _Binding(binding.kind, False)
        if isinstance(node, ast.Lambda):
            self.visit(node.body)
        else:
            for statement in node.body:
                self.visit(statement)
        self.bindings = previous

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function
    visit_Lambda = _function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expression in [*node.decorator_list, *node.bases]:
            self.visit(expression)
        for keyword in node.keywords:
            self.visit(keyword.value)
        self._assign(ast.Name(id=node.name), None)
        previous = self.bindings
        self.bindings = dict(previous)
        for statement in node.body:
            self.visit(statement)
        self.bindings = previous

    def visit_Call(self, node: ast.Call) -> None:
        binding = self._resolve(node.func)
        if binding is not None and binding.kind in {"import_module", "__import__"}:
            target = _literal(_argument(node, 0, "name"))
            reason = ""
            if not binding.certain:
                target, reason = None, "loader alias is shadowed or rebound"
            elif not target:
                target, reason = None, "module argument is not a nonempty string literal"
            elif binding.kind == "import_module" and target.startswith("."):
                package = _literal(_argument(node, 1, "package"))
                level = len(target) - len(target.lstrip("."))
                parts = package.split(".") if package else []
                if level > len(parts) or not all(parts):
                    target, reason = None, "relative import has no resolvable literal package"
                else:
                    target = ".".join(parts[: len(parts) - level + 1]) + target[level - 1 :]
            self.observations.append(DynamicImport(node.lineno, binding.kind, target, reason))
        self.generic_visit(node)


@lru_cache(maxsize=8192)
def python_dynamic_imports(source: str) -> tuple[DynamicImport, ...]:
    """Observe literal and unresolved calls through recognized Python aliases."""
    # Every recognized loader is reached through one of these two names, in the
    # call itself or in the import that binds an alias. Most files have neither
    # and need no second parse.
    if "__import__" not in source and "import_module" not in source:
        return ()
    try:
        with warnings.catch_warnings():
            # The scanned project's invalid escapes are not this tool's output.
            warnings.simplefilter("ignore")
            tree = ast.parse(source)
    except SyntaxError:
        # Existing import extraction retains its regex fallback. This helper
        # makes no new claim about a Python file it could not parse.
        return ()
    visitor = _PythonLoaders()
    visitor.visit(tree)
    return tuple(visitor.observations)


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str
    start: int
    literal: bool = False


_JS_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_REGEX_KEYWORDS = {"return", "throw", "case", "delete", "void", "typeof", "yield", "await"}
_CONTROL_KEYWORDS = {"if", "while", "for", "with", "switch", "catch"}
_REGEX_PREFIXES = {"(", "[", "{", "=", ":", ",", ";", "!", "?", "&", "|", "+", "-", "*", "~"}


def _decode_js_string(raw: str) -> str | None:
    """Decode literal escapes without evaluating JavaScript expressions."""
    result: list[str] = []
    index = 0
    escapes = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}
    while index < len(raw):
        char = raw[index]
        if char != "\\":
            result.append(char)
            index += 1
            continue
        index += 1
        if index >= len(raw):
            return None
        escaped = raw[index]
        if escaped in {"x", "u"}:
            length = 2 if escaped == "x" else 4
            digits = raw[index + 1 : index + 1 + length]
            if len(digits) != length or not re.fullmatch(r"[0-9A-Fa-f]+", digits):
                return None
            result.append(chr(int(digits, 16)))
            index += length + 1
        elif escaped in "\r\n":
            index += 2 if escaped == "\r" and raw[index + 1 : index + 2] == "\n" else 1
        else:
            result.append(escapes.get(escaped, escaped))
            index += 1
    return "".join(result)


def _js_tokens(
    source: str, start: int = 0, *, template_expression: bool = False
) -> tuple[list[_Token], int, list[list[_Token]]]:
    """Lex code while keeping template text, strings, comments and regex opaque."""
    tokens: list[_Token] = []
    embedded: list[list[_Token]] = []
    index, braces = start, 0
    regex_allowed = True
    control_parens: list[bool] = []
    while index < len(source):
        char = source[index]
        if char.isspace():
            index += 1
            continue
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            index = len(source) if end == -1 else end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            index = len(source) if end == -1 else end + 2
            continue
        if char in "\"'`":
            quote, opening = char, index
            index += 1
            literal = True
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                elif source[index] == quote:
                    break
                elif quote == "`" and source.startswith("${", index):
                    literal = False
                    inner, end, nested = _js_tokens(source, index + 2, template_expression=True)
                    embedded.extend([inner, *nested])
                    index = end + 1
                else:
                    index += 1
            closed = index < len(source)
            raw = source[opening + 1 : index]
            value = _decode_js_string(raw) if literal and closed else None
            tokens.append(_Token("string", value or "", opening, value is not None))
            index += int(closed)
            regex_allowed = False
            continue
        if char == "/" and regex_allowed:
            opening, in_class = index, False
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                elif source[index] == "[":
                    in_class = True
                    index += 1
                elif source[index] == "]":
                    in_class = False
                    index += 1
                elif source[index] == "/" and not in_class:
                    index += 1
                    while index < len(source) and source[index].isalpha():
                        index += 1
                    break
                elif source[index] in "\r\n":
                    break
                else:
                    index += 1
            tokens.append(_Token("regex", "", opening))
            regex_allowed = False
            continue
        identifier = _JS_IDENTIFIER.match(source, index)
        if identifier is not None:
            value = identifier.group()
            tokens.append(_Token("identifier", value, index))
            index = identifier.end()
            regex_allowed = value in _REGEX_KEYWORDS
            continue
        if char == "}" and template_expression and braces == 0:
            return tokens, index, embedded
        operator = next(
            (
                value
                for value in ("=>", "?.", "++", "--", "&&", "||", "??")
                if source.startswith(value, index)
            ),
            None,
        )
        if operator is not None:
            tokens.append(_Token("punctuation", operator, index))
            index += len(operator)
            regex_allowed = operator not in {"?.", "++", "--"}
            continue
        if char == "{":
            braces += 1
        elif char == "}":
            braces -= 1
        if char == "(":
            control_parens.append(bool(tokens and tokens[-1].value in _CONTROL_KEYWORDS))
        if char == ")":
            regex_allowed = control_parens.pop() if control_parens else False
        else:
            regex_allowed = char in _REGEX_PREFIXES
        tokens.append(_Token("punctuation", char, index))
        index += 1
    return tokens, index, embedded


def _closing_paren(tokens: list[_Token], opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(tokens)):
        if tokens[index].kind == "punctuation" and tokens[index].value == "(":
            depth += 1
        elif tokens[index].kind == "punctuation" and tokens[index].value == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


@lru_cache(maxsize=8192)
def js_dynamic_imports(source: str) -> tuple[DynamicImport, ...]:
    """Recognize named JS loaders, preserving nonliteral targets as unknown.

    This is lexical evidence, not a JS parser or proof of runtime execution.
    Member methods other than the conventional ``module.require`` are ignored;
    imported createRequire aliases and arbitrary function aliases are not resolved.
    """
    root, _, embedded = _js_tokens(source)
    lines = [match.start() for match in re.finditer("\n", source)]
    observations: list[DynamicImport] = []
    for tokens in [root, *embedded]:
        for index, token in enumerate(tokens):
            if token.kind != "identifier" or token.value not in {"require", "import"}:
                continue
            if index + 1 >= len(tokens) or tokens[index + 1].value != "(":
                continue
            previous = tokens[index - 1].value if index else ""
            module_require = (
                token.value == "require"
                and index >= 2
                and previous == "."
                and tokens[index - 2].value == "module"
            )
            if (previous in {".", "?."} and not module_require) or previous in {"function", "new"}:
                continue
            closing = _closing_paren(tokens, index + 1)
            if (
                closing is not None
                and closing + 1 < len(tokens)
                and tokens[closing + 1].value == "{"
            ):
                continue  # object/class method declaration, not a loader call
            arguments = tokens[index + 2 : closing]
            first: list[_Token] = []
            depth = 0
            for arg in arguments:
                if arg.kind == "punctuation" and arg.value == "," and depth == 0:
                    break
                first.append(arg)
                if arg.kind == "punctuation" and arg.value in {"(", "[", "{"}:
                    depth += 1
                elif arg.kind == "punctuation" and arg.value in {")", "]", "}"}:
                    depth -= 1
            target = None
            if (
                closing is not None
                and len(first) == 1
                and first[0].kind == "string"
                and first[0].literal
                and first[0].value
            ):
                target = first[0].value
            loader = "module.require" if module_require else token.value
            observations.append(
                DynamicImport(
                    bisect_right(lines, token.start) + 1,
                    loader,
                    target,
                    "" if target else "module argument is not a nonempty string literal",
                )
            )
    return tuple(observations)
