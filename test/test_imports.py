#!/usr/bin/env python3
"""
Static analysis tests for azfilesauth Python scripts.

These tests catch common errors such as:
- Syntax errors in .py and .py.in files
- Undefined names (functions/variables used but never defined or imported)
- Missing imports (names imported from azfilesauth that don't exist in azfilesauthmanager.py)

Run: python3 test/test_imports.py
Exit code 0 = all passed, 1 = failures found.
"""

import ast
import os
import re
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(REPO_ROOT, "src")

# ---------- helpers ----------

def read_py_source(path):
    """Read a .py or .py.in file, stripping autoconf @VAR@ substitutions."""
    with open(path, "r") as f:
        source = f.read()
    # Replace "@FOO@" (quoted) or @FOO@ (bare) with a valid Python string
    source = re.sub(r'"@\w+@"', '"/dev/null"', source)
    source = re.sub(r"'@\w+@'", '"/dev/null"', source)
    source = re.sub(r"@\w+@", '"/dev/null"', source)
    return source


def get_top_level_names(path):
    """Return the set of top-level function and class names defined in a Python file."""
    source = read_py_source(path)
    tree = ast.parse(source, filename=path)
    names = set()
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


def get_imports_from_module(path, module_name):
    """Return names imported from `module_name` in the given file.
    e.g. 'from azfilesauth import foo, bar' -> {'foo', 'bar'}
    """
    source = read_py_source(path)
    tree = ast.parse(source, filename=path)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == module_name:
            for alias in node.names:
                imported.add(alias.name)
    return imported


def collect_defined_names(path):
    """Collect all names that are defined or imported in a file (for undefined-name checks)."""
    source = read_py_source(path)
    tree = ast.parse(source, filename=path)
    defined = set()

    # builtins
    import builtins
    defined.update(dir(builtins))

    for node in ast.walk(tree):
        # function/class defs
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defined.add(node.name)
            for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
                defined.add(arg.arg)
            if node.args.vararg:
                defined.add(node.args.vararg.arg)
            if node.args.kwarg:
                defined.add(node.args.kwarg.arg)
        elif isinstance(node, ast.ClassDef):
            defined.add(node.name)
        # assignments
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    defined.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            defined.add(node.target.id)
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            defined.add(node.target.id)
        # for/with targets
        elif isinstance(node, ast.For) and isinstance(node.target, ast.Name):
            defined.add(node.target.id)
        elif isinstance(node, ast.With):
            for item in node.items:
                if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                    defined.add(item.optional_vars.id)
        # imports
        elif isinstance(node, ast.Import):
            for alias in node.names:
                defined.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                defined.add(alias.asname or alias.name)
        # comprehension variables
        elif isinstance(node, ast.comprehension) and isinstance(node.target, ast.Name):
            defined.add(node.target.id)
        # exception handlers
        elif isinstance(node, ast.ExceptHandler) and node.name:
            defined.add(node.name)
        # named expressions (walrus)
        elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            defined.add(node.target.id)
        # global/nonlocal
        elif isinstance(node, ast.Global):
            defined.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            defined.update(node.names)

    return defined


def collect_used_names(path):
    """Collect all Name nodes used in non-definition contexts at the module's top-level functions."""
    source = read_py_source(path)
    tree = ast.parse(source, filename=path)
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            used.add(node.id)
    return used


# ---------- tests ----------

class TestSyntax(unittest.TestCase):
    """Verify all Python source files parse without syntax errors."""

    def _check_syntax(self, path):
        source = read_py_source(path)
        try:
            ast.parse(source, filename=path)
        except SyntaxError as e:
            self.fail(f"Syntax error in {path}: {e}")

    def test_azfilesrefresh_syntax(self):
        self._check_syntax(os.path.join(SRC_DIR, "azfilesrefresh.py.in"))

    def test_azfilesauthmanager_syntax(self):
        self._check_syntax(os.path.join(SRC_DIR, "azfilesauthmanager.py"))

    def test_config_syntax(self):
        config_py = os.path.join(SRC_DIR, "config.py")
        if os.path.exists(config_py):
            self._check_syntax(config_py)


class TestImportsResolvable(unittest.TestCase):
    """Verify that all names imported from 'azfilesauth' in azfilesrefresh.py.in
    actually exist in azfilesauthmanager.py (which provides the azfilesauth package)."""

    def test_azfilesrefresh_imports_from_azfilesauth(self):
        refresh_path = os.path.join(SRC_DIR, "azfilesrefresh.py.in")
        manager_path = os.path.join(SRC_DIR, "azfilesauthmanager.py")

        imported_names = get_imports_from_module(refresh_path, "azfilesauth")
        available_names = get_top_level_names(manager_path)

        missing = imported_names - available_names
        self.assertFalse(
            missing,
            f"azfilesrefresh.py.in imports {missing} from azfilesauth, "
            f"but these names are not defined in azfilesauthmanager.py.\n"
            f"Available: {sorted(available_names)}"
        )


class TestNoUndefinedNames(unittest.TestCase):
    """Check that top-level function calls in key scripts reference defined names."""

    def _check_undefined(self, path):
        defined = collect_defined_names(path)
        used = collect_used_names(path)
        # Only flag names that look like our project functions (lowercase, underscore)
        # Skip single-char names, dunder names, and common dynamic attrs
        undefined = set()
        for name in used - defined:
            if name.startswith("_"):
                continue
            if len(name) <= 1:
                continue
            undefined.add(name)
        return undefined

    def test_azfilesrefresh_no_undefined(self):
        path = os.path.join(SRC_DIR, "azfilesrefresh.py.in")
        undefined = self._check_undefined(path)
        self.assertFalse(
            undefined,
            f"Potentially undefined names in azfilesrefresh.py.in: {sorted(undefined)}"
        )

    def test_azfilesauthmanager_no_undefined(self):
        path = os.path.join(SRC_DIR, "azfilesauthmanager.py")
        undefined = self._check_undefined(path)
        self.assertFalse(
            undefined,
            f"Potentially undefined names in azfilesauthmanager.py: {sorted(undefined)}"
        )


class TestCrossScriptConsistency(unittest.TestCase):
    """Verify that the azfilesauth package __init__.py pattern
    (from .azfilesauthmanager import *) will export all names
    that azfilesrefresh.py.in expects."""

    def test_all_refresh_dependencies_available(self):
        refresh_path = os.path.join(SRC_DIR, "azfilesrefresh.py.in")
        manager_path = os.path.join(SRC_DIR, "azfilesauthmanager.py")

        # Names that azfilesrefresh imports from azfilesauth
        needed = get_imports_from_module(refresh_path, "azfilesauth")
        # Names that azfilesauthmanager defines at top level (exported via import *)
        exported = get_top_level_names(manager_path)

        missing = needed - exported
        self.assertFalse(
            missing,
            f"azfilesrefresh needs {sorted(missing)} from the azfilesauth package, "
            f"but azfilesauthmanager.py does not define them.\n"
            f"Either add the definition to azfilesauthmanager.py or fix the import."
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
