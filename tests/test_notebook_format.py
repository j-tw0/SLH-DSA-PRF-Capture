"""Check that Jupyter notebooks are valid and code cells parse as Python.

No ChipWhisperer hardware is required. Run from the repository root:
    python tests/test_notebook_format.py
"""
from __future__ import annotations

import ast
from pathlib import Path

import nbformat

ROOT = Path(__file__).resolve().parents[1]
NOTEBOOKS = ROOT / "notebooks"


def main() -> None:
    paths = sorted(NOTEBOOKS.glob("*.ipynb"))
    if not paths:
        raise AssertionError("No notebooks found in notebooks/")
    for path in paths:
        # Reading raises for malformed JSON (e.g., an unescaped quote).
        notebook = nbformat.read(path, as_version=4)
        nbformat.validate(notebook)
        for index, cell in enumerate(notebook.cells):
            if cell.cell_type == "code":
                try:
                    ast.parse(cell.source, filename=f"{path.name}:cell{index}")
                except SyntaxError as exc:
                    raise AssertionError(f"Invalid Python in {path.name}, cell {index}") from exc
        print(f"PASS: {path.relative_to(ROOT)}")
    print(f"Notebook format checks passed: {len(paths)} file(s)")


if __name__ == "__main__":
    main()
