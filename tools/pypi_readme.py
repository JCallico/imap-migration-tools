#!/usr/bin/env python3
"""Make README links absolute so the long description renders on PyPI.

``README.md`` uses repository-relative links (``docs/gui.md``, ``docs/images/x.png``) so GitHub shows the files of the
branch being viewed. PyPI renders the README embedded in the package, outside the repository, where those links are
broken. At release time this script rewrites each relative link in a throwaway checkout to a URL pinned to the release
tag (or any commit), so every published release keeps pointing at the files it was built from.

    python tools/pypi_readme.py --repo OWNER/NAME --ref v1.2.3 [--readme README.md] [--output PATH]

Links inside fenced code blocks and inline code are left alone. A relative link to a file that does not exist, or one
that escapes the repository, is an error, so a broken link also fails pull requests that run this script in CI.
"""

from __future__ import annotations

import argparse
import posixpath
import re
import sys
from pathlib import Path
from urllib.parse import quote

IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")
_REFERENCE = re.compile(r"^[ ]{0,3}\[[^\]\n]+\]:[ \t]*(?P<target><[^>\n]*>|\S+)", re.MULTILINE)
_FENCE = re.compile(
    r"^[ ]{0,3}(?P<fence>`{3,}|~{3,}).*?(?:^[ ]{0,3}(?P=fence)[`~]*[ \t]*$|\Z)", re.MULTILINE | re.DOTALL
)
_CODE_SPAN = re.compile(r"(?P<ticks>`+)(?!`).+?(?<!`)(?P=ticks)(?!`)", re.DOTALL)
_TAG = re.compile(r"<[A-Za-z][^>]*>")
_ATTRIBUTE = re.compile(r"""\b(?P<name>src|href)\s*=\s*(?P<quote>["'])(?P<target>[^"']*)(?P=quote)""", re.IGNORECASE)
_REF = re.compile(r"[A-Za-z0-9._/\-]+")


class LinkError(ValueError):
    """A relative link that cannot be made absolute."""


def _mask_code(text: str) -> str:
    """Blank out code so link syntax inside it is never rewritten, keeping every offset intact."""

    def blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", "\x00", match.group(0))

    return _CODE_SPAN.sub(blank, _FENCE.sub(blank, text))


def _is_relative(target: str) -> bool:
    return bool(target) and not target.startswith("#") and not target.startswith("//") and not _SCHEME.match(target)


def _is_image(target: str, usage: str) -> bool:
    return usage == "image" or (usage == "reference" and target.split("#")[0].lower().endswith(IMAGE_SUFFIXES))


def _absolute(target: str, usage: str, repo: str, ref: str, root: Path) -> str:
    path, hash_mark, fragment = target.partition("#")
    path, question, query = path.partition("?")
    normalized = posixpath.normpath(path.lstrip("/")) if path.lstrip("/") else "."
    if normalized == ".." or normalized.startswith("../"):
        raise LinkError(f"{target}: the link leaves the repository")
    resolved = root / normalized
    if not resolved.exists():
        raise LinkError(f"{target}: no such file in the repository")
    suffix = (question + query if question else "") + (hash_mark + fragment if hash_mark else "")
    quoted = quote(normalized if normalized != "." else "", safe="/")
    if _is_image(target, usage):
        return f"https://raw.githubusercontent.com/{repo}/{ref}/{quoted}"
    kind = "tree" if resolved.is_dir() else "blob"
    return f"https://github.com/{repo}/{kind}/{ref}/{quoted}{suffix}"


def _matching_bracket(masked: str, close: int) -> int:
    """Return the index of the ``[`` matching the ``]`` at ``close``, or -1."""
    depth = 0
    for index in range(close, -1, -1):
        char = masked[index]
        if char == "]" and (index == 0 or masked[index - 1] != "\\"):
            depth += 1
        elif char == "[" and (index == 0 or masked[index - 1] != "\\"):
            depth -= 1
            if depth == 0:
                return index
    return -1


def _inline_targets(masked: str) -> list[tuple[int, int, str]]:
    """Find ``[text](target)`` and ``![alt](target)`` targets as (start, end, usage-flavoured) spans."""
    found: list[tuple[int, int, str]] = []
    for match in re.finditer(r"\]\(", masked):
        position = match.end()
        while position < len(masked) and masked[position] in " \t":
            position += 1
        if position < len(masked) and masked[position] == "<":
            end = masked.find(">", position)
            start, end = position + 1, end if end != -1 else position + 1
        else:
            start = end = position
            while end < len(masked) and masked[end] not in " \t\n)":
                end += 1
        opening = _matching_bracket(masked, match.start())
        usage = "image" if opening > 0 and masked[opening - 1] == "!" else "link"
        found.append((start, end, usage))
    return found


def _html_targets(masked: str) -> list[tuple[int, int, str]]:
    found: list[tuple[int, int, str]] = []
    for tag in _TAG.finditer(masked):
        for attribute in _ATTRIBUTE.finditer(tag.group(0)):
            start = tag.start() + attribute.start("target")
            usage = "image" if attribute.group("name").lower() == "src" else "link"
            found.append((start, tag.start() + attribute.end("target"), usage))
    return found


def _reference_targets(masked: str) -> list[tuple[int, int, str]]:
    found: list[tuple[int, int, str]] = []
    for match in _REFERENCE.finditer(masked):
        start, end = match.span("target")
        if masked[start] == "<":
            start, end = start + 1, end - 1
        found.append((start, end, "reference"))
    return found


def _targets(text: str) -> list[tuple[int, int, str]]:
    masked = _mask_code(text)
    spans = _inline_targets(masked) + _html_targets(masked) + _reference_targets(masked)
    return sorted(set(spans))


def relative_targets(text: str) -> list[str]:
    """List the relative link targets still present in ``text``."""
    return [text[start:end] for start, end, _usage in _targets(text) if _is_relative(text[start:end])]


def make_absolute(text: str, repo: str, ref: str, root: Path) -> str:
    """Return ``text`` with every relative link rewritten to an absolute URL pinned to ``ref``."""
    if not _REF.fullmatch(ref):
        raise LinkError(f"{ref!r} is not a valid tag or commit")
    pieces: list[str] = []
    cursor = 0
    problems: list[str] = []
    for start, end, usage in _targets(text):
        target = text[start:end]
        if not _is_relative(target) or start < cursor:
            continue
        try:
            replacement = _absolute(target, usage, repo, ref, root)
        except LinkError as error:
            problems.append(str(error))
            continue
        pieces.append(text[cursor:start])
        pieces.append(replacement)
        cursor = end
    if problems:
        raise LinkError("; ".join(problems))
    pieces.append(text[cursor:])
    return "".join(pieces)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Rewrite relative README links to absolute URLs for PyPI.")
    parser.add_argument("--repo", required=True, help="GitHub repository, for example OWNER/NAME")
    parser.add_argument("--ref", required=True, help="release tag or commit the links are pinned to")
    parser.add_argument("--readme", type=Path, default=Path("README.md"), help="README to rewrite")
    parser.add_argument("--output", type=Path, help="write here instead of rewriting the README in place")
    args = parser.parse_args(argv)
    original = args.readme.read_text(encoding="utf-8")
    try:
        rewritten = make_absolute(original, args.repo, args.ref, args.readme.resolve().parent)
    except LinkError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    leftover = relative_targets(rewritten)
    if leftover:
        print(f"error: relative links remain: {', '.join(leftover)}", file=sys.stderr)
        return 1
    destination = args.output or args.readme
    destination.write_text(rewritten, encoding="utf-8")
    print(f"Rewrote {len(relative_targets(original))} relative link(s) in {destination} to {args.repo}@{args.ref}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
