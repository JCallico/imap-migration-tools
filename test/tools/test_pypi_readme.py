"""Tests for the release-time rewrite of relative README links to absolute URLs."""

from pathlib import Path

import pytest

import pypi_readme
from pypi_readme import LinkError, main, make_absolute, relative_targets

REPO = "OWNER/project"
RAW = f"https://raw.githubusercontent.com/{REPO}/v1.2.3"
BLOB = f"https://github.com/{REPO}/blob/v1.2.3"


@pytest.fixture
def root(tmp_path):
    (tmp_path / "docs" / "images").mkdir(parents=True)
    for name in ("docs/gui.md", "docs/images/shot.png", "docs/images/my shot.png", "LICENSE", "docs/a.md"):
        (tmp_path / name).write_text("x", encoding="utf-8")
    return tmp_path


def rewrite(text, root):
    return make_absolute(text, REPO, "v1.2.3", root)


def test_inline_links_and_images_use_blob_and_raw_urls(root):
    text = "See [the guide](docs/gui.md) and ![shot](docs/images/shot.png) and [license](LICENSE)."

    assert rewrite(text, root) == (
        f"See [the guide]({BLOB}/docs/gui.md) and ![shot]({RAW}/docs/images/shot.png) and [license]({BLOB}/LICENSE)."
    )


def test_a_badge_rewrites_the_inner_image_and_leaves_the_outer_absolute_link(root):
    text = "[![shield](docs/images/shot.png)](https://example.com/ci)"

    assert rewrite(text, root) == f"[![shield]({RAW}/docs/images/shot.png)](https://example.com/ci)"


def test_a_relative_image_inside_a_relative_link_rewrites_both(root):
    text = "[![shield](docs/images/shot.png)](docs/gui.md)"

    assert rewrite(text, root) == f"[![shield]({RAW}/docs/images/shot.png)]({BLOB}/docs/gui.md)"


def test_html_img_src_and_anchor_href_are_rewritten(root):
    text = '<p><img src="docs/images/shot.png" width="420"> <a href=\'docs/gui.md\'>gui</a></p>'

    assert (
        rewrite(text, root)
        == f'<p><img src="{RAW}/docs/images/shot.png" width="420"> <a href=\'{BLOB}/docs/gui.md\'>gui</a></p>'
    )


def test_reference_definitions_follow_the_file_type(root):
    text = "[guide]: docs/gui.md\n[shot]: <docs/images/shot.png>\n[web]: https://example.com\n"

    assert rewrite(text, root) == (
        f"[guide]: {BLOB}/docs/gui.md\n[shot]: <{RAW}/docs/images/shot.png>\n[web]: https://example.com\n"
    )


def test_fragments_titles_dot_prefixes_and_directories(root):
    text = '[a](./docs/gui.md#install) [b](docs/a.md "Title") [c](docs/) [d](docs/gui.md?plain=1)'

    assert rewrite(text, root) == (
        f'[a]({BLOB}/docs/gui.md#install) [b]({BLOB}/docs/a.md "Title") '
        f"[c](https://github.com/{REPO}/tree/v1.2.3/docs) [d]({BLOB}/docs/gui.md?plain=1)"
    )


def test_spaces_in_paths_are_percent_encoded(root):
    assert rewrite("![x](<docs/images/my shot.png>)", root) == f"![x](<{RAW}/docs/images/my%20shot.png>)"


def test_absolute_anchor_mail_and_network_path_links_are_untouched(root):
    text = "[a](https://x.example/a) [b](#install) [c](mailto:me@example.com) [d](//cdn.example/x.png) [e]()"

    assert rewrite(text, root) == text
    assert relative_targets(text) == []


def test_code_blocks_and_code_spans_are_never_rewritten(root):
    text = (
        "Use `[x](docs/gui.md)` inline.\n\n```markdown\n[y](docs/gui.md)\n![z](docs/images/shot.png)\n```\n\n"
        "~~~\n[w](docs/gui.md)\n~~~\n\nReal [link](docs/gui.md).\n"
    )

    result = rewrite(text, root)

    assert "`[x](docs/gui.md)`" in result and "[y](docs/gui.md)" in result and "[w](docs/gui.md)" in result
    assert f"Real [link]({BLOB}/docs/gui.md)." in result
    assert relative_targets(result) == []


def test_an_unterminated_fence_protects_the_rest_of_the_document(root):
    text = "[a](docs/gui.md)\n```\n[b](docs/gui.md)\n"

    assert rewrite(text, root) == f"[a]({BLOB}/docs/gui.md)\n```\n[b](docs/gui.md)\n"


def test_rewriting_is_idempotent(root):
    once = rewrite("[a](docs/gui.md) ![b](docs/images/shot.png)", root)

    assert rewrite(once, root) == once


def test_a_missing_file_is_reported_with_every_problem(root):
    with pytest.raises(LinkError) as caught:
        rewrite("[a](docs/missing.md) ![b](docs/images/gone.png)", root)

    assert "docs/missing.md" in str(caught.value) and "docs/images/gone.png" in str(caught.value)


@pytest.mark.parametrize("target", ["../outside.md", "docs/../../outside.md"])
def test_links_that_leave_the_repository_are_rejected(root, target):
    with pytest.raises(LinkError, match="leaves the repository"):
        rewrite(f"[a]({target})", root)


@pytest.mark.parametrize("ref", ["", "bad ref", "v1;rm", "tag\n"])
def test_an_unsafe_ref_is_rejected(root, ref):
    with pytest.raises(LinkError, match="not a valid tag or commit"):
        make_absolute("[a](docs/gui.md)", REPO, ref, root)


def test_a_commit_sha_or_slashed_tag_is_accepted(root):
    assert f"https://github.com/{REPO}/blob/release/1.2/docs/gui.md" in make_absolute(
        "[a](docs/gui.md)", REPO, "release/1.2", root
    )


def test_command_line_rewrites_in_place_and_to_an_output_file(root, capsys):
    readme = root / "README.md"
    readme.write_text("[a](docs/gui.md)\n", encoding="utf-8")

    assert main(["--repo", REPO, "--ref", "v1.2.3", "--readme", str(readme), "--output", str(root / "out.md")]) == 0
    assert readme.read_text(encoding="utf-8") == "[a](docs/gui.md)\n"
    assert (root / "out.md").read_text(encoding="utf-8") == f"[a]({BLOB}/docs/gui.md)\n"
    assert main(["--repo", REPO, "--ref", "v1.2.3", "--readme", str(readme)]) == 0
    assert readme.read_text(encoding="utf-8") == f"[a]({BLOB}/docs/gui.md)\n"
    assert "Rewrote 1 relative link(s)" in capsys.readouterr().out


def test_command_line_fails_without_writing_when_a_link_is_broken(root, capsys):
    readme = root / "README.md"
    readme.write_text("[a](docs/missing.md)\n", encoding="utf-8")

    assert main(["--repo", REPO, "--ref", "v1.2.3", "--readme", str(readme)]) == 1
    assert readme.read_text(encoding="utf-8") == "[a](docs/missing.md)\n"
    assert "docs/missing.md" in capsys.readouterr().err


def test_command_line_fails_when_a_relative_link_survives(root, monkeypatch, capsys):
    readme = root / "README.md"
    readme.write_text("[a](docs/gui.md)\n", encoding="utf-8")
    monkeypatch.setattr(pypi_readme, "make_absolute", lambda text, *args: text)

    assert main(["--repo", REPO, "--ref", "v1.2.3", "--readme", str(readme)]) == 1
    assert "relative links remain" in capsys.readouterr().err


def test_the_repository_readme_can_be_made_fully_absolute():
    repository = Path(__file__).resolve().parents[2]
    text = (repository / "README.md").read_text(encoding="utf-8")

    result = make_absolute(text, "JCallico/imap-migration-tools", "v1.0.0", repository)

    assert relative_targets(result) == []
    assert "https://github.com/JCallico/imap-migration-tools/blob/v1.0.0/docs/gui.md" in result
