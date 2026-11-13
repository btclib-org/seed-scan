# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Configuration file for the Sphinx documentation builder.

For the full list of built-in configuration values, see the
documentation:
https://www.sphinx-doc.org/en/master/usage/configuration.html
"""

import posixpath
import re
import tomllib
from pathlib import Path

from docutils import nodes
from sphinx.addnodes import pending_xref
from sphinx.application import Sphinx
from sphinx.transforms.post_transforms import SphinxPostTransform

# the repository root, two levels up from this file, and the one place
# below that is allowed to name it
ROOT = Path(__file__).parents[2].resolve()
# read once, for the author and version below and the github url the
# transform at the bottom builds its links on
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = PYPROJECT["project"]["name"]
# pyproject.toml's `authors` table, the one place the holder is
# declared: PYPROJECT is already parsed above, so this is a second read
# of it rather than a second literal
author = PYPROJECT["project"]["authors"][0]["name"]
# the holder the MIT notice names, which is that same author, and no year:
# COPYRIGHT and LICENSE state none, a year being a thing that looks out of
# date every January without anything having changed
project_copyright = author
# read from pyproject.toml, the one place the version is declared, and not
# from importlib.metadata: the value should not depend on whether the
# package happens to be installed in the environment building the
# documentation (btclib-org/.github#1098)
release = PYPROJECT["project"]["version"]

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    # first, because -n below turns an unresolved cross-reference into a
    # warning and the annotations of this package name what the standard
    # library owns: without an inventory to resolve against,
    # `collections.abc.Sequence` is reported as this tree's own broken link
    # and the triage measures sphinx's ignorance rather than the
    # documentation
    "sphinx.ext.intersphinx",
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx.ext.coverage",
    "sphinx.ext.githubpages",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
]

# no sphinx.ext.todo: with todo_include_todos left at its default a
# `.. todo::` renders as nothing at all, so the directive is a note to
# nobody. Without the extension it is an unknown directive, which -W turns
# into a failed build -- the open questions belong in the issue tracker

# the standard library, whose types the signatures name
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", (None, "_inventories/python.inv")),
}
# `_inventories/python.inv` is a copy of Python 3.14's inventory and no
# cache: sphinx reads it only when `docs.python.org` fails, so a live site
# always wins. It is the Wayback Machine's capture of 2026-08-28,
# https://web.archive.org/web/20260828181213id_/https://docs.python.org/3/objects.inv
# To refresh it, run this from the repository root and rewrite the version
# and source above:
# curl -fsSL -o docs/source/_inventories/python.inv https://docs.python.org/3/objects.inv

# the one type of a sibling a signature names, `seed_scan.scan.scan`'s
# reader. Ignored rather than resolved: an inventory of btclib-wallet
# would be a second one the build fetches, with no copy to fall back on
nitpick_ignore = [("py:class", "btclib_wallet.fetch.history.HistoryReader")]

source_suffix = [".rst", ".md"]

# anchors for h1 to h6, which is what makes a link into a heading of a
# root markdown file resolve here. Without it myst generates no anchor at
# all, so a link GitHub and PyPI both follow, the anchor being what those
# two derive from the heading text, becomes an xref to a target no page
# has, and -W fails the build. Six is every level markdown heads at,
# which makes the number a fixed point rather than one re-derived from
# files that move: section 2 of the organization's standard says so, and
# names a depth read off this tree's own headings as the rejected
# alternative. Part of what such a
# re-derivation would read is not this tree's to hold still either --
# section 14 ports CONTRIBUTING.md's shared half into every repository,
# so a heading added there moves the depth in each of them at once
myst_heading_anchors = 6

# no suppress_warnings, and myst.xref_missing least of all: the transform
# at the bottom of this file resolves every link the included root files
# carry, so a myst target still missing is a link with nowhere to go and
# -W is what says so. Suppressing that subtype hides the defect rather than
# the noise, because what myst emits for a target it cannot resolve is not
# a visibly broken link, it is an anchor to an id the page does not have

exclude_patterns: list[str] = []


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

# furo: content first, the navigation in the left sidebar and the page's
# own contents in the right, light and dark from one setting -- the shape
# a reference generated from docstrings has. Section 2 of the organization's
# standard is where it was weighed against shibuya, whose landing pages
# and announcement bars are surface this tree would carry and not use;
# sphinx_rtd_theme is where a Read the Docs project starts by default,
# which is a reason to find it in a tree rather than to keep it
html_theme = "furo"

# no html_static_path: this project overrides no stylesheet and ships no
# image, so the "_static" the sphinx template declares names a directory
# that does not exist, and sphinx warns about it on every build, which -W
# turns into a failure. The setting arrives with the directory, not before
# it


# -- Links out of the included root markdown files ----------------------------

# Some pages of the toctree are this repository's root markdown files,
# each pulled into a *_link.md shim by a myst {include}. The code below
# reads the include of every docs/source/*.md page, so adding a shim needs
# no edit here. Those files are written for the places that read them
# unrendered: the GitHub file view and, for README.md, the PyPI long
# description. So a root file links another as "./SECURITY.md", the
# spelling links.yml checks, resolving it as a path relative to the file.
# Sphinx sees them lifted out of the tree that makes it correct, and myst
# resolves not one of those links. README.md links it as BLOB plus its
# path, PyPI resolving no relative link against the tree (section 2 of the
# organization's standard), and myst renders that as a link to GitHub.
#
# What myst emits for a relative link is the reason this needs code
# rather than a warning filter: a target myst cannot resolve becomes an
# anchor on the page it is already on, href="#./SECURITY.md", an id
# nothing has. The build succeeds, -W sees nothing, and lychee reads the
# sources, where the path is right.
#
# The transform below answers each link from the repository rather than
# from a table that would have to be kept in step with this directory: a
# path a page of docs/source includes, or a page of docs/source itself,
# becomes a reference to that page, whether written relative or as BLOB
# plus the path; any other relative path that exists in the tree becomes
# a link to the file on GitHub, and a relative path that exists nowhere
# is left to myst -- which reports it, and -W then fails, no
# suppress_warnings hiding the subtype.
#
# It also reads a link written this way on a page that includes no file,
# resolved against the document that wrote it. A page under docs/source
# is itself read unrendered on the forge, so a link composed relative to
# its own file -- "../../README.md#installing", climbing out of
# docs/source the way a checkout resolves it -- works there verbatim,
# and this is what lets the same link resolve here too, through the shim
# page that carries the heading once the {include} has run.
#
# Not the {include} directive's :relative-docs: option, which is what it
# looks like the job of. It rewrites destinations that begin with the
# prefix it is given, so "docs/source/" leaves "./SECURITY.md" untouched;
# and giving it "./" is worse than doing nothing, measured -- the
# destination becomes "../../SECURITY.md", a path outside srcdir that is
# no document, sphinx reads it as a download, finds nothing to copy, and
# renders the link text with no link at all.
#
# Not copying the root files into this directory at build time either.
# README.md links to LICENSE, which is not part of the documentation --
# no page includes it, which is what decides it -- so copies leave that
# link dead however many are made; and the copies are generated files in
# a source tree, which is a second definition of files that already
# exist.

# main, not a permalink pinned to a commit: these are navigation links
# to files that keep changing, and a reader following one wants the file
# as it stands. The base url comes from pyproject.toml, where every url
# this project publishes is declared
BLOB = f"{PYPROJECT['project']['urls']['repository']}/blob/main/"


# a line opening or closing a fence: the spaces before it, its marker, and
# the info string after it, which holds no backtick after one of them.
# Behind four spaces, a line at the top level of a page is no fence. The
# info string is trimmed of spaces and tabs only, as markdown-it reads a
# closer; MyST reads an opener's info string through `str.strip`

FENCE = re.compile(r"^( {0,3})(`{3,}(?=[^`]*$)|~{3,})[ \t]*(.*?)[ \t]*$")

# the info string of an include fence; its argument runs to the end of the line
INCLUDE = re.compile(r"^\{include\}\s+(.+)$")

# the name of the directive an info string opens, and the text after it
DIRECTIVE = re.compile(r"^\{([^}\s]+)\}(?:\s+(.*))?$")

# a line that may open a list item, a block quote or a footnote
# definition, a thematic break such as `* * *` among them
CONTAINER = re.compile(
    r"^ {0,3}(?:(?:[-+*]|[0-9]{1,9}[.)])(?:[ \t]|$)|>|\[\^[^\] ]+\]:)"
)

# a line opening a list item: the spaces before it, its marker, and the
# one to four spaces before the item's text, empty where none such follow
ITEM = re.compile(r"^( {0,3})([-+*]|[0-9]{1,9}[.)])( {1,4}(?=[^ \t])|(?= |$))")

# the html blocks that run past a blank line, to the line holding their
# closing string: each opening pattern, and that string
HTML_BLOCKS = (
    (
        re.compile(r"^ {0,3}<(?:script|pre|style|textarea)(?=\s|>|$)", re.IGNORECASE),
        re.compile(r"</(?:script|pre|style|textarea)>", re.IGNORECASE),
    ),
    # CommonMark ends a comment at `-->` only. Written `-{2}>`, which
    # CodeQL's py/bad-tag-filter, asking an html filter to end a comment
    # at `--!>` too, does not take for one
    (re.compile(r"^ {0,3}<!--"), re.compile(r"-{2}>")),
    (re.compile(r"^ {0,3}<\?"), re.compile(r"\?>")),
    (re.compile(r"^ {0,3}<![A-Z]"), re.compile(r">")),
    (re.compile(r"^ {0,3}<!\[CDATA\["), re.compile(r"\]\]>")),
)

# a line opening an html block that ends at a blank line, below a
# paragraph too: its tag is one of the names markdown-it-py's
# `html_blocks` lists
HTML_NAMED = re.compile(
    r"^ {0,3}</?(?:address|article|aside|base|basefont|blockquote|body|caption"
    r"|center|col|colgroup|dd|details|dialog|dir|div|dl|dt|fieldset"
    r"|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr"
    r"|html|iframe|legend|li|link|main|menu|menuitem|nav|noframes|ol"
    r"|optgroup|option|p|param|search|section|summary|table|tbody|td"
    r"|tfoot|th|thead|title|tr|track|ul)(?=\s|/?>|$)",
    re.IGNORECASE,
)

# a line opening an html block that ends at a blank line, where no
# paragraph is open: one opening or closing tag, alone. It matches the
# lines that markdown-it-py's pattern, built from its `open_tag` and
# `close_tag`, matches, and reads each one way. There `\s` and an unquoted
# value both take whitespace above \x20, so a line of such attributes
# has many readings and takes time exponential in their number to
# refuse. Here an unquoted value holds that whitespace, and ends before
# it only where one attribute name and `=` follow.

# whitespace `\s` matches up to \x20, which ends an unquoted value
_LOW_SPACE = r"[\t-\r\x1c-\x20]"
# whitespace `\s` matches above \x20, which an unquoted value may hold
_HIGH_SPACE = r"[^\S\x00-\x20]"
# an attribute name, and the names of attributes with no value
_NAME = r"[a-zA-Z_:][a-zA-Z0-9:._-]*"
_NAMES = rf"{_NAME}(?:\s+{_NAME})*\s*"
# a value after `=`, quoted or not
_QUOTED = r"\s*(?:'[^']*'|\"[^\"]*\")"
_UNQUOTED = rf"\s*[^\s\"'=<>`\x00-\x20]+(?:{_HIGH_SPACE}+[^\s\"'=<>`\x00-\x20]+)*"
# from a `=` to the next: a value, then the names up to it. One name
# alone follows an unquoted value with only whitespace above \x20 after
# it, and a value of such whitespace alone: with more, the first of them
# reads as a value or a part of one
_TO_EQUALS = (
    rf"(?:{_QUOTED}\s+{_NAMES}"
    rf"|{_UNQUOTED}(?:{_HIGH_SPACE}*{_LOW_SPACE}\s*{_NAMES}"
    rf"|{_HIGH_SPACE}+{_NAME}\s*)"
    rf"|{_LOW_SPACE}*{_HIGH_SPACE}\s+{_NAME}\s*)"
)
# from the last `=` to the closing `>`: a `/` after an unquoted value,
# with no whitespace up to \x20 between them, is the value's
_TO_END = (
    rf"(?:{_QUOTED}(?:\s+{_NAMES}|\s*)/?>"
    rf"|{_UNQUOTED}{_HIGH_SPACE}*(?:{_LOW_SPACE}\s*(?:{_NAMES})?/?)?>"
    rf"|{_LOW_SPACE}*{_HIGH_SPACE}\s*>)"
)
HTML_TAG = re.compile(
    r"^ {0,3}(?:<[A-Za-z][A-Za-z0-9-]*"
    rf"(?:\s+{_NAMES}=(?:{_TO_EQUALS}=)*{_TO_END}|(?:\s+{_NAMES}|\s*)/?>)"
    r"|</[A-Za-z][A-Za-z0-9-]*\s*>)\s*$"
)

# what ends an html block of `HTML_NAMED` or `HTML_TAG`
BLANK = re.compile(r"^[ \t]*$")

# a heading opened by `#`, or a thematic break, which no list item opens
HEADING = re.compile(r"^ {0,3}(?:#{1,6}(?:[ \t]|$)|([*_-])(?:[ \t]*\1){2,}[ \t]*$)")

# a line making the paragraph above it a heading
UNDERLINE = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")

# the label of a link reference definition, other than a footnote's, up to
# the colon after it
LABEL = re.compile(r"^ {0,3}\[(?!\^)((?:[^\[\]\\]|\\.)*)\]:")

# a link destination markdown-it refuses, unless `IMAGE` matches it
UNSAFE = re.compile(r"^(?:vbscript|javascript|file|data):", re.IGNORECASE)
IMAGE = re.compile(r"^data:image/(?:gif|png|jpeg|webp);", re.IGNORECASE)

# the directives whose body this reads as markup, among them the
# admonitions, containers and version notes of docutils and sphinx. Every
# directive not named here is read as code, so an include inside it is not
# read: {code-block}, {eval-rst} and {toctree}, and also some that do
# parse their body, as {figure}, {list-table}, {glossary} and {acks},
# which renders only a bullet list. The list names only directives MyST
# renders by parsing their body, and grows when a page needs an include
# inside another one
PARSED = (
    "admonition",
    "attention",
    "caution",
    "danger",
    "error",
    "hint",
    "important",
    "note",
    "tip",
    "warning",
    "seealso",
    "topic",
    "sidebar",
    "epigraph",
    "highlights",
    "pull-quote",
    "compound",
    "container",
    "only",
    "hlist",
    "deprecated",
    "versionadded",
    "versionchanged",
    "versionremoved",
    "version-deprecated",
    "version-added",
    "version-changed",
    "version-removed",
)

# the directives that a topic or a sidebar renders in, "" being the
# page: sphinx's {only} and its version notes parse their body as the
# page does. docutils refuses them in the body of any other directive
# and renders nothing
VERSIONS = (
    "deprecated",
    "versionadded",
    "versionchanged",
    "versionremoved",
    "version-deprecated",
    "version-added",
    "version-changed",
    "version-removed",
)
PLACED = {
    "topic": ("", "only", "sidebar", *VERSIONS),
    "sidebar": ("", "only", *VERSIONS),
}

# the directives of `PARSED` that take no options, so that MyST reads
# the lines opening their body as markdown
BARE = ("epigraph", "highlights", "pull-quote", "only", *VERSIONS)

# the directives of `PARSED` that take no argument, so that MyST reads
# the text after their name on the opener line as their body's first
# line, put after their options
UNARGUED = (
    "attention",
    "caution",
    "danger",
    "error",
    "hint",
    "important",
    "note",
    "tip",
    "warning",
    "seealso",
    "epigraph",
    "highlights",
    "pull-quote",
    "compound",
    "hlist",
)

# the directives of `PARSED` that docutils renders as a block quote: a
# line after a blank one that opens with `--`, `---` or an em dash, and
# holds more, starts the quote's attribution, and MyST drops it and all
# the lines below it from the body
QUOTES = ("epigraph", "highlights", "pull-quote")

# the start of an attribution, as MyST matches it
ATTRIBUTION = re.compile("^(?:---?(?!-)|\u2014) *.")


def fence_end(lines: list[str], start: int, marker: str) -> int:
    """Return where the fence `marker` opened closes, or the page's end.

    :param lines: the lines of the page.
    :param start: the line after the opener.
    :param marker: the opener's marker.
    :returns: the index of the line that closes the fence.
    """
    for at in range(start, len(lines)):
        fence = FENCE.match(lines[at])
        if (
            fence is not None
            and not fence[3]
            and fence[2][0] == marker[0]
            and len(fence[2]) >= len(marker)
        ):
            return at
    return len(lines)


def opens_html(line: str) -> bool:
    """Say whether a line may open an html block, a paragraph above it or not.

    :param line: a line of the page.
    :returns: whether it matches `HTML_BLOCKS`, `HTML_NAMED` or `HTML_TAG`.
    """
    return bool(html_block(line) or HTML_NAMED.match(line) or HTML_TAG.match(line))


def html_block(line: str) -> re.Pattern[str] | None:
    """Return the closing string of the html block a line opens, if it runs on.

    :param line: a line of the page.
    :returns: the pattern of the closing string, or None where the line
        opens none of `HTML_BLOCKS`.
    """
    return next((end for start, end in HTML_BLOCKS if start.match(line)), None)


def interrupts(line: str) -> bool:
    """Say whether a line may open a list item below an open paragraph.

    An item that is empty, or numbered from other than 1, may not: the
    line is then the paragraph's text.

    :param line: a line that `CONTAINER` matches.
    :returns: whether the line ends the paragraph.
    """
    item = ITEM.match(line)
    if item is None:
        return True
    number = item[2][:-1]
    return bool(line[item.end() :].strip(" \t")) and number in {"", "1"}


def destination(line: str, at: int) -> int | None:
    """Return where the link destination at `at` ends, as markdown-it reads it.

    :param line: the line.
    :param at: where the destination starts.
    :returns: the index after it, or None where there is none.
    """
    start, level = at, 0
    if line[at : at + 1] == "<":
        while (at := at + 1) < len(line) and line[at] not in "<>":
            at += line[at] == "\\"
        return at + 1 if line[at : at + 1] == ">" else None
    while (
        at < len(line)
        and line[at] > " "
        and line[at] != "\x7f"
        and line[at : at + 2] != "\\ "
    ):
        if line[at] == "\\":
            at += 1
        elif line[at] == "(":
            level += 1
        elif line[at] == ")":
            if not level:
                break
            level -= 1
        if level > 32:
            return None
        at += 1
    return None if at == start or level else at


def title(line: str, at: int) -> int | None:
    """Return where the link title at `at` ends, as markdown-it reads it.

    :param line: the line.
    :param at: where the title's opening mark is.
    :returns: the index after its closing mark, or None where it does not
        close on the line.
    """
    close = {'"': '"', "'": "'", "(": ")"}.get(line[at : at + 1])
    while close is not None and (at := at + 1) < len(line):
        if line[at] == close:
            return at + 1
        if line[at] == "(" and close == ")":
            return None
        at += line[at] == "\\"
    return None


def definition(line: str) -> bool:
    """Say whether a line is a whole link reference definition.

    :param line: the line.
    :returns: whether markdown-it reads the line alone as one.
    """
    label = LABEL.match(line)
    if label is None or not label[1].strip():
        return False
    start = len(line) - len(line[label.end() :].lstrip(" \t"))
    end = destination(line, start)
    if end is None:
        return False
    href = (
        line[start + 1 : end - 1] if line[start] == "<" else line[start:end]
    ).strip()
    if UNSAFE.match(href) and not IMAGE.match(href):
        return False
    rest = line[end:].lstrip(" \t")
    if not rest:
        return True
    close = title(line, len(line) - len(rest)) if len(rest) < len(line) - end else None
    return close is not None and not line[close:].strip(" \t")


def top_line(line: str, *, paragraph: bool) -> tuple[re.Pattern[str] | None, bool]:
    """Read a line at the top level that opens neither a fence nor a container.

    :param line: the line.
    :param paragraph: whether a paragraph is open above it.
    :returns: what ends the html block the line opens and leaves open, or
        None; and whether a paragraph is open after it.
    """
    block = html_block(line)
    if block is not None:
        return (None if block.search(line) else block), False
    if HTML_NAMED.match(line) or (not paragraph and HTML_TAG.match(line)):
        return BLANK, False
    if line.startswith("    "):
        # the paragraph's text, or else indented code
        return None, paragraph
    if not paragraph and definition(line):
        return None, False
    if paragraph:
        return None, not (HEADING.match(line) or UNDERLINE.match(line))
    return None, HEADING.match(line) is None


def options(texts: list[str], *, directive: str) -> int:
    """Return how many lines open a directive's body as its options.

    The body of a directive not in `BARE` may open with its options:
    from a line of `---` to the next line opening with three dashes, or
    to its end, or else as the lines at its start that open with one
    colon or two, such as `:class: tip`. What follows the dashes of that
    closing line, its first character off, is the body's first line, and
    this writes it into `texts` in place of the line.

    :param texts: the lines of the body, their indentation taken off.
    :param directive: the name of the directive, empty for a page.
    :returns: the count of the lines to skip.
    """
    if directive in ("", *BARE):
        return 0
    if texts and texts[0].startswith("---"):
        rest = (at for at in range(1, len(texts)) if texts[at].startswith("---"))
        skip = next(rest, len(texts))
        closing = texts[skip] if skip < len(texts) else ""
        if tail := closing[len(closing) - len(closing.lstrip("-")) + 1 :]:
            texts[skip] = tail
            return skip
        return min(skip + 1, len(texts))
    option = re.compile(r"\s*:(?!::)")
    rest = (at for at, text in enumerate(texts) if not option.match(text))
    return next(rest, len(texts))


def attribution(texts: list[str], start: int) -> int:
    """Return where the attribution of a quote of `QUOTES` starts.

    :param texts: the lines of the body, their indentation taken off.
    :param start: the line the body's markdown starts at.
    :returns: the index of the attribution's first line, or the body's end.
    """
    starts = (
        at
        for at in range(start + 1, len(texts))
        if not texts[at - 1].strip() and ATTRIBUTION.match(texts[at])
    )
    return next(starts, len(texts))


def front_matter(texts: list[str], start: int, *, body: bool) -> int:
    """Return where the markdown of a text starts, past its front matter.

    A text, a page or what a directive's body holds as markdown, may
    open with front matter: from a line of three dashes or more to a
    line of at least as many, or to a line of `...` with nothing after
    it that is not the text's last. An empty last line of a body is no
    line there. Left unclosed, it is no front matter.

    :param texts: the lines, their indentation taken off.
    :param start: the line the text starts at.
    :param body: whether the text is a directive's body.
    :returns: the index of the first line read as markdown.
    """
    opener = re.match(r"-{3,}", texts[start]) if start < len(texts) else None
    if opener is None:
        return start
    closer = re.compile(rf"^ {{0,3}}-{{{len(opener[0])},}}[ \t]*$")
    last = len(texts) - (1 if body and texts[-1] == "" else 0)
    end = (
        at
        for at in range(start + 1, len(texts))
        if closer.match(texts[at])
        or (texts[at].lstrip(" \t") == "..." and at + 1 < last)
    )
    return next(end, start - 1) + 1


def markdown_start(
    texts: list[str],
    bodies: list[str],
    page: list[str],
    *,
    directive: str,
    opener: str,
) -> int:
    """Return where the markdown of a page or a directive's body starts.

    Past the body's options, the opener's text is put in as a line of
    each list. Where there is none, a blank line there is dropped. A
    quote of `QUOTES` loses its attribution from `texts`. Front matter
    is skipped last.

    :param texts: the lines, their tabs before the text turned to spaces.
    :param bodies: the same lines, as `dedent` gives them.
    :param page: the same lines, as the page writes them.
    :param directive: the name of the directive, empty for a page.
    :param opener: the text `read_page` takes as the body's first line.
    :returns: the index of the first line read as markdown.
    """
    at = options(texts, directive=directive)
    if opener:
        for column in (texts, bodies, page):
            column.insert(at, opener)
    elif directive and at < len(texts) and not texts[at].strip():
        at += 1
    if directive in QUOTES:
        del texts[attribution(texts, at) :]
    return front_matter(texts, at, body=bool(directive))


def dedent(line: str, width: int) -> str:
    """Take the indentation of a directive's opener off a line of its body.

    As markdown-it does, this takes off at most `width` columns, a tab
    reaching to the next multiple of four, and gives back as spaces what
    a tab it takes off reaches past them. A tab it does not reach stays.

    :param line: the line, as the text holding the directive writes it.
    :param width: the columns to take off.
    :returns: the line, as the directive's body holds it.
    """
    column, at = 0, 0
    while at < len(line) and column < width and line[at] in " \t":
        column += 4 - column % 4 if line[at] == "\t" else 1
        at += 1
    return " " * (column - width) + line[at:]


def ends_containers(line: str, *, floor: int, blank: bool) -> bool:
    """Say whether a line ends every container open above it.

    The containers are list items, quotes and footnote definitions.

    A fence, an html block that may follow a paragraph, a heading or a
    thematic break does, behind fewer spaces than any open list item
    asks. After a blank line, so does a line with no spaces before it
    that may open no container or html block.

    :param line: the line, outside any html block or fence.
    :param floor: the spaces the list items open ask, 4 where none is.
    :param blank: whether a blank line is above it.
    :returns: whether the line is at the top level.
    """
    indent = len(line) - len(line.lstrip(" "))
    if indent < floor and (
        FENCE.match(line)
        or html_block(line)
        or HTML_NAMED.match(line)
        or HEADING.match(line)
    ):
        return True
    return blank and indent == 0 and not CONTAINER.match(line) and not opens_html(line)


def opens_container(line: str, *, paragraph: bool) -> bool:
    """Return whether a line at the top level opens a container.

    :param line: the line, which opens no fence.
    :param paragraph: whether a paragraph is open above it.
    :returns: whether it opens a list item, a block quote or a footnote
        definition.
    """
    return (
        CONTAINER.match(line) is not None
        and HEADING.match(line) is None
        and not (paragraph and not interrupts(line))
    )


def inner_line(
    line: str, *, end: re.Pattern[str] | None, raw: bool, floor: int
) -> tuple[re.Pattern[str] | None, bool, int]:
    """Read a line below the top level that opens no fence.

    :param line: the line.
    :param end: what ends the html block that may hide the line, or None.
    :param raw: whether the line may be inside an html block opened above.
    :param floor: the spaces the list items open ask, 4 where none is.
    :returns: `end`, `raw` and `floor` after the line.
    """
    block = html_block(line)
    end = block if block is not None and not block.search(line) else end
    raw = raw or (block is None and opens_html(line))
    item = ITEM.match(line)
    floor = min(floor, item.end() + (0 if item[3] else 1)) if item else floor
    return end, raw, floor


def fenced(
    texts: list[str],
    bodies: list[str],
    page: list[str],
    at: int,
    fence: re.Match[str],
    *,
    directive: str,
    top: bool,
) -> tuple[list[str], int]:
    """Read the fence a line opens, and the body of its directive.

    :param texts: the lines, their leading tabs expanded.
    :param bodies: the lines, as `dedent` leaves them.
    :param page: the lines, as the page writes them.
    :param at: the index of the line after the opener.
    :param fence: the opener's match of `FENCE`.
    :param directive: the name of the directive holding the fence, empty
        for a page.
    :param top: whether the opener is at the top level.
    :returns: the paths of the include fences it holds or is, and the
        index of the line after its closer.
    """
    close = fence_end(texts, at, fence[2])
    info = fence[3].strip()
    paths = INCLUDE.findall(info)
    name = DIRECTIVE.match(info)
    parents = PLACED.get(name[1], (directive,)) if name is not None else ()
    if name is not None and name[1] in PARSED and directive in parents:
        paths.extend(
            read_page(
                bodies[at:close],
                page=page[at:close],
                width=len(fence[1]),
                trusted=top,
                directive=name[1],
                opener=(name[2] or "") if name[1] in UNARGUED else "",
            )
        )
    return paths, close + 1


class Reading:
    """What `read_page` knows of the blocks open at a line."""

    def __init__(self, *, trusted: bool) -> None:
        """Start before the first line.

        :param trusted: whether the lines start at the top level.
        """
        self.trusted = trusted
        self.top = trusted
        self.paragraph = False
        self.blank = False
        self.raw = False
        # the fewest spaces a line needs to sit inside a list item open
        self.floor = 4
        # what ends an html block that may hide the lines read
        self.end: re.Pattern[str] | None = None
        # what closes a fence behind spaces left closed, which may be code
        self.shut: re.Pattern[str] | None = None
        # whether the line read closes such a fence
        self.closing = False

    def skips(self, line: str) -> bool:
        """Read a line as the blocks left open see it.

        :param line: the line.
        :returns: whether nothing more is read of it: it is blank, or an
            html block at the top level holds it.
        """
        # whether the line may still be a block's own
        held = self.end is not None or self.shut is not None
        if self.end is not None:
            self.end = None if self.end.search(line) else self.end
            if self.top:
                # the block's own, its last line included
                return True
        self.closing = self.shut is not None and self.shut.search(line) is not None
        self.shut = None if self.closing else self.shut
        if not line.strip(" \t"):
            self.blank, self.raw, self.paragraph = True, False, False
            return True
        self.place(line, held=held)
        return False

    def place(self, line: str, *, held: bool) -> None:
        """Read whether a line that is not blank is at the top level.

        :param line: the line.
        :param held: whether an html block or a fence left closed may
            still hold it.
        """
        if self.trusted and not held and not self.raw:
            self.top = self.top or ends_containers(
                line, floor=self.floor, blank=self.blank
            )
        self.floor = 4 if self.top else self.floor
        self.blank = False

    def read(self, line: str) -> None:
        """Read a line `skips` leaves, which opens no fence.

        :param line: the line.
        """
        if self.top and not opens_container(line, paragraph=self.paragraph):
            self.end, self.paragraph = top_line(line, paragraph=self.paragraph)
            return
        self.top = False
        self.end, self.raw, self.floor = inner_line(
            line, end=self.end, raw=self.raw, floor=self.floor
        )

    def leaves_closed(self, fence: re.Match[str], *, indented: bool) -> bool:
        """Read a fence this leaves closed, and what may close it.

        Below the top level a fence behind spaces or a tab on the page is
        left closed, but unless it closes one, it may open a code block.

        :param fence: the opener's match of `FENCE`.
        :param indented: whether spaces or a tab are before it on the page.
        :returns: whether the fence is left closed.
        """
        if self.top or not indented:
            return False
        closer = rf"^ {{0,3}}{fence[2][0]}{{{len(fence[2])},}}[ \t]*$"
        self.shut = None if self.closing else re.compile(closer)
        return True


def read_page(
    lines: list[str],
    *,
    page: list[str],
    width: int,
    trusted: bool,
    directive: str,
    opener: str,
) -> list[str]:
    """Return the paths of the include fences in lines of markdown.

    The lines are at the top level, of a page or of a directive's body,
    until one may open a list item, a block quote or a footnote
    definition. From there only a fence with nothing before it on the
    page opens, and an html block hides nothing. A line is at the top
    level again where `ends_containers` says so, unless an html block or
    a fence left closed may still hold it. Trusted lines start at the top
    level; untrusted ones never reach it.

    A link reference definition is read where it fits on one line, as
    `definition` says, which leaves a character reference in its
    destination undecoded. One that runs onto the next line is read as a
    paragraph, so a lone html tag below it opens no html block.

    A tab before a line's text reaches to the next multiple of four
    columns, counted from the start of the text that holds the line: the
    page, or the body of its innermost directive.

    :param lines: the lines, as the text holding them writes them.
    :param page: the same lines, as the page writes them.
    :param width: the columns `dedent` takes off the start of each line.
    :param trusted: whether the lines start at the top level.
    :param directive: the name of the directive whose body the lines
        are, empty for a page.
    :param opener: the text after the directive's name on its opener
        line, where `UNARGUED` names it, which is the body's first line
        after its options; else empty.
    :returns: the paths, as the fences write them.
    """
    bodies = [dedent(line, width) for line in lines]
    texts = [re.sub(r"^[ \t]+", lambda lead: lead[0].expandtabs(4), b) for b in bodies]
    page = [*page]
    at = markdown_start(texts, bodies, page, directive=directive, opener=opener)
    paths: list[str] = []
    state = Reading(trusted=trusted)
    while at < len(texts):
        text, at = texts[at], at + 1
        if state.skips(text):
            continue
        fence = FENCE.match(text)
        if fence is None:
            state.read(text)
        elif not state.leaves_closed(fence, indented=page[at - 1][0] in " \t"):
            found, at = fenced(
                texts, bodies, page, at, fence, directive=directive, top=state.top
            )
            paths.extend(found)
            state.paragraph = False
    return paths


def includes(text: str) -> list[str]:
    """Return the paths of the include fences of a page, in page order.

    A fence opening a directive of `PARSED` holds markdown, which myst
    parses, so a fence in its body is read, the opener's indentation
    taken off the body, unless `PLACED` says the directive renders
    nothing where it stands. The body opens with the text after the
    directive's name on the opener line, where `UNARGUED` names the
    directive, and in a quote of `QUOTES` it ends at the attribution. A
    directive MyST refuses for what it is given, such as an admonition
    with no title, renders nothing either, and its body is read all the
    same.

    Any other fence is code, and what it holds is shown, not parsed. A
    fence closes at a bare marker of its own character, at least as long
    as the one that opened it. An html block such as a comment shows
    what it holds as html, so a fence inside it is not read. A fence in
    a list item or a block quote is not read either. `read_page` says
    where this stops telling them and html blocks apart.

    :param text: the page.
    :returns: the paths, as the fences write them.
    """
    lines = text.splitlines()
    return read_page(lines, page=lines, width=0, trusted=True, directive="", opener="")


def included(page: Path) -> tuple[str, str] | None:
    """Map the file a page of docs/source includes to the page's docname.

    A page with no include fence renders no file, and maps nothing. One
    with more than one stops the build: a relative link on it would have
    two files to start from, and which one is not a question this can
    answer.
    """
    paths = includes(page.read_text(encoding="utf-8"))
    if len(paths) > 1:
        err_msg = f"{page.name}: {len(paths)} include fences, expected at most one"
        raise ValueError(err_msg)
    if not paths:
        return None
    return str((page.parent / paths[0]).resolve().relative_to(ROOT)), page.stem


# repository-relative path -> the docname whose page renders it
INCLUDED = dict(
    entry
    for entry in map(included, sorted(Path(__file__).parent.glob("*.md")))
    if entry is not None
)


class RootFileLinks(SphinxPostTransform):
    """Resolve the links naming a file of this tree."""

    # ahead of myst's own resolver, which runs at 9 and is what turns an
    # unresolved target into that anchor
    default_priority = 5

    @staticmethod
    def _to_page(node: pending_xref, page: str, anchor: str | None) -> None:
        """Point a myst xref at `page`, a docname."""
        node["refdomain"] = "doc"
        node["reftarget"] = page
        node["reftargetid"] = anchor or None

    def _broken_doc_target(self, node: pending_xref) -> tuple[Path, str | None] | None:
        """Recover the file behind a "doc" xref `path2doc` resolved wrong.

        myst already thinks this resolves; a real docname is a working
        cross-reference and none of this file's business. Anything else is
        `Project.path2doc` stripping a matching suffix off *any* file that
        exists on disk, docs or not (sphinx/project.py), so a link climbing
        out of srcdir into a real file -- a page under docs/source
        linking into README.md -- reads as resolved when it is not.
        Recover the file it actually named: reftarget is that path with
        its suffix gone, and only one of the two the tree parses still
        fits.
        """
        if node["reftarget"] in self.env.all_docs:
            return None
        candidates = (Path(f"{node['reftarget']}{suffix}") for suffix in source_suffix)
        found = next((c for c in candidates if c.is_file()), None)
        return None if found is None else (found, node.get("reftargetid"))

    def _unbound_target(
        self, node: pending_xref, refdoc: str
    ) -> tuple[Path, str | None]:
        """Resolve a link myst left with no domain at all.

        A page that includes a file holds links written relative to that
        file; any other page's links are written relative to wherever the
        page sits in the source tree -- doc2path is what answers that
        without assuming every docname sits flat under docs/source.
        """
        raw, _, anchor = node["reftarget"].partition("#")
        # a query, as `?plain=1`, is GitHub's and names no file
        raw = raw.partition("?")[0]
        rendered = [path for path, page in INCLUDED.items() if page == refdoc]
        origin = (
            (ROOT / rendered[0]).parent
            if rendered
            else Path(self.env.doc2path(refdoc)).parent
        )
        return origin / raw, anchor or None

    def _source_page(self, target: str) -> str | None:
        """Return the docname of `target` where it is a page of docs/source."""
        stem, suffix = posixpath.splitext(target)
        docname = stem.removeprefix("docs/source/")
        if docname == stem or suffix not in source_suffix:
            return None
        # the file itself, and not only its docname: a missing page.rst
        # would otherwise read as page.md
        if not (ROOT / target).is_file():
            return None
        return docname if docname in self.env.found_docs else None

    def run(self, **_kwargs: object) -> None:
        """Rewrite every link naming a file of this repository."""
        # the list is taken before the tree is edited: replace_self on a
        # node the generator is standing on reparents its children under it
        for node in list(self.document.findall(pending_xref)):
            if node.get("reftype") != "myst":
                continue
            refdomain = node.get("refdomain")
            if refdomain == "doc":
                resolved = self._broken_doc_target(node)
            elif refdomain is None:
                refdoc = node.get("refdoc", self.env.docname)
                resolved = self._unbound_target(node, refdoc)
            else:
                resolved = None
            if resolved is None:
                continue
            found, anchor = resolved
            try:
                # "./tests/README.md" from a shim resolves to
                # "tests/README.md"; a page's own "../../README.md"
                # resolves to "README.md" the same way, against the real
                # filesystem, so a path climbing above ROOT raises rather
                # than reading as one of its own
                target = str(found.resolve().relative_to(ROOT))
            except ValueError:
                # outside the repository: nothing this can answer
                continue
            if target in INCLUDED:
                # handed back to myst as the link it would have been
                # written as, so the page title and the caption are its
                # business and not this file's
                self._to_page(node, INCLUDED[target], anchor)
            elif (ROOT / target).is_file():
                fragment = f"#{anchor}" if anchor else ""
                reference = nodes.reference(
                    "", "", refuri=f"{BLOB}{target}{fragment}", internal=False
                )
                reference.extend(node.children)
                node.replace_self(reference)
        self._blob_links()

    def _blob_links(self) -> None:
        """Turn a BLOB link to a file the docs render into a link to its page.

        myst made each BLOB link an external reference: one naming an
        included file or a page of docs/source becomes the xref myst makes
        from a relative link, which myst's resolver then renders alike.
        """
        for node in list(self.document.findall(nodes.reference)):
            url, _, anchor = node.get("refuri", "").partition("#")
            # the path ends at a query, as `?plain=1`, which the page drops
            url = url.partition("?")[0]
            target = url.removeprefix(BLOB)
            if target == url:
                continue
            page = INCLUDED.get(target) or self._source_page(target)
            if page is None:
                continue
            xref = pending_xref(
                "",
                nodes.inline("", "", *node.children, classes=["xref", "myst"]),
                reftype="myst",
                refexplicit=True,
                refdoc=self.env.docname,
            )
            xref.source, xref.line = node.source, node.line
            self._to_page(xref, page, anchor)
            node.replace_self(xref)


def setup(app: Sphinx) -> None:
    """Register the transform above; sphinx calls this."""
    app.add_post_transform(RootFileLinks)
