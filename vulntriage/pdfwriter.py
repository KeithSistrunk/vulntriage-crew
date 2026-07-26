"""A minimal PDF writer -- enough for a text report, with no dependencies.

The rest of this project runs on pydantic alone (`python main.py --offline`), and
a report that only materializes after a `pip install` is not a report the run
produces. reportlab would be less code to own; it would also mean the PDF exists
on some machines and not others, so the format is written out directly here.

That is affordable because this is a text report: PDF's 14 standard fonts need no
embedding, so a page is a content stream of `Tf`/`Tm`/`Tj` operators plus filled
rectangles for rules and badges. What this deliberately does *not* implement is
anything needing a font program, an image codec, or a compression filter --
streams are written uncompressed, which costs bytes nobody counts on a 30-page
report and removes zlib from the trust surface of the output.

Only the mechanics live here. What goes on the page is `report_pdf.py`.
"""

from __future__ import annotations

from typing import Iterable

LETTER = (612.0, 792.0)

HELVETICA = "F1"
HELVETICA_BOLD = "F2"

# Advance widths for the two standard fonts used, in 1/1000 em, from the Adobe
# AFM tables. Without these, wrapping has to guess an average character width,
# which overflows the margin on capitalized text and looks broken.
_HELV = (
    "278 278 355 556 556 889 667 191 333 333 389 584 278 333 278 278 "
    "556 556 556 556 556 556 556 556 556 556 278 278 584 584 584 556 "
    "1015 667 667 722 722 667 611 778 722 278 500 667 556 833 722 778 "
    "667 778 722 667 611 722 667 944 667 667 611 278 278 278 469 556 "
    "333 556 556 500 556 556 278 556 556 222 222 500 222 833 556 556 "
    "556 556 333 500 278 556 500 722 500 500 500 334 260 334 584"
)
_HELV_BOLD = (
    "278 333 474 556 556 889 722 238 333 333 389 584 278 333 278 278 "
    "556 556 556 556 556 556 556 556 556 556 333 333 584 584 584 611 "
    "975 722 722 722 722 667 611 778 722 278 556 722 611 833 722 778 "
    "667 778 722 667 611 722 667 944 667 667 611 333 278 333 584 556 "
    "333 556 611 556 611 556 333 611 611 278 278 556 278 889 611 611 "
    "611 611 389 556 333 611 556 778 556 556 500 389 280 389 584"
)


def _width_table(spec: str) -> dict[int, int]:
    """ASCII 32..126 -> advance width."""
    return {32 + i: int(w) for i, w in enumerate(spec.split())}


_WIDTHS = {
    HELVETICA: _width_table(_HELV),
    HELVETICA_BOLD: _width_table(_HELV_BOLD),
}
# Anything outside ASCII (an accented owner name, a CVE description's typography)
# is measured at a middling width rather than skipped, so wrapping stays sane.
_DEFAULT_WIDTH = 556

# Characters worth spelling out rather than losing. WinAnsi covers the dashes and
# curly quotes already; these are the ones it does not, and "?" in the middle of a
# CVSS threshold would be a bug report waiting to happen.
_TRANSLITERATE = {
    "≥": ">=", "≤": "<=", "≠": "!=", "→": "->", "←": "<-",
    "×": "x", "✓": "OK", "✔": "OK", "⚠": "!", "•": "·",
    "‑": "-", "−": "-", " ": " ",
}


def sanitize(text: str) -> str:
    """Make text representable in WinAnsi, spelling out what it cannot encode."""
    for source, target in _TRANSLITERATE.items():
        if source in text:
            text = text.replace(source, target)
    # Round-trip through cp1252 so anything still unmappable becomes "?" here,
    # visibly, rather than raising at save() with the whole report already built.
    return text.encode("cp1252", errors="replace").decode("cp1252")


def text_width(text: str, font: str, size: float) -> float:
    table = _WIDTHS.get(font, _WIDTHS[HELVETICA])
    total = sum(table.get(ord(ch), _DEFAULT_WIDTH) for ch in text)
    return total * size / 1000.0


def wrap(text: str, font: str, size: float, max_width: float) -> list[str]:
    """Greedy word wrap to `max_width` points."""
    words = str(text).split()
    if not words:
        return [""]

    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}" if current else word
        if text_width(candidate, font, size) <= max_width:
            current = candidate
            continue
        if current:
            lines.append(current)
        # A single word wider than the column (a long URL, a CVE list) has to be
        # broken mid-word or it runs off the page.
        while text_width(word, font, size) > max_width:
            cut = len(word)
            while cut > 1 and text_width(word[:cut], font, size) > max_width:
                cut -= 1
            lines.append(word[:cut])
            word = word[cut:]
        current = word
    if current:
        lines.append(current)
    return lines


def _escape(text: str) -> str:
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


class PdfCanvas:
    """A paginated text canvas that serializes to PDF bytes.

    Coordinates are PDF-native: origin bottom-left, y increasing upward. The
    cursor (`self.y`) moves *down* the page as content is added, because that is
    how the report is written; `ensure()` breaks the page when it runs out.
    """

    def __init__(
        self,
        size: tuple[float, float] = LETTER,
        margin: float = 54.0,
        footer: str = "",
    ) -> None:
        self.width, self.height = size
        self.margin = margin
        self.footer = footer
        self._pages: list[list[str]] = []
        self._ops: list[str] = []
        self.y = 0.0
        self.new_page()

    # -- geometry -----------------------------------------------------------
    @property
    def content_width(self) -> float:
        return self.width - 2 * self.margin

    @property
    def bottom(self) -> float:
        # Room for the footer and its breathing space.
        return self.margin + 24.0

    def new_page(self) -> None:
        self._ops = []
        self._pages.append(self._ops)
        self.y = self.height - self.margin

    def ensure(self, needed: float) -> bool:
        """Start a new page if `needed` points do not remain. True if it broke."""
        if self.y - needed < self.bottom:
            self.new_page()
            return True
        return False

    def space(self, amount: float) -> None:
        self.y -= amount

    # -- drawing ------------------------------------------------------------
    def text(
        self,
        content: str,
        x: float | None = None,
        font: str = HELVETICA,
        size: float = 9.5,
        color: tuple[float, float, float] = (0, 0, 0),
        leading: float | None = None,
    ) -> None:
        """Draw one line at the cursor and advance it by `leading`."""
        x = self.margin if x is None else x
        line = sanitize(str(content))
        self._ops.append(
            f"BT {color[0]:.3f} {color[1]:.3f} {color[2]:.3f} rg /{font} {size:g} Tf "
            f"1 0 0 1 {x:.2f} {self.y:.2f} Tm ({_escape(line)}) Tj ET"
        )
        self.y -= leading if leading is not None else size * 1.32

    def paragraph(
        self,
        content: str,
        x: float | None = None,
        width: float | None = None,
        font: str = HELVETICA,
        size: float = 9.5,
        color: tuple[float, float, float] = (0, 0, 0),
        leading: float | None = None,
        indent: float = 0.0,
    ) -> None:
        """Wrap and draw, breaking the page between lines when it has to."""
        x = self.margin if x is None else x
        width = self.content_width if width is None else width
        leading = leading if leading is not None else size * 1.34
        for index, line in enumerate(wrap(sanitize(str(content)), font, size, width - indent)):
            self.ensure(leading)
            self.text(
                line,
                x=x + (indent if index else 0.0),
                font=font,
                size=size,
                color=color,
                leading=leading,
            )

    def rect(
        self,
        x: float,
        y: float,
        width: float,
        height: float,
        color: tuple[float, float, float],
    ) -> None:
        self._ops.append(
            f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} rg "
            f"{x:.2f} {y:.2f} {width:.2f} {height:.2f} re f"
        )

    def rule(self, color: tuple[float, float, float] = (0.85, 0.85, 0.87), weight: float = 0.6) -> None:
        """A horizontal rule at the cursor. Drawn as a thin filled box."""
        self.rect(self.margin, self.y, self.content_width, weight, color)
        self.y -= weight + 4.0

    def badge(
        self,
        label: str,
        x: float,
        width: float,
        fill: tuple[float, float, float],
        size: float = 8.0,
    ) -> None:
        """A filled chip with centered white text, on the current line."""
        height = size + 5.0
        self.rect(x, self.y - 2.5, width, height, fill)
        centered = x + (width - text_width(label, HELVETICA_BOLD, size)) / 2
        self._ops.append(
            f"BT 1 1 1 rg /{HELVETICA_BOLD} {size:g} Tf "
            f"1 0 0 1 {centered:.2f} {self.y:.2f} Tm ({_escape(sanitize(label))}) Tj ET"
        )

    # -- serialization ------------------------------------------------------
    def _footer_ops(self, page_number: int, total: int) -> list[str]:
        if not self.footer and total <= 1:
            return []
        y = self.margin - 12.0
        ops = [f"0.62 0.62 0.65 rg {self.margin:.2f} {self.margin + 2:.2f} "
               f"{self.content_width:.2f} 0.5 re f"]
        left = sanitize(self.footer)
        ops.append(
            f"BT 0.42 0.42 0.45 rg /{HELVETICA} 7.5 Tf "
            f"1 0 0 1 {self.margin:.2f} {y:.2f} Tm ({_escape(left)}) Tj ET"
        )
        right = f"Page {page_number} of {total}"
        x = self.width - self.margin - text_width(right, HELVETICA, 7.5)
        ops.append(
            f"BT 0.42 0.42 0.45 rg /{HELVETICA} 7.5 Tf "
            f"1 0 0 1 {x:.2f} {y:.2f} Tm ({_escape(right)}) Tj ET"
        )
        return ops

    def save(self, path) -> None:
        path.write_bytes(self.to_bytes())

    def to_bytes(self) -> bytes:
        """Serialize to a complete PDF file.

        Object numbering is fixed up front -- catalog, pages, two fonts, then a
        page object and a content stream per page -- because the cross-reference
        table at the end is a table of byte offsets, and every one of them has to
        be right or no reader will open the file.
        """
        total = len(self._pages)
        first_page_obj = 5
        page_ids = [first_page_obj + 2 * i for i in range(total)]

        objects: dict[int, bytes] = {
            1: b"<< /Type /Catalog /Pages 2 0 R >>",
            2: (
                "<< /Type /Pages /Count %d /Kids [%s] >>"
                % (total, " ".join(f"{pid} 0 R" for pid in page_ids))
            ).encode("ascii"),
            3: (
                b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
                b"/Encoding /WinAnsiEncoding >>"
            ),
            4: (
                b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
                b"/Encoding /WinAnsiEncoding >>"
            ),
        }

        for index, ops in enumerate(self._pages):
            page_id = page_ids[index]
            stream_id = page_id + 1
            objects[page_id] = (
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] "
                "/Resources << /Font << /%s 3 0 R /%s 4 0 R >> >> "
                "/Contents %d 0 R >>"
                % (self.width, self.height, HELVETICA, HELVETICA_BOLD, stream_id)
            ).encode("ascii")

            body = "\n".join([*ops, *self._footer_ops(index + 1, total)]).encode("cp1252")
            objects[stream_id] = (
                b"<< /Length %d >>\nstream\n" % len(body) + body + b"\nendstream"
            )

        return _assemble(objects)


def _assemble(objects: dict[int, bytes]) -> bytes:
    """Lay out objects, record their offsets, and append the xref and trailer."""
    # The binary comment marks the file as binary for tools that sniff it.
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}

    for number in sorted(objects):
        offsets[number] = len(out)
        out += b"%d 0 obj\n" % number + objects[number] + b"\nendobj\n"

    size = max(objects) + 1
    xref_at = len(out)
    out += b"xref\n0 %d\n" % size
    out += b"0000000000 65535 f \n"
    for number in range(1, size):
        # Every entry is exactly 20 bytes; readers index into this table.
        out += b"%010d 00000 n \n" % offsets[number]

    out += b"trailer\n<< /Size %d /Root 1 0 R >>\n" % size
    out += b"startxref\n%d\n%%%%EOF\n" % xref_at
    return bytes(out)


def columns(widths: Iterable[float], start: float) -> list[float]:
    """Left edges for a row of columns, given their widths."""
    edges: list[float] = []
    x = start
    for width in widths:
        edges.append(x)
        x += width
    return edges
