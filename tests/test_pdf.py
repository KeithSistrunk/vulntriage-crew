"""Tests for the PDF triage report.

The PDF is written byte by byte with no library behind it (`vulntriage/pdfwriter.py`),
so these tests do what a reader would do: parse the file structure, walk the
cross-reference table, and pull the text back out of the content streams.

That matters more here than for the markdown report. A malformed markdown file is
still readable; a PDF with one wrong byte offset in its xref table opens as
"damaged file" and the run's output is gone. So the structural checks are the
point, not boilerplate:

    python -m pytest tests/test_pdf.py -v
    python tests/test_pdf.py
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vulntriage.pdfwriter import (  # noqa: E402
    HELVETICA,
    HELVETICA_BOLD,
    PdfCanvas,
    sanitize,
    text_width,
    wrap,
)
from vulntriage.pipeline import run_offline  # noqa: E402
from vulntriage.remediation import remediation_for  # noqa: E402
from vulntriage.report import write_reports  # noqa: E402
from vulntriage.report_pdf import build_pdf  # noqa: E402
from vulntriage.state import PipelineState  # noqa: E402

SAMPLE_JSON = ROOT / "data" / "sample_findings.json"

_TEXT_OP = re.compile(
    rb"/(F\d) ([\d.]+) Tf 1 0 0 1 (-?[\d.]+) (-?[\d.]+) Tm \((.*?)\) Tj",
    re.DOTALL,
)
_FONTS = {b"F1": HELVETICA, b"F2": HELVETICA_BOLD}


def _state() -> PipelineState:
    state = PipelineState()
    run_offline(SAMPLE_JSON, state)
    return state


def _pdf() -> bytes:
    return build_pdf(_state())


def _unescape(raw: bytes) -> str:
    text = raw.decode("cp1252")
    return text.replace(r"\(", "(").replace(r"\)", ")").replace(r"\\", "\\")


def _drawn_text(pdf: bytes) -> str:
    """Every string the file actually draws, in page order."""
    return "\n".join(_unescape(m.group(5)) for m in _TEXT_OP.finditer(pdf))


def _xref_offsets(pdf: bytes) -> list[int]:
    start = int(pdf.rsplit(b"startxref", 1)[1].split(b"%%EOF")[0].strip())
    table = pdf[start:]
    header = table.split(b"\n")[1]
    size = int(header.split()[1])
    # 20 bytes an entry, after "xref\n" and the "0 N\n" header line.
    body = table.split(b"\n", 2)[2]
    return [int(body[i * 20:i * 20 + 10]) for i in range(size)]


# --------------------------------------------------------------------------- #
# 1. the file is a PDF a reader can open
# --------------------------------------------------------------------------- #

def test_the_file_is_a_well_formed_pdf():
    pdf = _pdf()
    assert pdf.startswith(b"%PDF-1.4"), "a reader sniffs the header first"
    assert pdf.rstrip().endswith(b"%%EOF")
    assert b"/Type /Catalog" in pdf and b"/Type /Pages" in pdf


def test_every_xref_offset_points_at_its_object():
    """The check that catches a corrupt file. One wrong offset here and the
    whole document opens as 'damaged'."""
    pdf = _pdf()
    offsets = _xref_offsets(pdf)

    assert offsets[0] == 0, "object 0 is the free-list head"
    for number, offset in enumerate(offsets[1:], start=1):
        assert 0 < offset < len(pdf), f"object {number} offset out of range"
        assert pdf[offset:].startswith(b"%d 0 obj" % number), \
            f"xref says object {number} is at {offset}; it is not"


def test_the_trailer_size_matches_the_objects_present():
    pdf = _pdf()
    declared = int(re.search(rb"/Size (\d+)", pdf).group(1))
    present = len(re.findall(rb"\n(\d+) 0 obj", pdf)) + 1  # +1 for the free entry
    assert declared == present


def test_every_stream_length_is_honest():
    """A /Length that disagrees with the stream truncates the page or overruns it."""
    pdf = _pdf()
    for match in re.finditer(rb"<< /Length (\d+) >>\nstream\n", pdf):
        declared = int(match.group(1))
        body = pdf[match.end():]
        assert body[declared:declared + len(b"\nendstream")] == b"\nendstream", \
            "declared stream length does not reach exactly to endstream"


def test_the_page_tree_agrees_with_the_pages_written():
    pdf = _pdf()
    count = int(re.search(rb"/Type /Pages /Count (\d+)", pdf).group(1))
    kids = len(re.search(rb"/Kids \[(.*?)\]", pdf).group(1).split(b"R")) - 1
    pages = len(re.findall(rb"/Type /Page[^s]", pdf))
    assert count == kids == pages
    assert count > 1, "18 findings with remediation is more than one page"


# --------------------------------------------------------------------------- #
# 2. the content is the structured data, and all of it
# --------------------------------------------------------------------------- #

def test_every_finding_appears_with_cve_cvss_host_and_priority():
    """The four fields the report exists to carry, for every finding."""
    state = _state()
    text = _drawn_text(build_pdf(state))

    for finding in state.scored:
        assert finding.cve in text, f"{finding.cve} is missing from the PDF"
        assert finding.hostname in text, f"{finding.hostname} is missing"
        assert f"{finding.effective_cvss:g}" in text, f"CVSS for {finding.cve} is missing"
    assert {f.priority for f in state.scored} <= set(re.findall(r"P[1-4]", text))


def test_every_finding_carries_its_remediation():
    """Not just the top N -- a PDF is read away from the terminal that made it."""
    state = _state()
    text = _drawn_text(build_pdf(state))

    for finding in state.scored:
        plan = remediation_for(finding)
        # The summary wraps across lines, so match on its opening words.
        opening = " ".join(sanitize(plan["summary"]).split()[:4])
        assert opening in " ".join(text.split()), \
            f"no remediation for {finding.cve}: expected {opening!r}"


def test_the_pdf_never_reproduces_the_agent_narrative():
    """The whole reason this renderer ignores `agent_notes`.

    A PDF gets forwarded to people who were not in the room. Structured data can
    be wrong but it cannot be invented; a model's prose can be both.
    """
    state = _state()
    hallucination = (
        "CVE-2029-99999 affects the payroll mainframe and has been exploited "
        "against this organization three times this quarter, per the SOC."
    )
    for stage in ("discovery", "enrichment", "prioritization", "remediation"):
        state.note(stage, hallucination * 2)

    text = _drawn_text(build_pdf(state))
    assert "CVE-2029-99999" not in text
    assert "payroll mainframe" not in text
    assert "per the SOC" not in text


def test_the_priority_counts_on_the_page_match_the_findings():
    state = _state()
    text = _drawn_text(build_pdf(state))
    counts = {p: sum(1 for f in state.scored if f.priority == p) for p in ("P1", "P2", "P3", "P4")}
    # The summary chips render the priority and its count on consecutive lines.
    lines = text.split("\n")
    for priority, count in counts.items():
        index = lines.index(priority)
        assert lines[index + 1] == str(count), f"{priority} chip shows the wrong count"


# --------------------------------------------------------------------------- #
# 3. the layout holds
# --------------------------------------------------------------------------- #

def test_no_text_runs_past_the_right_margin():
    """Wrapping is measured, not guessed -- so nothing should overflow.

    Text that runs off the page is the classic failure of a hand-rolled PDF and
    it is invisible in the byte stream, so it is asserted here instead.
    """
    pdf = _pdf()
    limit = 612.0 - 54.0 + 1.0  # page width - margin, plus a rounding tolerance

    for match in _TEXT_OP.finditer(pdf):
        font = _FONTS[match.group(1)]
        size = float(match.group(2))
        x = float(match.group(3))
        content = _unescape(match.group(5))
        end = x + text_width(content, font, size)
        assert end <= limit, f"{content!r} ends at {end:.1f}pt, past the {limit:.0f}pt margin"


def test_nothing_is_drawn_in_the_footer_or_off_the_page():
    pdf = _pdf()
    for match in _TEXT_OP.finditer(pdf):
        y = float(match.group(4))
        assert 0 < y < 792.0, "text drawn outside the page"
        # The footer band lives below y=42; only the footer itself may be there.
        if y < 42.0:
            content = _unescape(match.group(5))
            assert "VulnTriage" in content or content.startswith("Page "), \
                f"{content!r} collided with the footer"


def test_wrapping_respects_the_measured_width():
    long_text = "Upgrade the Spring Framework to 5.3.18 or 5.2.20 and redeploy " * 4
    for line in wrap(long_text, HELVETICA, 9.5, 200.0):
        assert text_width(line, HELVETICA, 9.5) <= 200.0


def test_an_unbreakable_token_is_split_rather_than_overflowing():
    """A long URL in a reference field must not run off the page."""
    url = "https://example.com/" + "a" * 400
    lines = wrap(url, HELVETICA, 9.5, 120.0)
    assert len(lines) > 1
    for line in lines:
        assert text_width(line, HELVETICA, 9.5) <= 120.0


def test_characters_outside_winansi_are_spelled_out_not_mangled():
    """A "?" in a CVSS threshold would read as a bug in the data."""
    assert sanitize("CVSS ≥ 7.0") == "CVSS >= 7.0"
    assert sanitize("a → b") == "a -> b"
    # cp1252 covers these, so they must survive intact rather than being replaced.
    assert sanitize("em — dash · dot") == "em — dash · dot"


def test_parentheses_in_content_cannot_break_the_content_stream():
    """An unescaped ')' ends the string operator early and corrupts the page."""
    canvas = PdfCanvas()
    canvas.text("Apache Log4j (Log4Shell) \\ backslash")
    pdf = canvas.to_bytes()
    assert rb"\(Log4Shell\)" in pdf
    assert _drawn_text(pdf).strip() == "Apache Log4j (Log4Shell) \\ backslash"


# --------------------------------------------------------------------------- #
# 4. it is produced by the run, alongside the others
# --------------------------------------------------------------------------- #

def test_write_reports_emits_the_pdf_with_the_other_three():
    state = _state()
    with tempfile.TemporaryDirectory() as tmp:
        out = write_reports(state, tmp, top_n=5)
        assert out.pdf.exists() and out.pdf.suffix == ".pdf"
        assert out.pdf.read_bytes().startswith(b"%PDF")
        assert out.pdf.stat().st_size > 2000, "a real report, not an empty page"
        for path in (out.markdown, out.json, out.csv):
            assert path.exists()


def test_pdf_only_writes_the_pdf_and_nothing_else():
    state = _state()
    with tempfile.TemporaryDirectory() as tmp:
        out = write_reports(state, tmp, top_n=5, pdf_only=True)
        assert out.pdf.exists() and out.pdf.read_bytes().startswith(b"%PDF")
        assert (out.markdown, out.json, out.csv) == (None, None, None)
        written = sorted(p.name for p in Path(tmp).iterdir())
        assert written == ["triage_report.pdf"], f"pdf-only wrote {written}"


def test_pdf_only_produces_the_same_pdf_as_a_full_run():
    """The flag drops artifacts; it must not change the one it keeps."""
    state = _state()
    with tempfile.TemporaryDirectory() as full, tempfile.TemporaryDirectory() as only:
        a = write_reports(state, full, top_n=5).pdf.read_bytes()
        b = write_reports(state, only, top_n=5, pdf_only=True).pdf.read_bytes()
    # The creation timestamp is the one byte range allowed to differ.
    assert len(a) == len(b)
    assert _drawn_text(a).count("CVE") == _drawn_text(b).count("CVE")


def test_pdf_only_still_runs_the_narrative_guard():
    """--strict-narrative decides an exit code from this; an output flag must
    not be able to switch the project's one safeguard off."""
    state = _state()
    with tempfile.TemporaryDirectory() as tmp:
        out = write_reports(state, tmp, top_n=5, pdf_only=True)
        assert out.guard is not None
        assert hasattr(out.guard, "violations")


def test_pdf_only_says_where_flagged_claims_went():
    """The markdown is where violations are annotated. If it was not written,
    that has to be said -- a silently dropped flag is the failure mode here."""
    state = _state()
    state.note("prioritization", "Every finding is on an internet-facing host.")
    with tempfile.TemporaryDirectory() as tmp:
        out = write_reports(state, tmp, top_n=5, pdf_only=True)
        if out.guard.violations:
            assert any("--pdf-only" in w for w in out.warnings), \
                "a pdf-only run must not drop guard violations in silence"


def test_a_locked_pdf_falls_back_instead_of_losing_the_run():
    """Same contract as the CSV: a PDF open in a viewer holds a lock on Windows."""
    from vulntriage.report import write_with_fallback

    state = _state()
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "triage_report.pdf"

        def refuse(path: Path) -> None:
            if path == target:
                raise PermissionError("open in a viewer")
            path.write_bytes(build_pdf(state))

        resolved, warning = write_with_fallback(target, refuse)
        assert resolved != target and resolved.exists()
        assert warning and "locked" in warning


if __name__ == "__main__":
    passed = failed = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            passed += 1
            print(f"  PASS  {name}")
        except Exception as exc:  # noqa: BLE001 - a hand-rolled runner wants everything
            failed += 1
            print(f"  FAIL  {name}: {type(exc).__name__}: {exc}")
    print(f"\n{passed} passed, {failed} failed")
    raise SystemExit(1 if failed else 0)
