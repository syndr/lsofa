"""Tests for reading a --classify series back (--trend) and writing it (emit_rows)."""

import csv

import pytest

import lsofa


# --- trend ------------------------------------------------------------------


def test_trend_reports_growth_per_class(classify_series):
    rows = {row["CLASS"]: row for row in lsofa.trend(str(classify_series))}
    assert rows["shm_deleted"]["first"] == 10
    assert rows["shm_deleted"]["last"] == 31
    assert rows["shm_deleted"]["delta"] == 21
    assert rows["dmabuf"]["delta"] == 0


def test_class_absent_from_first_sample_starts_at_zero(classify_series):
    """A class that appears partway through is exactly what a leak looks like.

    Skipping it, or treating its first observation as the baseline, would report
    delta 0 for the most interesting row in the file.
    """
    rows = {row["CLASS"]: row for row in lsofa.trend(str(classify_series))}
    assert rows["eventpoll"]["first"] == 0
    assert rows["eventpoll"]["delta"] == 7


def test_trend_sorts_by_growth_then_size(classify_series):
    rows = lsofa.trend(str(classify_series))
    # Growth first...
    assert [row["CLASS"] for row in rows[:2]] == ["shm_deleted", "eventpoll"]
    # ...then absolute size, so a series where nothing moved still reads as
    # "here is what this process holds", biggest first.
    assert [(row["delta"], row["last"]) for row in rows] == sorted(
        [(row["delta"], row["last"]) for row in rows], reverse=True
    )


def test_trend_top_limits_rows(classify_series):
    assert len(lsofa.trend(str(classify_series), top=1)) == 1


def test_trend_rejects_a_non_classify_csv(tmp_path):
    """Fail with a message naming the problem, not a KeyError traceback."""
    wrong = tmp_path / "wrong.csv"
    wrong.write_text("COMMAND,PID,used\nHyprland,42,100\n")
    with pytest.raises(SystemExit) as caught:
        lsofa.trend(str(wrong))
    assert "not a --classify series" in str(caught.value)


def test_trend_rejects_a_missing_file(tmp_path):
    with pytest.raises(SystemExit) as caught:
        lsofa.trend(str(tmp_path / "nope.csv"))
    assert "cannot read" in str(caught.value)


def test_trend_rejects_an_empty_series(tmp_path):
    empty = tmp_path / "empty.csv"
    empty.write_text("ts,COMMAND,PID,CLASS,count\n")
    with pytest.raises(SystemExit) as caught:
        lsofa.trend(str(empty))
    assert "no rows" in str(caught.value)


# --- emit_rows --------------------------------------------------------------


def _rows():
    return [
        {"ts": "2026-01-01T00:00:00+0000", "COMMAND": "x", "PID": "1", "CLASS": "shm", "count": 3},
    ]


def test_append_writes_the_header_exactly_once(tmp_path):
    """An external timer invokes us once per sample; a header per call would
    corrupt the series it is building."""
    out = tmp_path / "series.csv"
    lsofa.emit_rows(_rows(), str(out), append=True)
    lsofa.emit_rows(_rows(), str(out), append=True)
    text = out.read_text()
    assert text.count("ts,COMMAND") == 1
    assert len(list(csv.DictReader(out.open()))) == 2


def test_without_append_the_file_is_truncated(tmp_path):
    out = tmp_path / "snapshot.csv"
    lsofa.emit_rows(_rows(), str(out), append=False)
    lsofa.emit_rows(_rows(), str(out), append=False)
    assert len(list(csv.DictReader(out.open()))) == 1


def test_column_order_is_stable_and_extras_survive(tmp_path):
    """--classify and --trend share this writer, so it must order known columns
    predictably while still emitting anything a caller adds."""
    out = tmp_path / "extra.csv"
    lsofa.emit_rows(
        [{"count": 1, "CLASS": "shm", "PID": "1", "COMMAND": "x", "note": "hi"}],
        str(out),
    )
    header = out.read_text().splitlines()[0]
    assert header == "COMMAND,PID,CLASS,count,note"


def test_empty_rows_writes_nothing(tmp_path):
    out = tmp_path / "nothing.csv"
    lsofa.emit_rows([], str(out))
    assert not out.exists()


def test_markdown_output_renders(capsys):
    """The stdout branch is what a human actually sees, and no data-path test
    touches it -- a suite can pass while the table renderer raises."""
    lsofa.emit_rows(_rows(), None)
    out = capsys.readouterr().out
    assert "CLASS" in out and "shm" in out
    header, separator = out.splitlines()[0], out.splitlines()[1]
    assert len(header) == len(separator)
