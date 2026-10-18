#!/usr/bin/env python3
"""Validate the P0 golden-vector corpus against the independent Python harness.

The corpus under `test/vectors/` is produced by the Rust emitter
(`cargo test --test export_baseline_vectors`). This script never runs Rust: it
re-derives every expected value from the case's own inputs with `zro_vectors.py`
and reports PASS, ANCHOR (a pinned constant that cannot be independently
recomputed elsewhere), SKIP (no verifier) or FAIL.

Exit status is zero only when every case is PASS or ANCHOR and the envelope,
manifest and provenance checks all hold.
"""

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import zro_vectors  # noqa: E402

DEFAULT_ROOT = pathlib.Path(__file__).resolve().parents[1] / "vectors"
SCHEMA = "zro-baseline-vectors/1"
ENVELOPE_FIELDS = (
    "schema",
    "group",
    "intent",
    "note",
    "source",
    "source_commit",
    "provenance",
    "case_count",
    "cases",
)
CASE_FIELDS = ("id", "intent", "input", "expected", "independent_check")


class CorpusError(Exception):
    """The corpus envelope or manifest is malformed."""


def check_commit_word(path, value, field="source_commit"):
    """Reject anything that is not a 40-digit lowercase hex commit id."""
    if not isinstance(value, str) or len(value) != 40:
        raise CorpusError(f"{path}: {field} must be a 40-digit hex commit id, got {value!r}")
    if any(character not in "0123456789abcdef" for character in value):
        raise CorpusError(f"{path}: {field} must be lowercase hex, got {value!r}")
    return value


def load_document(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise CorpusError(f"{path}: not valid JSON ({error})")


def check_envelope(path, document, entry, source_commit):
    for field in ENVELOPE_FIELDS:
        if field not in document:
            raise CorpusError(f"{path}: the envelope is missing {field!r}")
    if document["schema"] != SCHEMA:
        raise CorpusError(f"{path}: schema is {document['schema']!r}, expected {SCHEMA!r}")
    if document["group"] != entry["group"]:
        raise CorpusError(f"{path}: group is {document['group']!r}, manifest says {entry['group']!r}")
    if not str(document["provenance"]).strip():
        raise CorpusError(f"{path}: provenance is empty")
    recorded = check_commit_word(path, document["source_commit"])
    if recorded != source_commit:
        raise CorpusError(
            f"{path}: source_commit is {recorded}, the manifest says {source_commit}"
        )
    cases = document["cases"]
    if document["case_count"] != len(cases):
        raise CorpusError(
            f"{path}: case_count is {document['case_count']}, found {len(cases)} cases"
        )
    if entry["cases"] != len(cases):
        raise CorpusError(f"{path}: manifest says {entry['cases']} cases, found {len(cases)}")


def load_corpus(root):
    """Return (cases by id, ordered case list, manifest) after structural checks."""
    manifest_path = root / "manifest.json"
    if not manifest_path.exists():
        raise CorpusError(f"{manifest_path}: the manifest is missing")
    manifest = load_document(manifest_path)
    if manifest.get("schema") != SCHEMA:
        raise CorpusError(f"{manifest_path}: schema is {manifest.get('schema')!r}")
    if not str(manifest.get("provenance", "")).strip():
        raise CorpusError(f"{manifest_path}: provenance is empty")
    if "source_commit" not in manifest:
        raise CorpusError(f"{manifest_path}: the manifest is missing 'source_commit'")
    source_commit = check_commit_word(manifest_path, manifest["source_commit"])

    listed = set()
    ordered = []
    for entry in manifest["files"]:
        path = root / entry["path"]
        if path in listed:
            raise CorpusError(f"{path}: listed twice in the manifest")
        if not path.exists():
            raise CorpusError(f"{path}: listed in the manifest but absent")
        listed.add(path)
        document = load_document(path)
        check_envelope(path, document, entry, source_commit)
        # A file may cover a whole namespace (`chain/header.json` holds both
        # `chain.header.*` and `chain.merkle.*`), so the guard is the top-level
        # namespace rather than the full group name. It still catches a case
        # pasted into the wrong domain file.
        namespace = entry["group"].split(".")[0]
        for case in document["cases"]:
            for field in CASE_FIELDS:
                if field not in case:
                    raise CorpusError(f"{path}: case {case.get('id')!r} is missing {field!r}")
            if not str(case["independent_check"]).strip():
                raise CorpusError(f"{path}: case {case['id']!r} has no independent_check")
            if case["id"].split(".")[0] != namespace:
                raise CorpusError(
                    f"{path}: case {case['id']!r} is outside namespace {namespace!r} "
                    f"of group {entry['group']!r}"
                )
            ordered.append(case)

    present = {path for path in root.rglob("*.json") if path != manifest_path}
    unlisted = sorted(path.relative_to(root).as_posix() for path in present - listed)
    if unlisted:
        raise CorpusError(f"{root}: files absent from the manifest: {unlisted}")
    if manifest.get("total_cases") != len(ordered):
        raise CorpusError(
            f"{manifest_path}: total_cases is {manifest.get('total_cases')}, found {len(ordered)}"
        )

    index = {}
    for case in ordered:
        if case["id"] in index:
            raise CorpusError(f"{case['id']}: duplicate case id")
        index[case["id"]] = case
    return index, ordered, manifest


def run(root, verbose):
    index, ordered, manifest = load_corpus(root)
    counts = {"PASS": 0, "ANCHOR": 0, "SKIP": 0, "FAIL": 0}
    failures = []
    for case in ordered:
        try:
            status = zro_vectors.verify_case(case, index)
            detail = ""
        except zro_vectors.VectorMismatch as error:
            status, detail = "FAIL", str(error)
        except zro_vectors.Unsupported as error:
            status, detail = "SKIP", str(error)
        except Exception as error:  # noqa: BLE001 - a malformed fixture must fail loudly
            status, detail = "FAIL", f"{type(error).__name__}: {error}"
        counts[status] += 1
        if status in ("FAIL", "SKIP"):
            failures.append((case["id"], status, detail))
        if verbose:
            line = f"{status:<6} {case['id']}"
            print(f"{line}  {detail}" if detail else line)

    total = len(ordered)
    print()
    print(f"phase {manifest.get('phase')}  corpus {total} cases  schema {manifest.get('schema')}")
    print(
        f"PASS {counts['PASS']}  ANCHOR {counts['ANCHOR']}  "
        f"SKIP {counts['SKIP']}  FAIL {counts['FAIL']}"
    )
    if failures:
        print()
        for case_id, status, detail in failures:
            print(f"{status} {case_id}: {detail}")
    return 0 if counts["FAIL"] == 0 and counts["SKIP"] == 0 else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--vectors",
        type=pathlib.Path,
        default=DEFAULT_ROOT,
        help=f"corpus directory (default: {DEFAULT_ROOT})",
    )
    parser.add_argument("--quiet", action="store_true", help="print only failures and the summary")
    arguments = parser.parse_args(argv)
    try:
        return run(arguments.vectors, not arguments.quiet)
    except CorpusError as error:
        print(f"CORPUS {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
