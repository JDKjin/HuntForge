from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

try:
    from pyfiglet import Figlet
except ImportError:  # pragma: no cover - optional presentation dependency
    Figlet = None

from poc import ajax, getSessionList, htmlofficeservlet, information, session_upload, sql, webmail
from poc import core


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Seeyon OA security evidence collector")
    targets = parser.add_mutually_exclusive_group(required=True)
    targets.add_argument("-u", "--url", help="single target URL")
    targets.add_argument("-f", "--file", type=Path, help="UTF-8 target URL file")
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="explicit JSONL evidence file inside the current working directory",
    )
    parser.add_argument(
        "--att",
        dest="attack",
        action="store_true",
        help="run the configured exploit-validation paths",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="disable TLS certificate validation for this run",
    )
    return parser


def _banner() -> None:
    print("====================================================")
    if Figlet is None:
        print("SeeyonExp")
    else:
        print(Figlet(font="slant").renderText("SeeyonExp"))
    print("Version 1.1 - evidence-safe output")
    print("====================================================")


def _scan(url: str, *, attack: bool) -> None:
    target = url.strip().rstrip("/")
    if not target:
        return
    information.check(target)
    getSessionList.get_sessionlist(target)
    webmail.check(target)
    sql.run(target, attack)
    session_upload.get_session(target, attack)
    htmlofficeservlet.check(target, attack)
    ajax.check(target, attack)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    options = parser.parse_args(argv)
    core.configure_tls(insecure=options.insecure)
    try:
        output_path = core.configure_output(options.output)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    _banner()
    if options.file is not None:
        try:
            targets = options.file.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            parser.error(f"cannot read target file: {exc}")
    else:
        targets = [options.url]

    for target in targets:
        _scan(str(target or ""), attack=options.attack)
    print(f"[#] scan complete; evidence: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
