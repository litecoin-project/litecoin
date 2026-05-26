#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Verify published Gitian signatures and summarize agreed output hashes."""

import argparse
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


TARGETS = {
    "linux": "contrib/gitian-descriptors/gitian-linux.yml",
    "win-unsigned": "contrib/gitian-descriptors/gitian-win.yml",
    "osx-unsigned": "contrib/gitian-descriptors/gitian-osx.yml",
}

OUT_MANIFEST_RE = re.compile(r"^\s+([^:#][^:]+):\s*([0-9a-fA-F]{64})\s*$")
SHA_LINE_RE = re.compile(r"^\s*([0-9a-fA-F]{64})\s+(\S+)\s*$")


def parse_assert_manifest(assert_file):
    hashes = {}
    in_out_manifest = False

    for line in assert_file.read_text(encoding="utf-8", errors="replace").splitlines():
        if line == "out_manifest:":
            in_out_manifest = True
            continue
        if in_out_manifest and line and not line.startswith((" ", "\t")):
            in_out_manifest = False

        if in_out_manifest:
            match = OUT_MANIFEST_RE.match(line)
            if match:
                hashes[match.group(1).strip().strip("'\"")] = match.group(2).lower()
                continue

        match = SHA_LINE_RE.match(line)
        if match:
            hashes[match.group(2)] = match.group(1).lower()

    return hashes


def collect_signer_manifests(release_dir):
    manifests = {}
    for signer_dir in sorted(path for path in release_dir.iterdir() if path.is_dir()):
        signer_hashes = {}
        for assert_file in sorted(signer_dir.glob("*.assert")):
            signer_hashes.update(parse_assert_manifest(assert_file))
        if signer_hashes:
            manifests[signer_dir.name] = signer_hashes
    return manifests


def consensus_hashes(manifests):
    by_file = defaultdict(dict)
    for signer, hashes in manifests.items():
        for filename, digest in hashes.items():
            by_file[filename][signer] = digest

    agreed = {}
    mismatches = {}
    for filename, signer_hashes in sorted(by_file.items()):
        unique_hashes = set(signer_hashes.values())
        if len(unique_hashes) == 1:
            agreed[filename] = next(iter(unique_hashes))
        else:
            mismatches[filename] = signer_hashes
    return agreed, mismatches


def run_gverify(gitian_builder_dir, sigs_dir, repo_dir, version, target):
    descriptor = repo_dir / TARGETS[target]
    release = f"{version}-{target}"
    command = [
        str(Path("bin") / "gverify"),
        "-v",
        "-d",
        str(sigs_dir),
        "-r",
        release,
        str(descriptor),
    ]
    completed = subprocess.run(command, cwd=gitian_builder_dir, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return completed.returncode, completed.stdout


def write_report(args, results, checksums):
    lines = [
        f"# Gitian verification report for {args.version}",
        "",
        f"Minimum builders required per target: {args.min_builders}",
        "",
    ]

    for result in results:
        status = "PASS" if result["ok"] else "FAIL"
        lines.extend(
            [
                f"## {result['target']}: {status}",
                "",
                f"- Release directory: `{result['release_dir']}`",
                f"- Builders with assertions: {len(result['signers'])}",
                f"- Signers: {', '.join(result['signers']) if result['signers'] else '(none)'}",
                f"- `gverify` exit code: {result['gverify_rc']}",
                f"- Agreed output files: {len(result['agreed'])}",
                f"- Mismatched output files: {len(result['mismatches'])}",
                "",
            ]
        )
        if result["mismatches"]:
            lines.append("Mismatches:")
            for filename, signer_hashes in result["mismatches"].items():
                lines.append(f"- `{filename}`")
                for signer, digest in sorted(signer_hashes.items()):
                    lines.append(f"  - `{signer}`: `{digest}`")
            lines.append("")

        log_path = args.output_dir / f"gverify-{result['target']}.log"
        log_path.write_text(result["gverify_output"], encoding="utf-8")
        lines.append(f"`gverify` log: `{log_path.name}`")
        lines.append("")

    if checksums:
        lines.extend(["## Agreed checksums", ""])
        for filename, digest in sorted(checksums.items()):
            lines.append(f"`{digest}  {filename}`")
        lines.append("")

    report_path = args.output_dir / "gitian-verification-report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")

    checksums_path = args.output_dir / "SHA256SUMS.gitian"
    checksums_path.write_text(
        "".join(f"{digest}  {filename}\n" for filename, digest in sorted(checksums.items())),
        encoding="utf-8",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="Release version without leading v, for example 0.21.4")
    parser.add_argument("--min-builders", type=int, default=3, help="Minimum independent builders required per target")
    parser.add_argument("--target", action="append", choices=sorted(TARGETS), dest="targets", help="Target to verify")
    parser.add_argument("--sigs-dir", type=Path, required=True, help="Path to gitian.sigs.ltc checkout")
    parser.add_argument("--gitian-builder-dir", type=Path, required=True, help="Path to gitian-builder checkout")
    parser.add_argument("--repo-dir", type=Path, default=Path.cwd(), help="Path to litecoin checkout")
    parser.add_argument("--output-dir", type=Path, default=Path("release-assist-output"), help="Report output directory")
    args = parser.parse_args()

    args.targets = args.targets or sorted(TARGETS)
    args.sigs_dir = args.sigs_dir.resolve()
    args.gitian_builder_dir = args.gitian_builder_dir.resolve()
    args.repo_dir = args.repo_dir.resolve()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    overall_ok = True
    all_checksums = {}
    results = []

    for target in args.targets:
        release_dir = args.sigs_dir / f"{args.version}-{target}"
        manifests = collect_signer_manifests(release_dir) if release_dir.is_dir() else {}
        agreed, mismatches = consensus_hashes(manifests)
        gverify_rc, gverify_output = run_gverify(args.gitian_builder_dir, args.sigs_dir, args.repo_dir, args.version, target)

        target_ok = (
            len(manifests) >= args.min_builders
            and gverify_rc == 0
            and not mismatches
            and bool(agreed)
        )
        overall_ok = overall_ok and target_ok
        all_checksums.update(agreed)
        results.append(
            {
                "target": target,
                "release_dir": release_dir,
                "signers": sorted(manifests),
                "agreed": agreed,
                "mismatches": mismatches,
                "gverify_rc": gverify_rc,
                "gverify_output": gverify_output,
                "ok": target_ok,
            }
        )

    write_report(args, results, all_checksums)

    if not overall_ok:
        print(f"Gitian verification failed for {args.version}. See {args.output_dir}.", file=sys.stderr)
        return 1

    print(f"Gitian verification passed for {args.version}. See {args.output_dir}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
