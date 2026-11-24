#!/usr/bin/env python3
"""Line coverage of the production code alone, from an lcov file.

    scripts/coverage-production.py target/llvm-cov/lcov.info

llvm-cov counts every line of a source file, the unit tests written at its
end included, and tests run their own lines by definition: the figure of the
report flatters. This one leaves out what follows the first `#[cfg(test)]` of
a file, and the files that only serve tests (`testing.rs`). Stable Rust has no
attribute to keep a module out of the measure, hence this script.

Prints the total, then the files under 100 %, lowest first.
"""

import os
import sys


def test_start(path):
    """The line of the first `#[cfg(test)]` of the file, or none."""
    try:
        with open(path, encoding="utf-8") as source:
            for number, line in enumerate(source, start=1):
                if line.strip() == "#[cfg(test)]":
                    return number
    except OSError:
        pass
    return None


def main():
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} <lcov.info>")
    root = os.getcwd() + os.sep
    files = {}
    path, cut = None, None
    with open(sys.argv[1], encoding="utf-8") as lcov:
        for record in lcov:
            record = record.strip()
            if record.startswith("SF:"):
                path = record[3:]
                cut = test_start(path)
                kept = os.sep + "src" + os.sep in path and os.path.basename(path) != "testing.rs"
                if not kept:
                    path = None
            elif record.startswith("DA:") and path:
                line, hits = record[3:].split(",")[:2]
                if cut is None or int(line) < cut:
                    found, covered = files.get(path, (0, 0))
                    files[path] = (found + 1, covered + (int(hits) > 0))
    found = sum(count for count, _ in files.values())
    covered = sum(count for _, count in files.values())
    if not found:
        sys.exit("no production line in the lcov file")
    print(f"production code: {100 * covered / found:.2f}% of the lines ({covered}/{found}), tests left out")
    partial = [(100 * hit / all_, all_ - hit, name) for name, (all_, hit) in files.items() if hit < all_]
    for percent, missed, name in sorted(partial):
        short = name[len(root):] if name.startswith(root) else name
        print(f"  {percent:6.2f}%  {missed:4d} missed  {short}")


if __name__ == "__main__":
    main()
