#!/usr/bin/env python3
#
# clang-format-diff.py - ClangFormat Diff Reformatter
#
# This script reads input from a unified diff (e.g., git diff -U0) and 
# reformats only the lines that have been changed using the clang-format tool.
# This avoids unnecessarily reformatting an entire large file when only a 
# small portion has been modified.
#
# The script adheres to the University of Illinois/NCSA Open Source License.
#

import argparse
import difflib
import re
import subprocess
import sys
from typing import Dict, List, Optional, Iterator

# Set this to the full path if clang-format is not globally accessible.
CLANG_FORMAT_BINARY = 'clang-format'


def find_changed_lines(diff_stream: Iterator[str], prefix_strip: int, 
                       file_regex: Optional[str], file_iregex: str) -> Dict[str, List[str]]:
    """
    Parses a unified diff stream (stdin) to extract modified line ranges 
    for files matching the specified regular expression patterns.

    Args:
        diff_stream: Iterator over lines of the unified diff input.
        prefix_strip: Number of leading directories to strip from filenames (via -p option).
        file_regex: Case-sensitive pattern for filtering filenames.
        file_iregex: Case-insensitive pattern for filtering filenames.

    Returns:
        A dictionary mapping filenames to a list of clang-format arguments 
        (e.g., ['-lines', '10:15', '-lines', '20:20']).
    """
    lines_by_file: Dict[str, List[str]] = {}
    current_filename: Optional[str] = None
    
    # Regex to find the file path in the '+++ b/path/to/file' line of the diff.
    # The {%s} part is used for prefix stripping (e.g., {1} strips one prefix).
    filename_regex = re.compile(r'^\+\+\+\ (.*?/){%s}(\S*)' % prefix_strip)
    
    # Regex to find the start line and optional line count in the '@@ -x,y +a,b @@' hunk header.
    hunk_regex = re.compile(r'^@@.*\+(\d+)(,(\d+))?')

    for line in diff_stream:
        # 1. Look for file headers (e.g., +++ b/path/to/file)
        match_filename = filename_regex.search(line)
        if match_filename:
            current_filename = match_filename.group(2)
            continue

        if current_filename is None:
            continue

        # 2. Filter filenames based on provided regexes
        # Case-sensitive regex check (if provided)
        if file_regex is not None:
            if not re.match(f'^{file_regex}$', current_filename):
                current_filename = None
                continue
        # Case-insensitive regex check (if regex is not provided)
        else:
            if not re.match(f'^{file_iregex}$', current_filename, re.IGNORECASE):
                current_filename = None
                continue

        # 3. Look for hunk headers (e.g., @@ -10,5 +10,3 @@)
        match_hunk = hunk_regex.search(line)
        if match_hunk:
            start_line = int(match_hunk.group(1))
            
            # Group 3 contains the line count, defaulting to 1 if not present.
            line_count = 1
            if match_hunk.group(3):
                line_count = int(match_hunk.group(3))
            
            if line_count == 0:
                continue

            end_line = start_line + line_count - 1
            line_range_arg = f'{start_line}:{end_line}'
            
            # Store the range as arguments for clang-format
            lines_by_file.setdefault(current_filename, []).extend(['-lines', line_range_arg])

    return lines_by_file


def main():
    parser = argparse.ArgumentParser(
        description='Reformat changed lines in diff using clang-format. '
                    'Use -i to apply edits to files directly, otherwise a diff is displayed.'
    )
    
    # Action options
    parser.add_argument('-i', action='store_true', default=False,
                        help='Apply edits to files instead of displaying a diff.')
    parser.add_argument('-sort-includes', action='store_true', default=False,
                        help='Let clang-format sort include blocks.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Be more verbose when running with -i.')
    
    # Filtering options
    parser.add_argument('-p', metavar='NUM', default=0, type=int,
                        help='Strip the smallest prefix containing P slashes (e.g., -p1 strips "a/").')
    parser.add_argument('-regex', metavar='PATTERN', default=None,
                        help='Custom case-sensitive pattern selecting file paths to reformat (overrides -iregex).')
    parser.add_argument('-iregex', metavar='PATTERN', 
                        default=r'.*\.(cpp|cc|c\+\+|cxx|c|cl|h|hpp|m|mm|inc|js|ts|proto|protodevel|java)',
                        help='Custom case-insensitive pattern selecting file paths to reformat (default covers C++ family, Java, and JS/TS).')
    
    args = parser.parse_args()

    # Get changed lines for each file by parsing stdin
    lines_by_file = find_changed_lines(sys.stdin, args.p, args.regex, args.iregex)

    # Reformat files containing changes.
    for filename, lines in lines_by_file.items():
        # Construct the base command
        command = [CLANG_FORMAT_BINARY, filename]
        
        if args.i:
            command.append('-i')
            if args.verbose:
                print(f'Formatting {filename} in place.')
        
        if args.sort_includes:
            command.append('-sort-includes')
            
        command.extend(lines)
        
        # Enforce using a .clang-format file for style or fallback to 'none'.
        command.extend(['-style=file', '-fallback-style=none'])
        
        # Execute clang-format
        # Set universal_newlines=True (renamed to text=True in newer Python versions) for text mode.
        try:
            p = subprocess.run(
                command,
                capture_output=True, # Captures stdout/stderr
                check=True,          # Raises CalledProcessError on non-zero exit code
                text=True,           # Use text mode for string I/O (equivalent to universal_newlines=True)
                input=''             # Provide empty input stream 
            )
        except subprocess.CalledProcessError as e:
            print(f"Error running clang-format on {filename}:", file=sys.stderr)
            print(e.stderr, file=sys.stderr)
            sys.exit(e.returncode)
        except FileNotFoundError:
            print(f"Error: clang-format binary '{CLANG_FORMAT_BINARY}' not found. Check your PATH.", file=sys.stderr)
            sys.exit(1)

        # If not applying in-place, generate and display the unified diff.
        if not args.i:
            # Read the original file content
            try:
                with open(filename, encoding="utf8") as f:
                    original_code = f.readlines()
            except FileNotFoundError:
                print(f"Error: Original file not found: {filename}", file=sys.stderr)
                continue
            except UnicodeDecodeError:
                print(f"Warning: Could not decode {filename} with utf8.", file=sys.stderr)
                continue
                
            # Formatted code is captured in p.stdout
            formatted_code = p.stdout.splitlines(keepends=True)

            # Generate and print the diff
            diff = difflib.unified_diff(
                original_code,
                formatted_code,
                filename, filename,
                '(before formatting)', '(after formatting)'
            )
            
            diff_string = ''.join(diff)
            if len(diff_string) > 0:
                sys.stdout.write(diff_string)

if __name__ == '__main__':
    main()
