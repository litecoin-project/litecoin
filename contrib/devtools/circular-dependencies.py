#!/usr/bin/env python3
"""
@fileoverview Python script to detect circular dependencies between C/C++ modules 
based on #include directives.

It uses a transitive closure approach to find the shortest remaining dependency cycle 
in the module graph.
"""
import sys
import re
from typing import Dict, Set, List, Optional

# --- CONFIGURATION ---

# Mapping to consolidate multiple source files into a single module name (e.g., core_io)
MAPPING: Dict[str, str] = {
    'core_read.cpp': 'core_io.cpp',
    'core_write.cpp': 'core_io.cpp',
}

# Directories where headers define module logic, hence the header file itself 
# should be treated as the module name without stripping the extension.
HEADER_MODULE_PATHS: List[str] = [
    'interfaces/'
]

# Regex to capture #include <path/to/header.h>
INCLUDE_RE = re.compile(r"^#include <(.*)>")

# --- CORE LOGIC ---

def module_name(path: str) -> Optional[str]:
    """
    Determines the module name from a file path based on mapping and extension.
    """
    if path in MAPPING:
        path = MAPPING[path]

    # Special handling for header-based modules (e.g., interfaces/)
    if any(path.startswith(dirpath) for dirpath in HEADER_MODULE_PATHS):
        return path
    
    # Strip common file extensions to get the module base name
    if path.endswith((".h", ".c")):
        return path[:-2]
    if path.endswith(".cpp"):
        return path[:-4]
    
    return None

def find_circular_dependencies(module_deps: Dict[str, Set[str]]) -> bool:
    """
    Iteratively finds and reports the shortest remaining circular dependency
    in the module graph, breaking the cycle after reporting.
    Returns True if any cycle was found.
    """
    have_cycle = False
    
    while True:
        shortest_cycle: Optional[List[str]] = None
        
        for module in sorted(module_deps.keys()):
            # closure stores dependency -> path_to_module
            closure: Dict[str, List[str]] = {}
            
            # Start the search from the module's direct dependencies
            for dep in module_deps[module]:
                closure[dep] = []
                
            # Compute the transitive closure (BFS-like approach for path tracking)
            while True:
                old_size = len(closure)
                old_closure_keys = sorted(closure.keys())
                
                for src in old_closure_keys:
                    for dep in module_deps.get(src, set()):
                        if dep not in closure:
                            # Record the path taken to reach 'dep'
                            closure[dep] = closure[src] + [src]
                
                if len(closure) == old_size:
                    break # Closure calculation stabilized

            # Check for circular dependency (module depends on itself)
            if module in closure:
                cycle_path = [module] + closure[module]
                
                # Check if this is the shortest cycle found so far
                if shortest_cycle is None or len(cycle_path) < len(shortest_cycle):
                    shortest_cycle = cycle_path

        if shortest_cycle is None:
            break # No more cycles found

        # Report the shortest cycle
        module_start = shortest_cycle[0]
        module_end = shortest_cycle[-1]
        
        print("Circular dependency: %s" % (" -> ".join(shortest_cycle + [module_start])))
        
        # Break the dependency to avoid repeating in subsequent checks:
        # Remove the dependency edge from the last module back to the start module
        module_deps[module_end] = module_deps[module_end] - set([module_start])
        have_cycle = True
        
    return have_cycle

# --- MAIN EXECUTION ---

if __name__ == '__main__':
    
    files: Dict[str, str] = {}
    deps: Dict[str, Set[str]] = {}

    # Pass 1: Identify all input files and determine their module names
    for arg in sys.argv[1:]:
        module = module_name(arg)
        if module is None:
            # Using sys.stderr for non-critical informational output
            print(f"Ignoring file {arg} (does not constitute module)", file=sys.stderr)
        else:
            files[arg] = module
            deps[module] = set() # Initialize set of direct dependencies

    # Pass 2: Build the direct dependency graph
    for filepath in sorted(files.keys()):
        module = files[filepath]
        try:
            # Use 'with open' for safe file handling
            with open(filepath, 'r', encoding="utf8") as f:
                for line in f:
                    match = INCLUDE_RE.match(line)
                    if match:
                        include = match.group(1)
                        included_module = module_name(include)
                        
                        # Only record if it maps to a known module AND is not self-dependency
                        if included_module in deps and included_module != module:
                            deps[module].add(included_module)
                            
        except FileNotFoundError:
            print(f"Error: File not found: {filepath}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file {filepath}: {e}", file=sys.stderr)
            sys.exit(1)

    # Pass 3: Analyze dependencies for cycles
    found_cycle = find_circular_dependencies(deps)

    sys.exit(1 if found_cycle else 0)
