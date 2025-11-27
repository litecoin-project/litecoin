# ==============================================================================
# 1. Base Compiler Flags (Shared across all Linux builds)
# ==============================================================================

# -pipe: Use pipes instead of temporary files for communication between stages of compilation.
# This improves compilation speed, especially on faster disks, by reducing I/O overhead.
LINUX_BASE_CFLAGS := -pipe
LINUX_BASE_CXXFLAGS := $(LINUX_BASE_CFLAGS)


# ==============================================================================
# 2. Optimization and Debug Flags (For Release and Debug targets)
# ==============================================================================

# Release Optimization: -O2 provides a good balance of compilation speed and performance.
LINUX_RELEASE_CFLAGS := -O2
LINUX_RELEASE_CXXFLAGS := $(LINUX_RELEASE_CFLAGS)

# Debug Optimization: -O1 is generally preferred over -O0 in debug builds 
# as it allows the debugger to function well while performing minor optimizations.
LINUX_DEBUG_CFLAGS := -O1
LINUX_DEBUG_CXXFLAGS := $(LINUX_DEBUG_CFLAGS)

# Debug C++ Flags: Enable standard library debugging checks for safety and correctness.
# -D_GLIBCXX_DEBUG: Enables debug mode for the GNU C++ standard library (STL).
# -D_GLIBCXX_DEBUG_PEDANTIC: Enables even stricter checking.
LINUX_DEBUG_CPPFLAGS := -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC


# ==============================================================================
# 3. Toolchain Definitions (Architecture Specific)
# ==============================================================================

# Check if we are building a native toolchain for x86 architectures (32-bit or 64-bit).
# The '86' check is likely to catch both i686 and x86_64 architectures when building natively.
ifeq (86,$(findstring 86,$(build_arch)))
  # --- Native Toolchain (When 'build_arch' contains '86') ---
  # Define the necessary tools (CC, CXX, AR, RANLIB, NM, STRIP) for both 32-bit and 64-bit native builds.

  # 32-bit (i686) Tools
  I686_LINUX_CC := gcc -m32
  I686_LINUX_CXX := g++ -m32
  I686_LINUX_AR := ar
  I686_LINUX_RANLIB := ranlib
  I686_LINUX_NM := nm
  I686_LINUX_STRIP := strip

  # 64-bit (x86_64) Tools
  X86_64_LINUX_CC := gcc -m64
  X86_64_LINUX_CXX := g++ -m64
  X86_64_LINUX_AR := $(I686_LINUX_AR)      # Reusing the basic commands for clarity
  X86_64_LINUX_RANLIB := $(I686_LINUX_RANLIB)
  X86_64_LINUX_NM := $(I686_LINUX_NM)
  X86_64_LINUX_STRIP := $(I686_LINUX_STRIP)

else
  # --- Cross-Compilation Toolchain ---
  # Use the default host compiler, explicitly setting the target architecture via -m32 or -m64 flags.

  # 32-bit (i686) Tools (Cross-compilation)
  I686_LINUX_CC := $(default_host_CC) -m32
  I686_LINUX_CXX := $(default_host_CXX) -m32

  # 64-bit (x86_64) Tools (Cross-compilation)
  X86_64_LINUX_CC := $(default_host_CC) -m64
  X86_64_LINUX_CXX := $(default_host_CXX) -m64

  # For cross-compilation, the AR/RANLIB/NM/STRIP tools might need to be prefixed
  # (e.g., 'i686-linux-gnu-ar'). If not explicitly defined elsewhere, assume the 
  # $(default_host_...) prefix implicitly handles this, or use generic ones:
  I686_LINUX_AR := ar # Placeholder for potentially complex cross-arch tools
  # ... (and so on for RANLIB, NM, STRIP)
endif

# CMake specific variable definition
LINUX_CMAKE_SYSTEM := Linux
