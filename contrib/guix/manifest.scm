(use-modules (gnu)
             (gnu packages)
             (gnu packages autotools) ; Used for autoconf/automake/libtool
             (gnu packages compression) ; Used for compression utils (tar, gzip, etc.)
             (gnu packages cross-base) ; Provides cross-binutils, cross-gcc, etc.
             (gnu packages file)
             (gnu packages gcc)
             (gnu packages mingw) ; Used for MinGW toolchain
             (gnu packages python) ; Used for python-3.7
             (gnu packages version-control) ; Used for git
             (guix build-system gnu)
             (guix build-system trivial)
             (guix packages)
             (guix utils))

;; --- Utility Functions for GCC Modification ---

(define (make-ssp-fixed-gcc xgcc)
  "Given a cross-GCC package (XGCC), returns a modified package that uses the 
SSP function from glibc instead of linking against libssp.so. 
This is typically done to satisfy symbol checks in environments like LFS/Guix."
  (package
    (inherit xgcc)
    (arguments
     (substitute-keyword-arguments (package-arguments xgcc)
       ;; Force GCC to believe glibc provides the Stack Smashing Protection (SSP) implementation.
       ((#:make-flags flags)
        `(cons "gcc_cv_libc_provides_ssp=yes" ,flags))))))

(define (make-gcc-rpath-link xgcc)
  "Given a cross-GCC package (XGCC), returns a modified package that replaces
-rpath instances inserted by Guix's default system spec with -rpath-link.
This is often necessary when linking static libraries during the cross-compilation
process to prevent unwanted run-time dependencies."
  (package
    (inherit xgcc)
    (arguments
     (substitute-keyword-arguments (package-arguments xgcc)
       ((#:phases phases)
        `(modify-phases ,phases
           (add-after 'pre-configure 'replace-rpath-with-rpath-link
             (lambda _
               (substitute* (cons "gcc/config/rs6000/sysv4.h"
                                  (find-files "gcc/config"
                                              "^gnu-user.*\\.h$"))
                            ;; Replace -rpath= with -rpath-link=
                            (("-rpath=") "-rpath-link="))
               #t))))))))

(define (make-gcc-with-pthreads gcc)
  "Returns a modified GCC package with POSIX threads enabled."
  (package-with-extra-configure-variable gcc "--enable-threads" "posix"))

;; --- Core Toolchain Builders ---

(define (make-cross-toolchain target
                              base-gcc-for-libc
                              base-kernel-headers
                              base-libc
                              base-gcc)
  "Creates a complete cross-compilation toolchain package for the specified TARGET.
The process follows the standard bootstrapping steps (binutils -> initial gcc -> 
kernel headers -> libc -> final gcc)."
  (let* ((xbinutils (cross-binutils target))
         ;; 1. Stage 1: Initial cross-compiling GCC without libc.
         (xgcc-sans-libc (cross-gcc target
                                    #:xgcc base-gcc-for-libc
                                    #:xbinutils xbinutils))
         ;; 2. Stage 2: Cross-compiled kernel headers.
         (xkernel (cross-kernel-headers target
                                        base-kernel-headers
                                        xgcc-sans-libc
                                        xbinutils))
         ;; 3. Stage 3: Cross-compiled libc (e.g., glibc).
         (xlibc (cross-libc target
                            base-libc
                            xgcc-sans-libc
                            xbinutils
                            xkernel))
         ;; 4. Stage 4: Final cross-compiling GCC, now targeting the cross-compiled libc.
         (xgcc (cross-gcc target
                          #:xgcc base-gcc
                          #:xbinutils xbinutils
                          #:libc xlibc)))
    ;; Define a meta-package to propagate all toolchain components.
    (package
      (name (string-append target "-toolchain"))
      (version (package-version xgcc))
      (source #f)
      (build-system trivial-build-system)
      (arguments '(#:builder (begin (mkdir %output) #t)))
      (propagated-inputs
       `(("binutils" ,xbinutils)
         ("libc" ,xlibc)
         ("libc:static" ,xlibc "static") ; Include static libc for full flexibility
         ("gcc" ,xgcc)))
      (synopsis (string-append "Complete GCC tool chain for " target))
      (description (string-append "This package provides a complete GCC tool
chain for " target " development."))
      (home-page (package-home-page xgcc))
      (license (package-license xgcc)))))

(define* (make-bitcoin-cross-toolchain target
                                     #:key
                                     (base-gcc-for-libc gcc-5)
                                     (base-kernel-headers linux-libre-headers-4.19)
                                     (base-libc glibc-2.27)
                                     (base-gcc (make-gcc-rpath-link gcc-9)))
  "Convenience wrapper around MAKE-CROSS-TOOLCHAIN with default values 
selected for building Bitcoin Core release binaries (as per common practice)."
  (make-cross-toolchain target
                        base-gcc-for-libc
                        base-kernel-headers
                        base-libc
                        base-gcc))

(define (make-mingw-pthreads-cross-toolchain target)
  "Creates a cross-compilation toolchain for TARGET using MinGW and winpthreads, 
specifically tailored for Windows (POSIX) cross-development."
  (let* ((xbinutils (cross-binutils target))
         ;; Use the MinGW winpthreads library as the libc for the cross-GCC
         (pthreads-xlibc mingw-w64-x86_64-winpthreads)
         ;; Final GCC: SSP-fixed, configured for winpthreads, and Pthreads-enabled
         (pthreads-xgcc (make-gcc-with-pthreads
                          (cross-gcc target
                                     #:xgcc (make-ssp-fixed-gcc gcc-9)
                                     #:xbinutils xbinutils
                                     #:libc pthreads-xlibc))))
    ;; Define a meta-package propagating the toolchain.
    (package
      (name (string-append target "-posix-toolchain"))
      (version (package-version pthreads-xgcc))
      (source #f)
      (build-system trivial-build-system)
      (arguments '(#:builder (begin (mkdir %output) #t)))
      (propagated-inputs
       `(("binutils" ,xbinutils)
         ("libc" ,pthreads-xlibc)
         ("gcc" ,pthreads-xgcc)))
      (synopsis (string-append "Complete GCC tool chain for " target))
      (description (string-append "This package provides a complete GCC tool
chain for " target " development."))
      (home-page (package-home-page pthreads-xgcc))
      (license (package-license pthreads-xgcc)))))


;; --- Final Manifest Generation ---

(packages->manifest
  (append
   (list ;; Essential Tools: Using a standard base package set for conciseness
         ;; This list replaces many explicit package names.
         (@@ (gnu packages base) base-packages) 
         
         ;; Specific/Non-Base Tools
         which
         util-linux
         grep
         diffutils
         pkg-config
         gnu-make
         libtool
         autoconf
         automake
         perl
         python-3.7
         git
         
         ;; Native Toolchain for building cross-tools
         (make-gcc-toolchain gcc-9 glibc-2.27))
   
   ;; Conditional Cross-Toolchain Definition
   (let ((target (getenv "HOST")))
     (cond ((string-suffix? "-mingw32" target)
            ;; Windows (MinGW) Toolchain
            (list zip 
                  (make-mingw-pthreads-cross-toolchain "x86_64-w64-mingw32")
                  nsis-x86_64))
           ((string-contains target "riscv64-linux-")
            ;; RISC-V Linux Toolchain (using an older GCC base for libc)
            (list (make-bitcoin-cross-toolchain "riscv64-linux-gnu"
                                                #:base-gcc-for-libc gcc-7)))
           ((string-contains target "-linux-")
            ;; General Linux Toolchains (e.g., arm-linux-gnu, aarch64-linux-gnu)
            (list (make-bitcoin-cross-toolchain target)))
           (else '())))))
