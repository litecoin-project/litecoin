# Test for Thread library from the Boost C++ libraries.
# Requires a preceding call to AX_BOOST_BASE.

# serial 34

AC_DEFUN([AX_BOOST_THREAD],
[
    AC_ARG_WITH([boost-thread],
    AS_HELP_STRING([--with-boost-thread@<:@=special-lib@:>@],
                   [use the Thread library from boost -
                    it is possible to specify a certain library for the linker
                    e.g. --with-boost-thread=boost_thread-gcc-mt ]),
        [
        if test "$withval" = "yes"; then
            want_boost="yes"
            ax_boost_user_thread_lib=""
        else
            want_boost="yes"
            ax_boost_user_thread_lib="$withval"
        fi
        ],
        [want_boost="yes"]
    )

    if test "x$want_boost" = "xyes"; then
        AC_REQUIRE([AC_PROG_CC])
        AC_REQUIRE([AC_CANONICAL_BUILD])
        
        # Save flags and apply Boost specific flags
        CPPFLAGS_SAVED="$CPPFLAGS"
        CPPFLAGS="$CPPFLAGS $BOOST_CPPFLAGS"
        LDFLAGS_SAVED="$LDFLAGS"
        LDFLAGS="$LDFLAGS $BOOST_LDFLAGS"
        export CPPFLAGS LDFLAGS

        # Determine thread compiler/linker flags based on host OS
        ax_boost_thread_compiler_flags=""
        ax_boost_thread_linker_flags=""

        case "x$host_os" in
            xsolaris)
                ax_boost_thread_compiler_flags="-pthreads"
                ax_boost_thread_linker_flags="-lpthread"
                ;;
            xmingw32)
                ax_boost_thread_compiler_flags="-mthreads"
                ;;
            *android*)
                # No special flags often needed for Android NDK
                ;;
            *bsd*)
                ax_boost_thread_linker_flags="-pthread"
                ;;
            *)
                ax_boost_thread_compiler_flags="-pthread"
                ax_boost_thread_linker_flags="-lpthread"
                ;;
        esac

        AC_CACHE_CHECK(whether the Boost::Thread library is available,
                      ax_cv_boost_thread,
        [
            AC_LANG_PUSH([C++])
            CXXFLAGS_SAVE=$CXXFLAGS
            LDFLAGS_TEST_SAVE=$LDFLAGS
            
            # Apply OS-specific flags for compile test
            CXXFLAGS="$ax_boost_thread_compiler_flags $CXXFLAGS"
            LDFLAGS="$ax_boost_thread_linker_flags $LDFLAGS"

            AC_COMPILE_IFELSE([
                AC_LANG_PROGRAM(
                    [[#include <boost/thread/thread.hpp>]],
                    [[boost::thread_group thrds;
                      return 0;]])],
                ax_cv_boost_thread=yes, ax_cv_boost_thread=no)
                
            CXXFLAGS=$CXXFLAGS_SAVE
            LDFLAGS=$LDFLAGS_TEST_SAVE
            AC_LANG_POP([C++])
        ])

        if test "x$ax_cv_boost_thread" = "xyes"; then
            # Add compiler flags permanently if test succeeded
            BOOST_CPPFLAGS="$ax_boost_thread_compiler_flags $BOOST_CPPFLAGS"
            AC_SUBST(BOOST_CPPFLAGS)

            AC_DEFINE(HAVE_BOOST_THREAD,,
                      [define if the Boost::Thread library is available])

            # Try to find the required Boost Thread library file
            ax_lib=""
            link_thread="no"
            
            # 1. User specified a library name
            if test "x$ax_boost_user_thread_lib" != "x"; then
                # Check for the specified library name and common variations
                for lib_name_check in $ax_boost_user_thread_lib "boost_thread-$ax_boost_user_thread_lib"; do
                    AC_CHECK_LIB($lib_name_check, exit,
                                 [link_thread="yes"; ax_lib="$lib_name_check"; break])
                done
            
            # 2. Automatically discover the library (no user specification)
            elif test "x$BOOST_LDFLAGS" != "x"; then
                # NOTE: We cannot safely parse `ls` output. 
                # Instead, check common known library names (e.g., boost_thread-mt) 
                # if BOOST_LDFLAGS gives us a directory to look in.
                
                # Default library name to check (most common)
                AC_CHECK_LIB(boost_thread, exit,
                             [link_thread="yes"; ax_lib="boost_thread"])
            
            # 3. Fallback: Check if the system linker can find it without -L flag (e.g., standard path)
            else 
                AC_CHECK_LIB(boost_thread, exit,
                             [link_thread="yes"; ax_lib="boost_thread"])
            fi

            if test "x$ax_lib" = "x"; then
                AC_MSG_ERROR(Could not find a suitable version of the Boost::Thread library!)
            fi
            
            if test "x$link_thread" = "xno"; then
                AC_MSG_ERROR(Could not link against the Boost::Thread library ($ax_lib)!)
            else
                BOOST_THREAD_LIB="-l$ax_lib $ax_boost_thread_linker_flags"
                
                # Check for Solaris -lpthread requirement again (can be complex)
                if test "x$host_os" = "xsolaris"; then
                    BOOST_THREAD_LIB="$BOOST_THREAD_LIB -lpthread"
                fi
                
                AC_SUBST(BOOST_THREAD_LIB)
            fi
        fi

        # Restore flags
        CPPFLAGS="$CPPFLAGS_SAVED"
        LDFLAGS="$LDFLAGS_SAVED"
        export CPPFLAGS LDFLAGS
    fi
])
