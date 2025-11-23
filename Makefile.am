# Copyright (c) 2013-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Automake file for building, packaging, and testing components of the project.

# Pattern rule to print variables, e.g. make print-top_srcdir
print-%:
	@echo $* = $($*)

ACLOCAL_AMFLAGS = -I build-aux/m4
SUBDIRS = src
if ENABLE_MAN
SUBDIRS += doc/man
endif
.PHONY: deploy FORCE

export PYTHONPATH

# --- Library and Configuration Setup ---

if BUILD_BITCOIN_LIBS
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libbitcoinconsensus.pc
endif

# Define paths for built binaries
BITCOIND_BIN=$(top_builddir)/src/$(BITCOIN_DAEMON_NAME)$(EXEEXT)
BITCOIN_QT_BIN=$(top_builddir)/src/qt/$(BITCOIN_GUI_NAME)$(EXEEXT)
BITCOIN_CLI_BIN=$(top_builddir)/src/$(BITCOIN_CLI_NAME)$(EXEEXT)
BITCOIN_TX_BIN=$(top_builddir)/src/$(BITCOIN_TX_NAME)$(EXEEXT)
BITCOIN_WALLET_BIN=$(top_builddir)/src/$(BITCOIN_WALLET_TOOL_NAME)$(EXEEXT)
BITCOIN_WIN_INSTALLER=$(PACKAGE)-$(PACKAGE_VERSION)-win64-setup$(EXEEXT)

# Helper variables for string manipulation (used in macOS volume name)
empty :=
space := $(empty) $(empty)

# --- macOS (OSX) Packaging Variables ---

OSX_APP=Litecoin-Qt.app
# Volume name for the DMG, substituting spaces with hyphens
OSX_VOLNAME = $(subst $(space),-,$(PACKAGE_NAME))
OSX_DMG = $(OSX_VOLNAME).dmg
OSX_TEMP_ISO = $(OSX_DMG:.dmg=).temp.iso
OSX_BACKGROUND_SVG=background.svg
OSX_BACKGROUND_IMAGE=background.tiff
# DPIs used for generating background images (36dpi and 72dpi)
OSX_BACKGROUND_IMAGE_DPIS=36 72
OSX_DSSTORE_GEN=$(top_srcdir)/contrib/macdeploy/custom_dsstore.py
OSX_DEPLOY_SCRIPT=$(top_srcdir)/contrib/macdeploy/macdeployqtplus
OSX_FANCY_PLIST=$(top_srcdir)/contrib/macdeploy/fancy.plist
OSX_INSTALLER_ICONS=$(top_srcdir)/src/qt/res/icons/bitcoin.icns
# Info.plist for the application bundle (not installed)
OSX_PLIST=$(top_builddir)/share/qt/Info.plist 
# List of Qt translations to include in the macOS bundle
OSX_QT_TRANSLATIONS = ar,bg,ca,cs,da,de,es,fa,fi,fr,gd,gl,he,hu,it,ja,ko,lt,lv,pl,pt,ru,sk,sl,sv,uk,zh_CN,zh_TW

# --- Distribution Files ---

# Contrib files included in source distribution
DIST_CONTRIB = \
	$(top_srcdir)/contrib/linearize/linearize-data.py \
	$(top_srcdir)/contrib/linearize/linearize-hashes.py

# Share files included in source distribution
DIST_SHARE = \
	$(top_srcdir)/share/genbuild.sh \
	$(top_srcdir)/share/rpcauth

# Devtools/check scripts
BIN_CHECKS=$(top_srcdir)/contrib/devtools/symbol-check.py \
	$(top_srcdir)/contrib/devtools/security-check.py

# Files required for Windows NSIS packaging
WINDOWS_PACKAGING = $(top_srcdir)/share/pixmaps/bitcoin.ico \
	$(top_srcdir)/share/pixmaps/nsis-header.bmp \
	$(top_srcdir)/share/pixmaps/nsis-wizard.bmp \
	$(top_srcdir)/doc/README_windows.txt

# Files required for macOS packaging
OSX_PACKAGING = $(OSX_DEPLOY_SCRIPT) $(OSX_FANCY_PLIST) $(OSX_INSTALLER_ICONS) \
	$(top_srcdir)/contrib/macdeploy/$(OSX_BACKGROUND_SVG) \
	$(OSX_DSSTORE_GEN) \
	$(top_srcdir)/contrib/macdeploy/detached-sig-apply.sh \
	$(top_srcdir)/contrib/macdeploy/detached-sig-create.sh

# LCOV files generated during code coverage runs
COVERAGE_INFO = $(COV_TOOL_WRAPPER) baseline.info \
	test_bitcoin_filtered.info total_coverage.info \
	baseline_filtered.info functional_test.info functional_test_filtered.info \
	test_bitcoin_coverage.info test_bitcoin.info fuzz.info fuzz_filtered.info fuzz_coverage.info

# Hook to include clientversion.cpp in the source tarball (git archive is faster than copying)
dist-hook:
	-$(GIT) archive --format=tar HEAD -- src/clientversion.cpp | $(AMTAR) -C $(top_distdir) -xf -

# --- Windows Installer Rule (NSIS) ---

$(BITCOIN_WIN_INSTALLER): all-recursive
	# Create release directory and strip/install binaries
	$(MKDIR_P) $(top_builddir)/release
	STRIPPROG="$(STRIP)" $(INSTALL_STRIP_PROGRAM) $(BITCOIND_BIN) $(top_builddir)/release
	STRIPPROG="$(STRIP)" $(INSTALL_STRIP_PROGRAM) $(BITCOIN_QT_BIN) $(top_builddir)/release
	STRIPPROG="$(STRIP)" $(INSTALL_STRIP_PROGRAM) $(BITCOIN_CLI_BIN) $(top_builddir)/release
	STRIPPROG="$(STRIP)" $(INSTALL_STRIP_PROGRAM) $(BITCOIN_TX_BIN) $(top_builddir)/release
	STRIPPROG="$(STRIP)" $(INSTALL_STRIP_PROGRAM) $(BITCOIN_WALLET_BIN) $(top_builddir)/release
	# Build the installer using makensis
	@test -f $(MAKENSIS) && echo 'OutFile "$@"' | cat $(top_builddir)/share/setup.nsi - | $(MAKENSIS) -V2 - || \
	echo error: could not build $@
	@echo built $@

# --- macOS App Bundle Rules ---

# Create PkgInfo file
$(OSX_APP)/Contents/PkgInfo:
	$(MKDIR_P) $(@D)
	@echo "APPL????" > $@

# Create dummy language file for locale detection
$(OSX_APP)/Contents/Resources/empty.lproj:
	$(MKDIR_P) $(@D)
	@touch $@

# Install the Info.plist file
$(OSX_APP)/Contents/Info.plist: $(OSX_PLIST)
	$(MKDIR_P) $(@D)
	$(INSTALL_DATA) $< $@

# Install the application icon
$(OSX_APP)/Contents/Resources/bitcoin.icns: $(OSX_INSTALLER_ICONS)
	$(MKDIR_P) $(@D)
	$(INSTALL_DATA) $< $@

# Install and strip the main executable (Litecoin-Qt)
$(OSX_APP)/Contents/MacOS/Litecoin-Qt: all-recursive
	$(MKDIR_P) $(@D)
	STRIPPROG="$(STRIP)" $(INSTALL_STRIP_PROGRAM) $(BITCOIN_QT_BIN) $@

# Create display name strings file
$(OSX_APP)/Contents/Resources/Base.lproj/InfoPlist.strings:
	$(MKDIR_P) $(@D)
	echo '{	CFBundleDisplayName = "$(PACKAGE_NAME)"; CFBundleName = "$(PACKAGE_NAME)"; }' > $@

# List of all files needed to build the App Bundle
OSX_APP_BUILT=$(OSX_APP)/Contents/PkgInfo $(OSX_APP)/Contents/Resources/empty.lproj \
	$(OSX_APP)/Contents/Resources/bitcoin.icns $(OSX_APP)/Contents/Info.plist \
	$(OSX_APP)/Contents/MacOS/Litecoin-Qt $(OSX_APP)/Contents/Resources/Base.lproj/InfoPlist.strings

# Rule to get the volume name
osx_volname:
	echo $(OSX_VOLNAME) >$@

# --- macOS DMG Rules (Using BUILD_DARWIN flag) ---

if BUILD_DARWIN
# Build the DMG using macdeployqtplus and tiffutil (for older approach)
$(OSX_DMG): $(OSX_APP_BUILT) $(OSX_PACKAGING) $(OSX_BACKGROUND_IMAGE)
	$(PYTHON) $(OSX_DEPLOY_SCRIPT) $(OSX_APP) -add-qt-tr $(OSX_QT_TRANSLATIONS) -translations-dir=$(QT_TRANSLATION_DIR) -dmg -fancy $(OSX_FANCY_PLIST) -verbose 2 -volname $(OSX_VOLNAME)

# Generate 36 dpi background image
$(OSX_BACKGROUND_IMAGE).png: contrib/macdeploy/$(OSX_BACKGROUND_SVG)
	sed 's/PACKAGE_NAME/$(PACKAGE_NAME)/' < "$<" | $(RSVG_CONVERT) -f png -d 36 -p 36 -o $@
# Generate 72 dpi background image
$(OSX_BACKGROUND_IMAGE)@2x.png: contrib/macdeploy/$(OSX_BACKGROUND_SVG)
	sed 's/PACKAGE_NAME/$(PACKAGE_NAME)/' < "$<" | $(RSVG_CONVERT) -f png -d 72 -p 72 -o $@
# Combine PNGs into multi-DPI TIFF
$(OSX_BACKGROUND_IMAGE): $(OSX_BACKGROUND_IMAGE).png $(OSX_BACKGROUND_IMAGE)@2x.png
	tiffutil -cathidpicheck $^ -out $@

deploydir: $(OSX_DMG)
else
# --- macOS DMG Rules (Using xorriso/dmg for modern approach) ---

APP_DIST_DIR=$(top_builddir)/dist
# Extra files needed for the distribution directory layout
APP_DIST_EXTRAS=$(APP_DIST_DIR)/.background/$(OSX_BACKGROUND_IMAGE) $(APP_DIST_DIR)/.DS_Store $(APP_DIST_DIR)/Applications

# Create symbolic link to /Applications
$(APP_DIST_DIR)/Applications:
	@rm -f $@
	@cd $(@D); $(LN_S) /Applications $(@F)

# Trigger rule to build App Bundle and extras
$(APP_DIST_EXTRAS): $(APP_DIST_DIR)/$(OSX_APP)/Contents/MacOS/Litecoin-Qt

.INTERMEDIATE: $(OSX_TEMP_ISO)
# Create temporary ISO for DMG generation
$(OSX_TEMP_ISO): $(APP_DIST_EXTRAS)
	$(XORRISOFS) -D -l -V "$(OSX_VOLNAME)" -no-pad -r -dir-mode 0755 -o $@ dist

# Create final DMG from the temporary ISO
$(OSX_DMG): $(OSX_TEMP_ISO)
	$(DMG) dmg "$<" "$@"

# Generate background images for different DPIs
dpi%.$(OSX_BACKGROUND_IMAGE): contrib/macdeploy/$(OSX_BACKGROUND_SVG)
	sed 's/PACKAGE_NAME/$(PACKAGE_NAME)/' < "$<" | $(RSVG_CONVERT) -f png -d $* -p $* | $(IMAGEMAGICK_CONVERT) - $@
OSX_BACKGROUND_IMAGE_DPIFILES := $(foreach dpi,$(OSX_BACKGROUND_IMAGE_DPIS),dpi$(dpi).$(OSX_BACKGROUND_IMAGE))
# Combine DPI images into a multi-DPI TIFF
$(APP_DIST_DIR)/.background/$(OSX_BACKGROUND_IMAGE): $(OSX_BACKGROUND_IMAGE_DPIFILES)
	$(MKDIR_P) $(@D)
	$(TIFFCP) -c none $(OSX_BACKGROUND_IMAGE_DPIFILES) $@

# Generate the .DS_Store file for custom folder appearance
$(APP_DIST_DIR)/.DS_Store: $(OSX_DSSTORE_GEN)
	$(PYTHON) $< "$@" "$(OSX_VOLNAME)"

# Deploy the App Bundle and include Qt dependencies/translations
$(APP_DIST_DIR)/$(OSX_APP)/Contents/MacOS/Litecoin-Qt: $(OSX_APP_BUILT) $(OSX_PACKAGING)
	INSTALLNAMETOOL=$(INSTALLNAMETOOL) OTOOL=$(OTOOL) STRIP=$(STRIP) $(PYTHON) $(OSX_DEPLOY_SCRIPT) $(OSX_APP) -translations-dir=$(QT_TRANSLATION_DIR) -add-qt-tr $(OSX_QT_TRANSLATIONS) -verbose 2

deploydir: $(APP_DIST_EXTRAS)
endif

# --- Deployment Targets ---

if TARGET_DARWIN
appbundle: $(OSX_APP_BUILT)
deploy: $(OSX_DMG)
endif
if TARGET_WINDOWS
deploy: $(BITCOIN_WIN_INSTALLER)
endif

# --- Binary Build Rules ---

# Force re-make of Qt binary
$(BITCOIN_QT_BIN): FORCE
	$(MAKE) -C src qt/$(@F)

# Force re-make of daemon binary
$(BITCOIND_BIN): FORCE
	$(MAKE) -C src $(@F)

# Force re-make of CLI binary
$(BITCOIN_CLI_BIN): FORCE
	$(MAKE) -C src $(@F)

# Force re-make of tx utility binary
$(BITCOIN_TX_BIN): FORCE
	$(MAKE) -C src $(@F)

# Force re-make of wallet utility binary
$(BITCOIN_WALLET_BIN): FORCE
	$(MAKE) -C src $(@F)

# --- Code Coverage Rules (LCOV) ---

if USE_LCOV
# Filter pattern to exclude specific libraries/paths from coverage reports
LCOV_FILTER_PATTERN = \
	-p "/usr/local/" \
	-p "/usr/include/" \
	-p "/usr/lib/" \
	-p "/usr/lib64/" \
	-p "src/leveldb/" \
	-p "src/crc32c/" \
	-p "src/bench/" \
	-p "src/univalue" \
	-p "src/crypto/ctaes" \
	-p "src/crypto/blake3" \
	-p "src/secp256k1-zkp" \
	-p "depends"

DIR_FUZZ_SEED_CORPUS ?= qa-assets/fuzz_seed_corpus

# Wrapper for the coverage tool (if needed)
$(COV_TOOL_WRAPPER):
	@echo 'exec $(COV_TOOL) "$$@"' > $(COV_TOOL_WRAPPER)
	@chmod +x $(COV_TOOL_WRAPPER)

# Capture initial baseline coverage (before tests run)
baseline.info: $(COV_TOOL_WRAPPER)
	$(LCOV) -c -i -d $(abs_builddir)/src -o $@

# Filter out non-relevant code from the baseline
baseline_filtered.info: baseline.info
	$(abs_builddir)/contrib/filter-lcov.py $(LCOV_FILTER_PATTERN) $< $@
	$(LCOV) -a $@ $(LCOV_OPTS) -o $@

# Run fuzz tests and capture coverage
fuzz.info: baseline_filtered.info
	@TIMEOUT=15 test/fuzz/test_runner.py $(DIR_FUZZ_SEED_CORPUS) -l DEBUG
	$(LCOV) -c $(LCOV_OPTS) -d $(abs_builddir)/src --t fuzz-tests -o $@
	$(LCOV) -z $(LCOV_OPTS) -d $(abs_builddir)/src

# Filter fuzz coverage
fuzz_filtered.info: fuzz.info
	$(abs_builddir)/contrib/filter-lcov.py $(LCOV_FILTER_PATTERN) $< $@
	$(LCOV) -a $@ $(LCOV_OPTS) -o $@

# Run unit tests (test_bitcoin) and capture coverage
test_bitcoin.info: baseline_filtered.info
	$(MAKE) -C src/ check
	$(LCOV) -c $(LCOV_OPTS) -d $(abs_builddir)/src -t test_bitcoin -o $@
	$(LCOV) -z $(LCOV_OPTS) -d $(abs_builddir)/src

# Filter unit test coverage
test_bitcoin_filtered.info: test_bitcoin.info
	$(abs_builddir)/contrib/filter-lcov.py $(LCOV_FILTER_PATTERN) $< $@
	$(LCOV) -a $@ $(LCOV_OPTS) -o $@

# Run functional tests and capture coverage
functional_test.info: test_bitcoin_filtered.info
	@TIMEOUT=15 test/functional/test_runner.py $(EXTENDED_FUNCTIONAL_TESTS)
	$(LCOV) -c $(LCOV_OPTS) -d $(abs_builddir)/src --t functional-tests -o $@
	$(LCOV) -z $(LCOV_OPTS) -d $(abs_builddir)/src

# Filter functional test coverage
functional_test_filtered.info: functional_test.info
	$(abs_builddir)/contrib/filter-lcov.py $(LCOV_FILTER_PATTERN) $< $@
	$(LCOV) -a $@ $(LCOV_OPTS) -o $@

# Combine baseline and fuzz coverage
fuzz_coverage.info: fuzz_filtered.info
	$(LCOV) -a $(LCOV_OPTS) baseline_filtered.info -a fuzz_filtered.info -o $@ | $(GREP) "\%" | $(AWK) '{ print substr($$3,2,50) "/" $$5 }' > coverage_percent.txt

# Combine baseline and unit test coverage
test_bitcoin_coverage.info: baseline_filtered.info test_bitcoin_filtered.info
	$(LCOV) -a $(LCOV_OPTS) baseline_filtered.info -a test_bitcoin_filtered.info -o $@

# Combine all coverage (unit and functional tests)
total_coverage.info: test_bitcoin_filtered.info functional_test_filtered.info
	$(LCOV) -a $(LCOV_OPTS) baseline_filtered.info -a test_bitcoin_filtered.info -a functional_test_filtered.info -o $@ | $(GREP) "\%" | $(AWK) '{ print substr($$3,2,50) "/" $$5 }' > coverage_percent.txt

# Generate HTML report for fuzz coverage
fuzz.coverage/.dirstamp: fuzz_coverage.info
	$(GENHTML) -s $(LCOV_OPTS) $< -o $(@D)
	@touch $@

# Generate HTML report for unit test coverage
test_bitcoin.coverage/.dirstamp: test_bitcoin_coverage.info
	$(GENHTML) -s $(LCOV_OPTS) $< -o $(@D)
	@touch $@

# Generate HTML report for total coverage
total.coverage/.dirstamp: total_coverage.info
	$(GENHTML) -s $(LCOV_OPTS) $< -o $(@D)
	@touch $@

# Coverage targets
cov_fuzz: fuzz.coverage/.dirstamp

cov: test_bitcoin.coverage/.dirstamp total.coverage/.dirstamp

endif

# --- Source Distribution Files (EXTRA_DIST) ---

dist_noinst_SCRIPTS = autogen.sh

# Main list of files to include in source distribution
EXTRA_DIST = $(DIST_SHARE) $(DIST_CONTRIB) $(WINDOWS_PACKAGING) $(OSX_PACKAGING) $(BIN_CHECKS)

# Add test directories to distribution
EXTRA_DIST += \
	test/functional \
	test/fuzz

# Add miscellaneous test utility files to distribution
EXTRA_DIST += \
	test/util/bitcoin-util-test.py \
	test/util/data/bitcoin-util-test.json \
	test/util/data/blanktxv1.hex \
	test/util/data/blanktxv1.json \
	test/util/data/blanktxv2.hex \
	test/util/data/blanktxv2.json \
	test/util/data/tt-delin1-out.hex \
	test/util/data/tt-delin1-out.json \
	test/util/data/tt-delout1-out.hex \
	test/util/data/tt-delout1-out.json \
	test/util/data/tt-locktime317000-out.hex \
	test/util/data/tt-locktime317000-out.json \
	test/util/data/tx394b54bb.hex \
	test/util/data/txcreate1.hex \
	test/util/data/txcreate1.json \
	test/util/data/txcreate2.hex \
	test/util/data/txcreate2.json \
	test/util/data/txcreatedata1.hex \
	test/util/data/txcreatedata1.json \
	test/util/data/txcreatedata2.hex \
	test/util/data/txcreatedata2.json \
	test/util/data/txcreatedata_seq0.hex \
	test/util/data/txcreatedata_seq0.json \
	test/util/data/txcreatedata_seq1.hex \
	test/util/data/txcreatedata_seq1.json \
	test/util/data/txcreatemultisig1.hex \
	test/util/data/txcreatemultisig1.json \
	test/util/data/txcreatemultisig2.hex \
	test/util/data/txcreatemultisig2.json \
	test/util/data/txcreatemultisig3.hex \
	test/util/data/txcreatemultisig3.json \
	test/util/data/txcreatemultisig4.hex \
	test/util/data/txcreatemultisig4.json \
	test/util/data/txcreatemultisig5.json \
	test/util/data/txcreateoutpubkey1.hex \
	test/util/data/txcreateoutpubkey1.json \
	test/util/data/txcreateoutpubkey2.hex \
	test/util/data/txcreateoutpubkey2.json \
	test/util/data/txcreateoutpubkey3.hex \
	test/util/data/txcreateoutpubkey3.json \
	test/util/data/txcreatescript1.hex \
	test/util/data/txcreatescript1.json \
	test/util/data/txcreatescript2.hex \
	test/util/data/txcreatescript2.json \
	test/util/data/txcreatescript3.hex \
	test/util/data/txcreatescript3.json \
	test/util/data/txcreatescript4.hex \
	test/util/data/txcreatescript4.json \
	test/util/data/txcreatescript5.hex \
	test/util/data/txcreatescript6.hex \
	test/util/data/txcreatesignv1.hex \
	test/util/data/txcreatesignv1.json \
	test/util/data/txcreatesignv2.hex \
	test/util/rpcauth-test.py

# Files to be cleaned up after a build
CLEANFILES = $(OSX_DMG) $(BITCOIN_WIN_INSTALLER)

.INTERMEDIATE: $(COVERAGE_INFO)

DISTCHECK_CONFIGURE_FLAGS = --enable-man

# --- Doxygen Documentation Rules ---

# Rule to generate doxygen documentation
doc/doxygen/.stamp: doc/Doxyfile FORCE
	$(MKDIR_P) $(@D)
	$(DOXYGEN) $^
	$(AM_V_at) touch $@

if HAVE_DOXYGEN
docs: doc/doxygen/.stamp
else
docs:
	@echo "error: doxygen not found"
endif

# Target to clean generated documentation
clean-docs:
	rm -rf doc/doxygen

# Local cleanup target for miscellaneous files
clean-local: clean-docs
	rm -rf coverage_percent.txt test_bitcoin.coverage/ total.coverage/ fuzz.coverage/ test/tmp/ cache/ $(OSX_APP)
	rm -rf test/functional/__pycache__ test/functional/test_framework/__pycache__ test/cache share/rpcauth/__pycache__
	rm -rf osx_volname dist/ dpi36.background.tiff dpi72.background.tiff

# --- Security Check Tests ---

# Run security checks for platform-specific binaries
test-security-check:
if TARGET_DARWIN
	$(AM_V_at) $(PYTHON) $(top_srcdir)/contrib/devtools/test-security-check.py TestSecurityChecks.test_MACHO
endif
if TARGET_WINDOWS
	$(AM_V_at) $(PYTHON) $(top_srcdir)/contrib/devtools/test-security-check.py TestSecurityChecks.test_PE
endif
if TARGET_LINUX
	$(AM_V_at) $(PYTHON) $(top_srcdir)/contrib/devtools/test-security-check.py TestSecurityChecks.test_ELF
endif
