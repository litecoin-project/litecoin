#!/usr/bin/env python3
# Copyright (c) 2026 The Litecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/licenses/MIT.
"""Exercise Linux macOS bundle staging with the depends mac_alias and ds_store packages."""

import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

try:
    from ds_store import DSStore
    from mac_alias import Alias
except ImportError:
    DSStore = Alias = None


HERE = Path(__file__).resolve().parent
SCRIPT = HERE / 'macdeployqtplus'


@unittest.skipUnless(sys.platform.startswith('linux') and DSStore is not None and Alias is not None,
                     'Linux and the depends mac_alias/ds_store packages are required')
class MacDeployTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='litecoin-macdeploy-test-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        bundle = self.root / 'Litecoin-Qt.app/Contents'
        (bundle / 'MacOS').mkdir(parents=True)
        (bundle / 'MacOS/Litecoin-Qt').write_bytes(b'static Qt executable fixture')
        (bundle / 'Resources').mkdir()
        self.translations = self.root / 'translations'
        self.translations.mkdir()
        (self.translations / 'qt_en.qm').write_bytes(b'translation fixture')
        background = self.root / 'contrib/macdeploy/background.tiff'
        background.parent.mkdir(parents=True)
        shutil.copyfile(str(HERE / 'background.tiff'), str(background))
        self.otool = self.root / 'otool'
        self.otool.write_text('#!/bin/sh\nprintf "%s:\\n" "$2"\n', encoding='utf8')
        self.otool.chmod(0o755)

    def deploy(self, name='Litecoin-Core'):
        env = dict(os.environ, OTOOL=str(self.otool), PYTHONDONTWRITEBYTECODE='1')
        env.pop('QTDIR', None)
        result = subprocess.run([sys.executable, str(SCRIPT), 'Litecoin-Qt.app', name,
                                 '-translations-dir=' + str(self.translations), '-no-strip', '-no-plugins'],
                                cwd=str(self.root), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, encoding='utf8')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return self.root / 'dist'

    # Static Qt staging must produce a readable background alias without corrupting the nested Litecoin folder record.
    def test_background_alias(self):
        output = self.deploy()
        with DSStore.open(str(output / '.DS_Store'), 'r') as store:
            payload = store['.']['icvp']['backgroundImageAlias']
            self.assertEqual(store['Applications']['Iloc'], (370, 156))
            self.assertEqual(store['Litecoin-Qt.app']['Iloc'], (128, 156))
        alias = Alias.from_bytes(payload)
        self.assertEqual(struct.unpack_from('>H', payload, 4)[0], len(payload))
        self.assertEqual(alias.volume.name, 'Litecoin-Core')
        self.assertEqual(alias.volume.posix_path, '/Volumes/Litecoin-Core')
        self.assertEqual(alias.target.filename, 'background.tiff')
        self.assertEqual(alias.target.folder_name, '.background')
        self.assertEqual(alias.target.posix_path, '/.background/background.tiff')
        self.assertEqual(alias.volume.disk_image_alias.target.folder_name, 'litecoin')
        self.assertEqual(alias.to_bytes(), payload)
        self.assertEqual((output / '.background/background.tiff').read_bytes(), (HERE / 'background.tiff').read_bytes())
        self.assertEqual(os.readlink(str(output / 'Applications')), '/Applications')
        self.assertEqual((output / 'Litecoin-Qt.app/Contents/Resources/qt_en.qm').read_bytes(), b'translation fixture')

    # Repeated staging stays byte-for-byte reproducible when the volume name has odd or even length and spaces.
    def test_reproducible_store_for_volume_names(self):
        for name in ('Litecoin-Core', 'Litecoin Core Testnet'):
            with self.subTest(name=name):
                first = (self.deploy(name) / '.DS_Store').read_bytes()
                second = (self.deploy(name) / '.DS_Store').read_bytes()
                self.assertEqual(first, second)
                with DSStore.open(str(self.root / 'dist/.DS_Store'), 'r') as store:
                    alias = Alias.from_bytes(store['.']['icvp']['backgroundImageAlias'])
                self.assertEqual(alias.volume.name, name)
                self.assertEqual(alias.volume.posix_path, '/Volumes/' + name)


if __name__ == '__main__':
    unittest.main()
