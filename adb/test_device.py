#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from __future__ import print_function

import hashlib
import os
import posixpath
import random
import shlex
import shutil
import subprocess
import tempfile
import unittest

import mock

import adb


class GetDeviceTest(unittest.TestCase):
    def setUp(self):
        self.android_serial = os.getenv('ANDROID_SERIAL')
        del os.environ['ANDROID_SERIAL']

    def tearDown(self):
        os.environ['ANDROID_SERIAL'] = self.android_serial

    @mock.patch('adb.device.get_devices')
    def test_explicit(self, mock_get_devices):
        mock_get_devices.return_value = ['foo', 'bar']
        device = adb.get_device('foo')
        self.assertEqual(device.serial, 'foo')

    @mock.patch('adb.device.get_devices')
    def test_from_env(self, mock_get_devices):
        mock_get_devices.return_value = ['foo', 'bar']
        os.environ['ANDROID_SERIAL'] = 'foo'
        device = adb.get_device()
        self.assertEqual(device.serial, 'foo')

    @mock.patch('adb.device.get_devices')
    def test_arg_beats_env(self, mock_get_devices):
        mock_get_devices.return_value = ['foo', 'bar']
        os.environ['ANDROID_SERIAL'] = 'bar'
        device = adb.get_device('foo')
        self.assertEqual(device.serial, 'foo')

    @mock.patch('adb.device.get_devices')
    def test_no_such_device(self, mock_get_devices):
        mock_get_devices.return_value = ['foo', 'bar']
        self.assertRaises(adb.DeviceNotFoundError, adb.get_device, ['baz'])

        os.environ['ANDROID_SERIAL'] = 'baz'
        self.assertRaises(adb.DeviceNotFoundError, adb.get_device)

    @mock.patch('adb.device.get_devices')
    def test_unique_device(self, mock_get_devices):
        mock_get_devices.return_value = ['foo']
        device = adb.get_device()
        self.assertEqual(device.serial, 'foo')

    @mock.patch('adb.device.get_devices')
    def test_no_unique_device(self, mock_get_devices):
        mock_get_devices.return_value = ['foo', 'bar']
        self.assertRaises(adb.NoUniqueDeviceError, adb.get_device)


class DeviceTest(unittest.TestCase):
    def setUp(self):
        self.device = adb.get_device()


class ShellTest(DeviceTest):
    def test_cat(self):
        """Check that we can at least cat a file."""
        out = self.device.shell(['cat', '/proc/uptime']).strip()
        elements = out.split()
        self.assertEqual(len(elements), 2)

        uptime, idle = elements
        self.assertGreater(float(uptime), 0.0)
        self.assertGreater(float(idle), 0.0)

    def test_throws_on_failure(self):
        self.assertRaises(subprocess.CalledProcessError,
                          self.device.shell, ['false'])

    def test_output_not_stripped(self):
        out = self.device.shell(['echo', 'foo'])
        self.assertEqual(out, 'foo' + self.device.linesep)

    def test_shell_nocheck_failure(self):
        rc, out = self.device.shell_nocheck(['false'])
        self.assertNotEqual(rc, 0)
        self.assertEqual(out, '')

    def test_shell_nocheck_output_not_stripped(self):
        rc, out = self.device.shell_nocheck(['echo', 'foo'])
        self.assertEqual(rc, 0)
        self.assertEqual(out, 'foo' + self.device.linesep)

    def test_can_distinguish_tricky_results(self):
        # If result checking on ADB shell is naively implemented as
        # `adb shell <cmd>; echo $?`, we would be unable to distinguish the
        # output from the result for a cmd of `echo -n 1`.
        rc, out = self.device.shell_nocheck(['echo', '-n', '1'])
        self.assertEqual(rc, 0)
        self.assertEqual(out, '1')

    def test_line_endings(self):
        """Ensure that line ending translation is not happening in the pty.

        Bug: http://b/19735063
        """
        output = self.device.shell(['uname'])
        self.assertEqual(output, 'Linux' + self.device.linesep)


class ArgumentEscapingTest(DeviceTest):
    def test_shell_escaping(self):
        """Make sure that argument escaping is somewhat sane."""

        # http://b/19734868
        # Note that this actually matches ssh(1)'s behavior --- it's
        # converted to `sh -c echo hello; echo world` which sh interprets
        # as `sh -c echo` (with an argument to that shell of "hello"),
        # and then `echo world` back in the first shell.
        result = self.device.shell(
            shlex.split("sh -c 'echo hello; echo world'"))
        result = result.splitlines()
        self.assertEqual(['', 'world'], result)
        # If you really wanted "hello" and "world", here's what you'd do:
        result = self.device.shell(
            shlex.split(r'echo hello\;echo world')).splitlines()
        self.assertEqual(['hello', 'world'], result)

        # http://b/15479704
        result = self.device.shell(shlex.split("'true && echo t'")).strip()
        self.assertEqual('t', result)
        result = self.device.shell(
            shlex.split("sh -c 'true && echo t'")).strip()
        self.assertEqual('t', result)

        # http://b/20564385
        result = self.device.shell(shlex.split('FOO=a BAR=b echo t')).strip()
        self.assertEqual('t', result)
        result = self.device.shell(shlex.split(r'echo -n 123\;uname')).strip()
        self.assertEqual('123Linux', result)

    def test_install_argument_escaping(self):
        """Make sure that install argument escaping works."""
        # http://b/20323053
        tf = tempfile.NamedTemporaryFile('wb', suffix='-text;ls;1.apk')
        self.assertIn("-text;ls;1.apk", self.device.install(tf.name))

        # http://b/3090932
        tf = tempfile.NamedTemporaryFile('wb', suffix="-Live Hold'em.apk")
        self.assertIn("-Live Hold'em.apk", self.device.install(tf.name))


class RootUnrootTest(DeviceTest):
    def _test_root(self):
        message = self.device.root()
        if 'adbd cannot run as root in production builds' in message:
            return
        self.device.wait()
        self.assertEqual('root', self.device.shell(['id', '-un']).strip())

    def _test_unroot(self):
        self.device.unroot()
        self.device.wait()
        self.assertEqual('shell', self.device.shell(['id', '-un']).strip())

    def test_root_unroot(self):
        """Make sure that adb root and adb unroot work, using id(1)."""
        original_user = self.device.shell(['id', '-un']).strip()
        try:
            if original_user == 'root':
                self._test_unroot()
                self._test_root()
            elif original_user == 'shell':
                self._test_root()
                self._test_unroot()
        finally:
            if original_user == 'root':
                self.device.root()
            else:
                self.device.unroot()
            self.device.wait()


class TcpIpTest(DeviceTest):
    def test_tcpip_failure_raises(self):
        """adb tcpip requires a port.

        Bug: http://b/22636927
        """
        self.assertRaises(
            subprocess.CalledProcessError, self.device.tcpip, '')
        self.assertRaises(
            subprocess.CalledProcessError, self.device.tcpip, 'foo')


def compute_md5(string):
    hsh = hashlib.md5()
    hsh.update(string)
    return hsh.hexdigest()


def get_md5_prog(device):
    """Older platforms (pre-L) had the name md5 rather than md5sum."""
    try:
        device.shell(['md5sum', '/proc/uptime'])
        return 'md5sum'
    except subprocess.CalledProcessError:
        return 'md5'


class HostFile(object):
    def __init__(self, handle, checksum):
        self.handle = handle
        self.checksum = checksum
        self.full_path = handle.name
        self.base_name = os.path.basename(self.full_path)


class DeviceFile(object):
    def __init__(self, checksum, full_path):
        self.checksum = checksum
        self.full_path = full_path
        self.base_name = posixpath.basename(self.full_path)


def make_random_host_files(in_dir, num_files):
    min_size = 1 * (1 << 10)
    max_size = 16 * (1 << 10)

    files = []
    for _ in xrange(num_files):
        file_handle = tempfile.NamedTemporaryFile(dir=in_dir, delete=False)

        size = random.randrange(min_size, max_size, 1024)
        rand_str = os.urandom(size)
        file_handle.write(rand_str)
        file_handle.flush()
        file_handle.close()

        md5 = compute_md5(rand_str)
        files.append(HostFile(file_handle, md5))
    return files


def make_random_device_files(device, in_dir, num_files):
    min_size = 1 * (1 << 10)
    max_size = 16 * (1 << 10)

    files = []
    for file_num in xrange(num_files):
        size = random.randrange(min_size, max_size, 1024)

        base_name = 'device_tmpfile' + str(file_num)
        full_path = os.path.join(in_dir, base_name)

        device.shell(['dd', 'if=/dev/urandom', 'of={}'.format(full_path),
                      'bs={}'.format(size), 'count=1'])
        dev_md5, _ = device.shell([get_md5_prog(device), full_path]).split()

        files.append(DeviceFile(dev_md5, full_path))
    return files


class FileOperationsTest(DeviceTest):
    SCRATCH_DIR = '/data/local/tmp'
    DEVICE_TEMP_FILE = SCRATCH_DIR + '/adb_test_file'
    DEVICE_TEMP_DIR = SCRATCH_DIR + '/adb_test_dir'

    def _test_push(self, local_file, checksum):
        self.device.shell(['rm', '-rf', self.DEVICE_TEMP_FILE])
        try:
            self.device.push(
                local=local_file, remote=self.DEVICE_TEMP_FILE)
            dev_md5, _ = self.device.shell(
                [get_md5_prog(self.device), self.DEVICE_TEMP_FILE]).split()
            self.assertEqual(checksum, dev_md5)
        finally:
            self.device.shell(['rm', '-f', self.DEVICE_TEMP_FILE])

    def test_push(self):
        """Push a randomly generated file to specified device."""
        kbytes = 512
        tmp = tempfile.NamedTemporaryFile(mode='wb', delete=False)
        try:
            rand_str = os.urandom(1024 * kbytes)
            tmp.write(rand_str)
            tmp.close()
            self._test_push(tmp.name, compute_md5(rand_str))
        finally:
            os.remove(tmp.name)

    # TODO: write push directory test.

    def _test_pull(self, remote_file, checksum):
        tmp_write = tempfile.NamedTemporaryFile(mode='wb', delete=False)
        try:
            tmp_write.close()
            self.device.pull(remote=remote_file, local=tmp_write.name)
            with open(tmp_write.name, 'rb') as tmp_read:
                host_contents = tmp_read.read()
                host_md5 = compute_md5(host_contents)
            self.assertEqual(checksum, host_md5)
        finally:
            os.remove(tmp_write.name)

    def test_pull(self):
        """Pull a randomly generated file from specified device."""
        kbytes = 512
        self.device.shell(['rm', '-rf', self.DEVICE_TEMP_FILE])
        try:
            cmd = ['dd', 'if=/dev/urandom',
                   'of={}'.format(self.DEVICE_TEMP_FILE), 'bs=1024',
                   'count={}'.format(kbytes)]
            self.device.shell(cmd)
            dev_md5, _ = self.device.shell(
                [get_md5_prog(self.device), self.DEVICE_TEMP_FILE]).split()
            self._test_pull(self.DEVICE_TEMP_FILE, dev_md5)
        finally:
            self.device.shell_nocheck(['rm', self.DEVICE_TEMP_FILE])

    def test_pull_dir(self):
        """Pull a randomly generated directory of files from the device."""
        host_dir = tempfile.mkdtemp()
        try:
            self.device.shell(['rm', '-rf', self.DEVICE_TEMP_DIR])
            self.device.shell(['mkdir', '-p', self.DEVICE_TEMP_DIR])

            # Populate device directory with random files.
            temp_files = make_random_device_files(
                self.device, in_dir=self.DEVICE_TEMP_DIR, num_files=32)

            self.device.pull(remote=self.DEVICE_TEMP_DIR, local=host_dir)

            for temp_file in temp_files:
                host_path = os.path.join(host_dir, temp_file.base_name)
                with open(host_path, 'rb') as host_file:
                    host_md5 = compute_md5(host_file.read())
                    self.assertEqual(host_md5, temp_file.checksum)
        finally:
            self.device.shell(['rm', '-rf', self.DEVICE_TEMP_DIR])
            if host_dir is not None:
                shutil.rmtree(host_dir)

    def test_sync(self):
        """Sync a randomly generated directory of files to specified device."""
        base_dir = tempfile.mkdtemp()
        try:
            # Create mirror device directory hierarchy within base_dir.
            full_dir_path = base_dir + self.DEVICE_TEMP_DIR
            os.makedirs(full_dir_path)

            # Create 32 random files within the host mirror.
            temp_files = make_random_host_files(in_dir=full_dir_path,
                                                num_files=32)

            # Clean up any trash on the device.
            device = adb.get_device(product=base_dir)
            device.shell(['rm', '-rf', self.DEVICE_TEMP_DIR])

            device.sync('data')

            # Confirm that every file on the device mirrors that on the host.
            for temp_file in temp_files:
                device_full_path = posixpath.join(
                    self.DEVICE_TEMP_DIR, temp_file.base_name)
                dev_md5, _ = device.shell(
                    [get_md5_prog(self.device), device_full_path]).split()
                self.assertEqual(temp_file.checksum, dev_md5)
        finally:
            self.device.shell(['rm', '-rf', self.DEVICE_TEMP_DIR])
            shutil.rmtree(base_dir + self.DEVICE_TEMP_DIR)


    def test_unicode_paths(self):
        """Ensure that we can support non-ASCII paths, even on Windows."""
        name = u'로보카 폴리'.encode('utf-8')

        ## push.
        tf = tempfile.NamedTemporaryFile('wb', suffix=name)
        self.device.push(tf.name, '/data/local/tmp/adb-test-{}'.format(name))
        self.device.shell(['rm', '-f', '/data/local/tmp/adb-test-*'])

        # pull.
        cmd = ['touch', '"/data/local/tmp/adb-test-{}"'.format(name)]
        self.device.shell(cmd)

        tf = tempfile.NamedTemporaryFile('wb', suffix=name)
        self.device.pull('/data/local/tmp/adb-test-{}'.format(name), tf.name)


def main():
    random.seed(0)
    if len(adb.get_devices()) > 0:
        suite = unittest.TestLoader().loadTestsFromName(__name__)
        unittest.TextTestRunner(verbosity=3).run(suite)
    else:
        print('Test suite must be run with attached devices')


if __name__ == '__main__':
    main()
