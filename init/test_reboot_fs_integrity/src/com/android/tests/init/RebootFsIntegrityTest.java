/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.tests.init;

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assume.assumeTrue;

import com.android.tradefed.device.ITestDevice;
import com.android.tradefed.log.LogUtil;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RunWith(DeviceJUnit4ClassRunner.class)
public class RebootFsIntegrityTest extends BaseHostJUnit4Test {
    private ITestDevice mDevice;

    private final List<String> pstorePaths = Arrays.asList(
            "/sys/fs/pstore/console-ramoops-0",
            "/sys/fs/pstore/console-ramoops"
    );
    private final List<String> mErrorPatterns = Arrays.asList(
            "Umount /data failed, try to use ioctl to shutdown",
            "umount timeout, last resort, kill all and try"
    );

    @Before
    public void setUp() throws Exception {
        mDevice = getDevice();
    }

    @Test
    public void rebootFsIntegrity() throws Exception {
        mDevice.reboot("Reboot to check logs in pstore");
        File pstoreFile = tryGetPstoreFile();
        assumeTrue("Skip test: pstore console log is not available", pstoreFile != null);
        assertThat(findUmountError(pstoreFile)).isEqualTo(null);
    }

    private File tryGetPstoreFile() throws Exception {
        for (String pathString : pstorePaths) {
            // possible kernel console output paths to check
            // Check if the current file exists
            if (mDevice.doesFileExist(pathString)) {
                return mDevice.pullFile(pathString);
            }
        }
        return null;
    }

    // Return umount error message if found in logFile, if there's no any error
    // found, return null.
    private String findUmountError(File logFile) {
        try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                for (String pattern : mErrorPatterns) {
                    if (line.contains(pattern)) {
                        return pattern;
                    }
                }
            }
        } catch (IOException e) {
            return "Error reading log file: " + e.getMessage();
        }
        return null;
    }
}
