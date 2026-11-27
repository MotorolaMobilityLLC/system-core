/*
 * Copyright (C) 2026 The Android Open Source Project
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

package android.os.cts.rlimit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import android.os.Process;
import androidx.test.runner.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class RlimitTest {
    private static final long NOFILE_CUR_DEFAULT = 32768;
    private static final long NOFILE_MAX_64BIT = 524288;
    private static final long NOFILE_MAX_32BIT = 32768;

    static {
        System.loadLibrary("ctsrlimit_jni");
    }

    private native long[] getNofileLimit();
    private native int setNofileLimit(long softLimit);

    @Test
    public void testRlimitNofile() {
        long[] limits = getNofileLimit();
        assertNotNull("getrlimit failed", limits);
        assertEquals(2, limits.length);
        assertEquals("Current limit (rlim_cur) should be " + NOFILE_CUR_DEFAULT,
                NOFILE_CUR_DEFAULT, limits[0]);

        long expectedMax = Process.is64Bit() ? NOFILE_MAX_64BIT : NOFILE_MAX_32BIT;
        assertEquals("Max limit (rlim_max) should be " + expectedMax, expectedMax, limits[1]);
    }

    @Test
    public void testSetRlimitNofile64Bit() {
        if (!Process.is64Bit()) {
            return;
        }

        long[] originalLimits = getNofileLimit();
        assertNotNull("getrlimit failed to get original limits", originalLimits);
        long originalSoftLimit = originalLimits[0];

        try {
            long newSoftLimit = NOFILE_MAX_64BIT;
            int result = setNofileLimit(newSoftLimit);
            assertEquals("setrlimit failed with errno: " + result, 0, result);

            long[] limits = getNofileLimit();
            assertNotNull("getrlimit failed", limits);
            assertEquals("New current limit (rlim_cur) should be " + newSoftLimit,
                    newSoftLimit, limits[0]);
        } finally {
            setNofileLimit(originalSoftLimit);
        }
    }
}
