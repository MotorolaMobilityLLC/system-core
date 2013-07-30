/*
 * Copyright (C) 2009 The Android Open Source Project
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
package com.android.vcard;

import android.text.TextUtils;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * <p>
 * The class which tries to detects the source of a vCard file from its contents.
 * </p>
 * <p>
 * The specification of vCard (including both 2.1 and 3.0) is not so strict as to
 * guess its format just by reading beginning few lines (usually we can, but in
 * some most pessimistic case, we cannot until at almost the end of the file).
 * Also we cannot store all vCard entries in memory, while there's no specification
 * how big the vCard entry would become after the parse.
 * </p>
 * <p>
 * This class is usually used for the "first scan", in which we can understand which vCard
 * version is used (and how many entries exist in a file).
 * </p>
 */
public class VCardSourceDetector implements VCardInterpreter {
    private static Set<String> APPLE_SIGNS = new HashSet<String>(Arrays.asList(
            "X-PHONETIC-FIRST-NAME", "X-PHONETIC-MIDDLE-NAME", "X-PHONETIC-LAST-NAME",
            "X-ABADR", "X-ABUID"));
    
    private static Set<String> JAPANESE_MOBILE_PHONE_SIGNS = new HashSet<String>(Arrays.asList(
            "X-GNO", "X-GN", "X-REDUCTION"));
    
    private static Set<String> WINDOWS_MOBILE_PHONE_SIGNS = new HashSet<String>(Arrays.asList(
            "X-MICROSOFT-ASST_TEL", "X-MICROSOFT-ASSISTANT", "X-MICROSOFT-OFFICELOC"));
    
    // Note: these signes appears before the signs of the other type (e.g. "X-GN").
    // In other words, Japanese FOMA mobile phones are detected as FOMA, not JAPANESE_MOBILE_PHONES.
    private static Set<String> FOMA_SIGNS = new HashSet<String>(Arrays.asList(
            "X-SD-VERN", "X-SD-FORMAT_VER", "X-SD-CATEGORIES", "X-SD-CLASS", "X-SD-DCREATED",
            "X-SD-DESCRIPTION"));
    private static String TYPE_FOMA_CHARSET_SIGN = "X-SD-CHAR_CODE";


    // TODO: Should replace this with types in VCardConfig
    private static final int PARSE_TYPE_UNKNOWN = 0;
    // For Apple's software, which does not mean this type is effective for all its products.
    // We confirmed they usually use UTF-8, but not sure about vCard type.
    private static final int PARSE_TYPE_APPLE = 1;
    // For Japanese mobile phones, which are usually using Shift_JIS as a charset.
    private static final int PARSE_TYPE_MOBILE_PHONE_JP = 2;
    // For some of mobile phones released from DoCoMo, which use nested vCard. 
    private static final int PARSE_TYPE_DOCOMO_TORELATE_NEST = 3;
    // For Japanese Windows Mobel phones. It's version is supposed to be 6.5.
    private static final int PARSE_TYPE_WINDOWS_MOBILE_V65_JP = 4;

    private int mParseType = 0;  // Not sure.

    // Some mobile phones (like FOMA) tells us the charset of the data.
    private boolean mNeedParseSpecifiedCharset;
    private String mSpecifiedCharset;
    
    public void start() {
    }
    
    public void end() {
    }

    public void startEntry() {
    }    

    public void startProperty() {
        mNeedParseSpecifiedCharset = false;
    }
    
    public void endProperty() {
    }

    public void endEntry() {
    }

    public void propertyGroup(String group) {
    }
    
    public void propertyName(String name) {
        if (name.equalsIgnoreCase(TYPE_FOMA_CHARSET_SIGN)) {
            mParseType = PARSE_TYPE_DOCOMO_TORELATE_NEST;
            // Probably Shift_JIS is used, but we should double confirm.
            mNeedParseSpecifiedCharset = true;
            return;
        }
        if (mParseType != PARSE_TYPE_UNKNOWN) {
            return;
        }
        if (WINDOWS_MOBILE_PHONE_SIGNS.contains(name)) {
            mParseType = PARSE_TYPE_WINDOWS_MOBILE_V65_JP;
        } else if (FOMA_SIGNS.contains(name)) {
            mParseType = PARSE_TYPE_DOCOMO_TORELATE_NEST;
        } else if (JAPANESE_MOBILE_PHONE_SIGNS.contains(name)) {
            mParseType = PARSE_TYPE_MOBILE_PHONE_JP;
        } else if (APPLE_SIGNS.contains(name)) {
            mParseType = PARSE_TYPE_APPLE;
        }
    }

    public void propertyParamType(String type) {
    }

    public void propertyParamValue(String value) {
    }

    public void propertyValues(List<String> values) {
        if (mNeedParseSpecifiedCharset && values.size() > 0) {
            mSpecifiedCharset = values.get(0);
        }
    }

    /**
     * @return The available type can be used with vCard parser. You probably need to
     * use {{@link #getEstimatedCharset()} to understand the charset to be used.
     */
    public int getEstimatedType() {
        switch (mParseType) {
            case PARSE_TYPE_DOCOMO_TORELATE_NEST:
                return VCardConfig.VCARD_TYPE_DOCOMO | VCardConfig.FLAG_TORELATE_NEST;
            case PARSE_TYPE_MOBILE_PHONE_JP:
                return VCardConfig.VCARD_TYPE_V21_JAPANESE_MOBILE;
            case PARSE_TYPE_APPLE:
            case PARSE_TYPE_WINDOWS_MOBILE_V65_JP:
            default:
                return VCardConfig.VCARD_TYPE_UNKNOWN;
        }
    }

    /**
     * <p>
     * Returns charset String guessed from the source's properties.
     * This method must be called after parsing target file(s).
     * </p>
     * @return Charset String. Null is returned if guessing the source fails.
     */
    public String getEstimatedCharset() {
        if (TextUtils.isEmpty(mSpecifiedCharset)) {
            return mSpecifiedCharset;
        }
        switch (mParseType) {
            case PARSE_TYPE_WINDOWS_MOBILE_V65_JP:
            case PARSE_TYPE_DOCOMO_TORELATE_NEST:
            case PARSE_TYPE_MOBILE_PHONE_JP:
                return "SHIFT_JIS";
            case PARSE_TYPE_APPLE:
                return "UTF-8";
            default:
                return null;
        }
    }
}
