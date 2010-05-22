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

import android.accounts.Account;
import android.text.TextUtils;
import android.util.Base64;
import android.util.CharsetUtils;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * <p>
 * The {@link VCardInterpreter} implementation which enables {@link VCardEntryHandler} objects
 * to easily handle each vCard entry.
 * </p>
 * <p>
 * This class understand details inside vCard and translates it to {@link VCardEntry}.
 * Then the class throw it to {@link VCardEntryHandler} registered via
 * {@link #addEntryHandler(VCardEntryHandler)}, so that all those registered objects
 * are able to handle the {@link VCardEntry} object.
 * </p>
 * <p>
 * If you want to know the detail inside vCard, it would be better to implement
 * {@link VCardInterpreter} directly, instead of relying on this class and
 * {@link VCardEntry} created by the object.
 * </p>
 */
public class VCardEntryConstructor implements VCardInterpreter {
    private static String LOG_TAG = "VCardEntryConstructor";

    private VCardEntry.Property mCurrentProperty = new VCardEntry.Property();
    private VCardEntry mCurrentVCardEntry;
    private String mParamType;
    
    // The charset using which {@link VCardInterpreter} parses the text.
    // Each String is first decoded into binary stream with this charset, and encoded back
    // to "target charset", which may be explicitly specified by the vCard with "CHARSET"
    // property or implicitly mentioned by its version (e.g. vCard 3.0 recommends UTF-8).
    private final String mSourceCharset;

    private final boolean mStrictLineBreaking;
    private final int mVCardType;
    private final Account mAccount;
    
    // For measuring performance.
    private long mTimePushIntoContentResolver;

    private final List<VCardEntryHandler> mEntryHandlers = new ArrayList<VCardEntryHandler>();

    public VCardEntryConstructor() {
        this(VCardConfig.VCARD_TYPE_V21_GENERIC, null);
    }

    public VCardEntryConstructor(final int vcardType) {
        this(vcardType, null, null, false);
    }

    public VCardEntryConstructor(final int vcardType, final Account account) {
        this(vcardType, account, null, false);
    }

    public VCardEntryConstructor(final int vcardType, final Account account,
            final String inputCharset) {
        this(vcardType, account, inputCharset, false);
    }

    /**
     * @hide Just for testing.
     */
    public VCardEntryConstructor(final int vcardType, final Account account,
            final String inputCharset, final boolean strictLineBreakParsing) {
        if (inputCharset != null) {
            mSourceCharset = inputCharset;
        } else {
            mSourceCharset = VCardConfig.DEFAULT_INTERMEDIATE_CHARSET;
        }
        mStrictLineBreaking = strictLineBreakParsing;
        mVCardType = vcardType;
        mAccount = account;
    }

    public void addEntryHandler(VCardEntryHandler entryHandler) {
        mEntryHandlers.add(entryHandler);
    }
    
    public void start() {
        for (VCardEntryHandler entryHandler : mEntryHandlers) {
            entryHandler.onStart();
        }
    }

    public void end() {
        for (VCardEntryHandler entryHandler : mEntryHandlers) {
            entryHandler.onEnd();
        }
    }

    public void clear() {
        mCurrentVCardEntry = null;
        mCurrentProperty = new VCardEntry.Property();
    }

    public void startEntry() {
        if (mCurrentVCardEntry != null) {
            Log.e(LOG_TAG, "Nested VCard code is not supported now.");
        }
        mCurrentVCardEntry = new VCardEntry(mVCardType, mAccount);
    }

    public void endEntry() {
        mCurrentVCardEntry.consolidateFields();
        for (VCardEntryHandler entryHandler : mEntryHandlers) {
            entryHandler.onEntryCreated(mCurrentVCardEntry);
        }
        mCurrentVCardEntry = null;
    }

    public void startProperty() {
        mCurrentProperty.clear();
    }

    public void endProperty() {
        mCurrentVCardEntry.addProperty(mCurrentProperty);
    }
    
    public void propertyName(String name) {
        mCurrentProperty.setPropertyName(name);
    }

    public void propertyGroup(String group) {
    }

    public void propertyParamType(String type) {
        if (mParamType != null) {
            Log.e(LOG_TAG, "propertyParamType() is called more than once " +
                    "before propertyParamValue() is called");
        }
        mParamType = type;
    }

    public void propertyParamValue(String value) {
        if (mParamType == null) {
            // From vCard 2.1 specification. vCard 3.0 formally does not allow this case.
            mParamType = "TYPE";
        }
        mCurrentProperty.addParameter(mParamType, value);
        mParamType = null;
    }

    private static String encodeToSystemCharset(String originalString,
            String sourceCharset, String targetCharset) {
        if (sourceCharset.equalsIgnoreCase(targetCharset)) {
            return originalString;
        }
        final Charset charset = Charset.forName(sourceCharset);
        final ByteBuffer byteBuffer = charset.encode(originalString);
        // byteBuffer.array() "may" return byte array which is larger than
        // byteBuffer.remaining(). Here, we keep on the safe side.
        final byte[] bytes = new byte[byteBuffer.remaining()];
        byteBuffer.get(bytes);
        try {
            String ret = new String(bytes, targetCharset);
            return ret;
        } catch (UnsupportedEncodingException e) {
            Log.e(LOG_TAG, "Failed to encode: charset=" + targetCharset);
            return null;
        }
    }

    private String handleOneValue(String value,
            String sourceCharset, String targetCharset, String encoding) {
        if (value == null) {
            Log.w(LOG_TAG, "Null is given.");
            value = "";
        }

        if (encoding != null) {
            if (encoding.equals("BASE64") || encoding.equals("B")) {
                mCurrentProperty.setPropertyBytes(Base64.decode(value.getBytes(), Base64.DEFAULT));
                return value;
            } else if (encoding.equals("QUOTED-PRINTABLE")) {
                return VCardUtils.parseQuotedPrintable(
                        value, mStrictLineBreaking, sourceCharset, targetCharset);
            }
            Log.w(LOG_TAG, "Unknown encoding. Fall back to default.");
        }

        // Just translate the charset of a given String from inputCharset to a system one. 
        return encodeToSystemCharset(value, sourceCharset, targetCharset);
    }
    
    public void propertyValues(List<String> values) {
        if (values == null || values.isEmpty()) {
            return;
        }

        final Collection<String> charsetCollection = mCurrentProperty.getParameters("CHARSET");
        final Collection<String> encodingCollection = mCurrentProperty.getParameters("ENCODING");
        final String encoding =
            ((encodingCollection != null) ? encodingCollection.iterator().next() : null);
        String targetCharset = CharsetUtils.nameForDefaultVendor(
                ((charsetCollection != null) ? charsetCollection.iterator().next() : null));
        if (TextUtils.isEmpty(targetCharset)) {
            targetCharset = VCardConfig.DEFAULT_IMPORT_CHARSET;
        }

        for (final String value : values) {
            mCurrentProperty.addToPropertyValueList(
                    handleOneValue(value, mSourceCharset, targetCharset, encoding));
        }
    }

    /**
     * @hide
     */
    public void showPerformanceInfo() {
        Log.d(LOG_TAG, "time for insert ContactStruct to database: " + 
                mTimePushIntoContentResolver + " ms");
    }
}
