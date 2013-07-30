/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.android.vcard.tests.test_utils;

import android.content.ContentResolver;
import android.content.Context;
import android.content.EntityIterator;
import android.net.Uri;
import android.test.AndroidTestCase;
import android.test.mock.MockContext;
import android.text.TextUtils;
import android.util.Log;

import com.android.vcard.VCardComposer;
import com.android.vcard.VCardConfig;
import com.android.vcard.VCardEntryConstructor;
import com.android.vcard.VCardInterpreter;
import com.android.vcard.VCardInterpreterCollection;
import com.android.vcard.VCardParser;
import com.android.vcard.VCardParser_V21;
import com.android.vcard.VCardParser_V30;
import com.android.vcard.exception.VCardException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.Arrays;

/**
 * <p>
 * The class lets users checks that given expected vCard data are same as given actual vCard data.
 * Able to verify both vCard importer/exporter.
 * </p>
 * <p>
 * First a user has to initialize the object by calling either
 * {@link #initForImportTest(int, int)} or {@link #initForExportTest(int)}.
 * "Round trip test" (import -> export -> import, or export -> import -> export) is not supported.
 * </p>
 */
public class VCardVerifier {
    private static final String LOG_TAG = "VCardVerifier";

    private static class CustomMockContext extends MockContext {
        final ContentResolver mResolver;
        public CustomMockContext(ContentResolver resolver) {
            mResolver = resolver;
        }

        @Override
        public ContentResolver getContentResolver() {
            return mResolver;
        }
    }

    private class VCardVerifierInternal implements VCardComposer.OneEntryHandler {
        public boolean onInit(Context context) {
            return true;
        }
        public boolean onEntryCreated(String vcard) {
            verifyOneVCard(vcard);
            return true;
        }
        public void onTerminate() {
        }
    }

    private final AndroidTestCase mTestCase;
    private final VCardVerifierInternal mVCardVerifierInternal;
    private int mVCardType;
    private boolean mIsV30;
    private boolean mIsDoCoMo;

    // Only one of them must be non-empty.
    private ExportTestResolver mExportTestResolver;
    private InputStream mInputStream;

    // To allow duplication, use list instead of set.
    // When null, we don't need to do the verification.
    private PropertyNodesVerifier mPropertyNodesVerifier;
    private LineVerifier mLineVerifier;
    private ContentValuesVerifier mContentValuesVerifier;
    private boolean mInitialized;
    private boolean mVerified = false;
    private String mCharset;

    // Called by VCardTestsBase
    public VCardVerifier(AndroidTestCase testCase) {
        mTestCase = testCase;
        mVCardVerifierInternal = new VCardVerifierInternal();
        mExportTestResolver = null;
        mInputStream = null;
        mInitialized = false;
        mVerified = false;
    }

    // Should be called at the beginning of each import test.
    public void initForImportTest(int vcardType, int resId) {
        if (mInitialized) {
            mTestCase.fail("Already initialized");
        }
        mVCardType = vcardType;
        mIsV30 = VCardConfig.isV30(vcardType);
        mIsDoCoMo = VCardConfig.isDoCoMo(vcardType);
        setInputResourceId(resId);
        mInitialized = true;
    }

    // Should be called at the beginning of each export test.
    public void initForExportTest(int vcardType) {
        initForExportTest(vcardType, "UTF-8");
    }

    public void initForExportTest(int vcardType, String charset) {
        if (mInitialized) {
            mTestCase.fail("Already initialized");
        }
        mExportTestResolver = new ExportTestResolver(mTestCase);
        mVCardType = vcardType;
        mIsV30 = VCardConfig.isV30(vcardType);
        mIsDoCoMo = VCardConfig.isDoCoMo(vcardType);
        mInitialized = true;
        if (TextUtils.isEmpty(charset)) {
            mCharset = "UTF-8";
        } else {
            mCharset = charset;
        }
    }

    private void setInputResourceId(int resId) {
        InputStream inputStream = mTestCase.getContext().getResources().openRawResource(resId);
        if (inputStream == null) {
            mTestCase.fail("Wrong resId: " + resId);
        }
        setInputStream(inputStream);
    }

    private void setInputStream(InputStream inputStream) {
        if (mExportTestResolver != null) {
            mTestCase.fail("addInputEntry() is called.");
        } else if (mInputStream != null) {
            mTestCase.fail("InputStream is already set");
        }
        mInputStream = inputStream;
    }

    public ContactEntry addInputEntry() {
        if (!mInitialized) {
            mTestCase.fail("Not initialized");
        }
        if (mInputStream != null) {
            mTestCase.fail("setInputStream is called");
        }
        return mExportTestResolver.addInputContactEntry();
    }

    public PropertyNodesVerifierElem addPropertyNodesVerifierElem() {
        if (!mInitialized) {
            mTestCase.fail("Not initialized");
        }
        if (mPropertyNodesVerifier == null) {
            mPropertyNodesVerifier = new PropertyNodesVerifier(mTestCase);
        }
        PropertyNodesVerifierElem elem =
                mPropertyNodesVerifier.addPropertyNodesVerifierElem();
        elem.addExpectedNodeWithOrder("VERSION", (mIsV30 ? "3.0" : "2.1"));

        return elem;
    }

    public PropertyNodesVerifierElem addPropertyNodesVerifierElemWithEmptyName() {
        if (!mInitialized) {
            mTestCase.fail("Not initialized");
        }
        PropertyNodesVerifierElem elem = addPropertyNodesVerifierElem();
        if (mIsV30) {
            elem.addExpectedNodeWithOrder("N", "").addExpectedNodeWithOrder("FN", "");
        } else if (mIsDoCoMo) {
            elem.addExpectedNodeWithOrder("N", "");
        }
        return elem;
    }

    public LineVerifierElem addLineVerifierElem() {
        if (!mInitialized) {
            mTestCase.fail("Not initialized");
        }
        if (mLineVerifier == null) {
            mLineVerifier = new LineVerifier(mTestCase, mVCardType);
        }
        return mLineVerifier.addLineVerifierElem();
    }

    public ContentValuesVerifierElem addContentValuesVerifierElem() {
        if (!mInitialized) {
            mTestCase.fail("Not initialized");
        }
        if (mContentValuesVerifier == null) {
            mContentValuesVerifier = new ContentValuesVerifier();
        }

        return mContentValuesVerifier.addElem(mTestCase);
    }

    private void verifyOneVCard(final String vcard) {
        Log.d(LOG_TAG, vcard);
        final VCardInterpreter builder;
        if (mContentValuesVerifier != null) {
            final VNodeBuilder vnodeBuilder = mPropertyNodesVerifier;
            final VCardEntryConstructor vcardDataBuilder =
                    new VCardEntryConstructor(mVCardType);
            vcardDataBuilder.addEntryHandler(mContentValuesVerifier);
            if (mPropertyNodesVerifier != null) {
                builder = new VCardInterpreterCollection(Arrays.asList(
                        mPropertyNodesVerifier, vcardDataBuilder));
            } else {
                builder = vnodeBuilder;
            }
        } else {
            if (mPropertyNodesVerifier != null) {
                builder = mPropertyNodesVerifier;
            } else {
                return;
            }
        }

        InputStream is = null;
        try {
            // Note: we must not specify charset toward vCard parsers. This code checks whether
            // those parsers are able to encode given binary without any extra information for
            // charset.
            final VCardParser parser = (mIsV30 ?
                    new VCardParser_V30(mVCardType) : new VCardParser_V21(mVCardType));
            is = new ByteArrayInputStream(vcard.getBytes(mCharset));
            parser.parse(is, builder);
        } catch (IOException e) {
            mTestCase.fail("Unexpected IOException: " + e.getMessage());
        } catch (VCardException e) {
            mTestCase.fail("Unexpected VCardException: " + e.getMessage());
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException e) {
                    mTestCase.fail("Unexpected IOException: " + e.getMessage());
                }
            }
        }
    }

    public void verify() {
        if (!mInitialized) {
            mTestCase.fail("Not initialized.");
        }
        if (mVerified) {
            mTestCase.fail("verify() was called twice.");
        }
        if (mInputStream != null) {
            try {
                verifyForImportTest();
            } catch (IOException e) {
                mTestCase.fail("IOException was thrown: " + e.getMessage());
            } catch (VCardException e) {
                mTestCase.fail("VCardException was thrown: " + e.getMessage());
            }
        } else if (mExportTestResolver != null){
            verifyForExportTest();
        } else {
            mTestCase.fail("No input is determined");
        }
        mVerified = true;
    }

    private void verifyForImportTest() throws IOException, VCardException {
        if (mLineVerifier != null) {
            mTestCase.fail("Not supported now.");
        }
        if (mContentValuesVerifier != null) {
            mContentValuesVerifier.verify(mInputStream, mVCardType);
        }
    }

    public static EntityIterator mockGetEntityIteratorMethod(
            final ContentResolver resolver,
            final Uri uri, final String selection,
            final String[] selectionArgs, final String sortOrder) {
        if (ExportTestResolver.class.equals(resolver.getClass())) {
            return ((ExportTestResolver)resolver).getProvider().queryEntities(
                    uri, selection, selectionArgs, sortOrder);
        }

        Log.e(LOG_TAG, "Unexpected provider given.");
        return null;
    }

    private Method getMockGetEntityIteratorMethod()
            throws SecurityException, NoSuchMethodException {
        return this.getClass().getMethod("mockGetEntityIteratorMethod",
                ContentResolver.class, Uri.class, String.class, String[].class, String.class);
    }

    private void verifyForExportTest() {
       final VCardComposer composer =
            new VCardComposer(new CustomMockContext(mExportTestResolver), mVCardType, mCharset);
        composer.addHandler(mLineVerifier);
        composer.addHandler(mVCardVerifierInternal);
        if (!composer.init(VCardComposer.CONTACTS_TEST_CONTENT_URI, null, null, null)) {
            mTestCase.fail("init() failed. Reason: " + composer.getErrorReason());
        }
        mTestCase.assertFalse(composer.isAfterLast());
        try {
            while (!composer.isAfterLast()) {
                try {
                    final Method mockGetEntityIteratorMethod = getMockGetEntityIteratorMethod();
                    mTestCase.assertNotNull(mockGetEntityIteratorMethod);
                    mTestCase.assertTrue(composer.createOneEntry(mockGetEntityIteratorMethod));
                } catch (Exception e) {
                    e.printStackTrace();
                    mTestCase.fail();
                }
            }
        } finally {
            composer.terminate();
        }
    }
}
