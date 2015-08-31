/*
 * Copyright (C) 2007 The Android Open Source Project
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

#define TRACE_TAG TRACE_USB

#include "sysdeps.h"

#include <winsock2.h>  // winsock.h *must* be included before windows.h.
#include <adb_api.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <usb100.h>
#include <windows.h>
#include <winerror.h>

#include "adb.h"
#include "transport.h"

/** Structure usb_handle describes our connection to the usb device via
  AdbWinApi.dll. This structure is returned from usb_open() routine and
  is expected in each subsequent call that is accessing the device.

  Most members are protected by usb_lock, except for adb_{read,write}_pipe which
  rely on AdbWinApi.dll's handle validation and AdbCloseHandle(endpoint)'s
  ability to break a thread out of pipe IO.
*/
struct usb_handle {
  /// Previous entry in the list of opened usb handles
  usb_handle *prev;

  /// Next entry in the list of opened usb handles
  usb_handle *next;

  /// Handle to USB interface
  ADBAPIHANDLE  adb_interface;

  /// Handle to USB read pipe (endpoint)
  ADBAPIHANDLE  adb_read_pipe;

  /// Handle to USB write pipe (endpoint)
  ADBAPIHANDLE  adb_write_pipe;

  /// Interface name
  char*         interface_name;

  /// Mask for determining when to use zero length packets
  unsigned zero_mask;
};

/// Class ID assigned to the device by androidusb.sys
static const GUID usb_class_id = ANDROID_USB_CLASS_ID;

/// List of opened usb handles
static usb_handle handle_list = {
  .prev = &handle_list,
  .next = &handle_list,
};

/// Locker for the list of opened usb handles
ADB_MUTEX_DEFINE( usb_lock );

/// Checks if there is opened usb handle in handle_list for this device.
int known_device(const char* dev_name);

/// Checks if there is opened usb handle in handle_list for this device.
/// usb_lock mutex must be held before calling this routine.
int known_device_locked(const char* dev_name);

/// Registers opened usb handle (adds it to handle_list).
int register_new_device(usb_handle* handle);

/// Checks if interface (device) matches certain criteria
int recognized_device(usb_handle* handle);

/// Enumerates present and available interfaces (devices), opens new ones and
/// registers usb transport for them.
void find_devices();

/// Kicks all USB devices
static void kick_devices();

/// Entry point for thread that polls (every second) for new usb interfaces.
/// This routine calls find_devices in infinite loop.
void* device_poll_thread(void* unused);

/// Initializes this module
void usb_init();

/// Opens usb interface (device) by interface (device) name.
usb_handle* do_usb_open(const wchar_t* interface_name);

/// Writes data to the opened usb handle
int usb_write(usb_handle* handle, const void* data, int len);

/// Reads data using the opened usb handle
int usb_read(usb_handle *handle, void* data, int len);

/// Cleans up opened usb handle
void usb_cleanup_handle(usb_handle* handle);

/// Cleans up (but don't close) opened usb handle
void usb_kick(usb_handle* handle);

/// Closes opened usb handle
int usb_close(usb_handle* handle);

int known_device_locked(const char* dev_name) {
  usb_handle* usb;

  if (NULL != dev_name) {
    // Iterate through the list looking for the name match.
    for(usb = handle_list.next; usb != &handle_list; usb = usb->next) {
      // In Windows names are not case sensetive!
      if((NULL != usb->interface_name) &&
         (0 == stricmp(usb->interface_name, dev_name))) {
        return 1;
      }
    }
  }

  return 0;
}

int known_device(const char* dev_name) {
  int ret = 0;

  if (NULL != dev_name) {
    adb_mutex_lock(&usb_lock);
    ret = known_device_locked(dev_name);
    adb_mutex_unlock(&usb_lock);
  }

  return ret;
}

int register_new_device(usb_handle* handle) {
  if (NULL == handle)
    return 0;

  adb_mutex_lock(&usb_lock);

  // Check if device is already in the list
  if (known_device_locked(handle->interface_name)) {
    adb_mutex_unlock(&usb_lock);
    return 0;
  }

  // Not in the list. Add this handle to the list.
  handle->next = &handle_list;
  handle->prev = handle_list.prev;
  handle->prev->next = handle;
  handle->next->prev = handle;

  adb_mutex_unlock(&usb_lock);

  return 1;
}

void* device_poll_thread(void* unused) {
  adb_thread_setname("Device Poll");
  D("Created device thread\n");

  while(1) {
    find_devices();
    adb_sleep_ms(1000);
  }

  return NULL;
}

static LRESULT CALLBACK _power_window_proc(HWND hwnd, UINT uMsg, WPARAM wParam,
                                           LPARAM lParam) {
  switch (uMsg) {
  case WM_POWERBROADCAST:
    switch (wParam) {
    case PBT_APMRESUMEAUTOMATIC:
      // Resuming from sleep or hibernation, so kick all existing USB devices
      // and then allow the device_poll_thread to redetect USB devices from
      // scratch. If we don't do this, existing USB devices will never respond
      // to us because they'll be waiting for the connect/auth handshake.
      D("Received (WM_POWERBROADCAST, PBT_APMRESUMEAUTOMATIC) notification, "
        "so kicking all USB devices\n");
      kick_devices();
      return TRUE;
    }
  }
  return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

static void* _power_notification_thread(void* unused) {
  // This uses a thread with its own window message pump to get power
  // notifications. If adb runs from a non-interactive service account, this
  // might not work (not sure). If that happens to not work, we could use
  // heavyweight WMI APIs to get power notifications. But for the common case
  // of a developer's interactive session, a window message pump is more
  // appropriate.
  D("Created power notification thread\n");
  adb_thread_setname("Power Notifier");

  // Window class names are process specific.
  static const WCHAR kPowerNotificationWindowClassName[] =
    L"PowerNotificationWindow";

  // Get the HINSTANCE corresponding to the module that _power_window_proc
  // is in (the main module).
  const HINSTANCE instance = GetModuleHandleW(NULL);
  if (!instance) {
    // This is such a common API call that this should never fail.
    fatal("GetModuleHandleW failed: %s",
          SystemErrorCodeToString(GetLastError()).c_str());
  }

  WNDCLASSEXW wndclass;
  memset(&wndclass, 0, sizeof(wndclass));
  wndclass.cbSize = sizeof(wndclass);
  wndclass.lpfnWndProc = _power_window_proc;
  wndclass.hInstance = instance;
  wndclass.lpszClassName = kPowerNotificationWindowClassName;
  if (!RegisterClassExW(&wndclass)) {
    fatal("RegisterClassExW failed: %s",
          SystemErrorCodeToString(GetLastError()).c_str());
  }

  if (!CreateWindowExW(WS_EX_NOACTIVATE, kPowerNotificationWindowClassName,
                       L"ADB Power Notification Window", WS_POPUP, 0, 0, 0, 0,
                       NULL, NULL, instance, NULL)) {
    fatal("CreateWindowExW failed: %s",
          SystemErrorCodeToString(GetLastError()).c_str());
  }

  MSG msg;
  while (GetMessageW(&msg, NULL, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }

  // GetMessageW() will return false if a quit message is posted. We don't
  // do that, but it might be possible for that to occur when logging off or
  // shutting down. Not a big deal since the whole process will be going away
  // soon anyway.
  D("Power notification thread exiting\n");

  return NULL;
}

void usb_init() {
  if (!adb_thread_create(device_poll_thread, nullptr)) {
    fatal_errno("cannot create device poll thread");
  }
  if (!adb_thread_create(_power_notification_thread, nullptr)) {
    fatal_errno("cannot create power notification thread");
  }
}

usb_handle* do_usb_open(const wchar_t* interface_name) {
  unsigned long name_len = 0;

  // Allocate our handle
  usb_handle* ret = (usb_handle*)calloc(1, sizeof(usb_handle));
  if (NULL == ret) {
    D("Could not allocate %u bytes for usb_handle: %s\n", sizeof(usb_handle),
      strerror(errno));
    goto fail;
  }

  // Set linkers back to the handle
  ret->next = ret;
  ret->prev = ret;

  // Create interface.
  ret->adb_interface = AdbCreateInterfaceByName(interface_name);
  if (NULL == ret->adb_interface) {
    D("AdbCreateInterfaceByName failed: %s\n",
      SystemErrorCodeToString(GetLastError()).c_str());
    goto fail;
  }

  // Open read pipe (endpoint)
  ret->adb_read_pipe =
    AdbOpenDefaultBulkReadEndpoint(ret->adb_interface,
                                   AdbOpenAccessTypeReadWrite,
                                   AdbOpenSharingModeReadWrite);
  if (NULL == ret->adb_read_pipe) {
    D("AdbOpenDefaultBulkReadEndpoint failed: %s\n",
      SystemErrorCodeToString(GetLastError()).c_str());
    goto fail;
  }

  // Open write pipe (endpoint)
  ret->adb_write_pipe =
    AdbOpenDefaultBulkWriteEndpoint(ret->adb_interface,
                                    AdbOpenAccessTypeReadWrite,
                                    AdbOpenSharingModeReadWrite);
  if (NULL == ret->adb_write_pipe) {
    D("AdbOpenDefaultBulkWriteEndpoint failed: %s\n",
      SystemErrorCodeToString(GetLastError()).c_str());
    goto fail;
  }

  // Save interface name
  // First get expected name length
  AdbGetInterfaceName(ret->adb_interface,
                      NULL,
                      &name_len,
                      true);
  if (0 == name_len) {
    D("AdbGetInterfaceName returned name length of zero: %s\n",
      SystemErrorCodeToString(GetLastError()).c_str());
    goto fail;
  }

  ret->interface_name = (char*)malloc(name_len);
  if (NULL == ret->interface_name) {
    D("Could not allocate %lu bytes for interface_name: %s\n", name_len,
      strerror(errno));
    goto fail;
  }

  // Now save the name
  if (!AdbGetInterfaceName(ret->adb_interface,
                           ret->interface_name,
                           &name_len,
                           true)) {
    D("AdbGetInterfaceName failed: %s\n",
      SystemErrorCodeToString(GetLastError()).c_str());
    goto fail;
  }

  // We're done at this point
  return ret;

fail:
  if (NULL != ret) {
    usb_cleanup_handle(ret);
    free(ret);
  }

  return NULL;
}

int usb_write(usb_handle* handle, const void* data, int len) {
  unsigned long time_out = 5000;
  unsigned long written = 0;
  int err = 0;

  D("usb_write %d\n", len);
  if (NULL == handle) {
    D("usb_write was passed NULL handle\n");
    err = EINVAL;
    goto fail;
  }

  // Perform write
  if (!AdbWriteEndpointSync(handle->adb_write_pipe,
                            (void*)data,
                            (unsigned long)len,
                            &written,
                            time_out)) {
    D("AdbWriteEndpointSync failed: %s\n",
      SystemErrorCodeToString(GetLastError()).c_str());
    err = EIO;
    goto fail;
  }

  // Make sure that we've written what we were asked to write
  D("usb_write got: %ld, expected: %d\n", written, len);
  if (written != (unsigned long)len) {
    // If this occurs, this code should be changed to repeatedly call
    // AdbWriteEndpointSync() until all bytes are written.
    D("AdbWriteEndpointSync was supposed to write %d, but only wrote %ld\n",
      len, written);
    err = EIO;
    goto fail;
  }

  if (handle->zero_mask && (len & handle->zero_mask) == 0) {
    // Send a zero length packet
    if (!AdbWriteEndpointSync(handle->adb_write_pipe,
                              (void*)data,
                              0,
                              &written,
                              time_out)) {
      D("AdbWriteEndpointSync of zero length packet failed: %s\n",
        SystemErrorCodeToString(GetLastError()).c_str());
      err = EIO;
      goto fail;
    }
  }

  return 0;

fail:
  // Any failure should cause us to kick the device instead of leaving it a
  // zombie state with potential to hang.
  if (NULL != handle) {
    D("Kicking device due to error in usb_write\n");
    usb_kick(handle);
  }

  D("usb_write failed\n");
  errno = err;
  return -1;
}

int usb_read(usb_handle *handle, void* data, int len) {
  unsigned long time_out = 0;
  unsigned long read = 0;
  int err = 0;

  D("usb_read %d\n", len);
  if (NULL == handle) {
    D("usb_read was passed NULL handle\n");
    err = EINVAL;
    goto fail;
  }

  while (len > 0) {
    if (!AdbReadEndpointSync(handle->adb_read_pipe, data, len, &read,
                             time_out)) {
      D("AdbReadEndpointSync failed: %s\n",
        SystemErrorCodeToString(GetLastError()).c_str());
      err = EIO;
      goto fail;
    }
    D("usb_read got: %ld, expected: %d\n", read, len);

    data = (char *)data + read;
    len -= read;
  }

  return 0;

fail:
  // Any failure should cause us to kick the device instead of leaving it a
  // zombie state with potential to hang.
  if (NULL != handle) {
    D("Kicking device due to error in usb_read\n");
    usb_kick(handle);
  }

  D("usb_read failed\n");
  errno = err;
  return -1;
}

// Wrapper around AdbCloseHandle() that logs diagnostics.
static void _adb_close_handle(ADBAPIHANDLE adb_handle) {
  if (!AdbCloseHandle(adb_handle)) {
    D("AdbCloseHandle(%p) failed: %s\n", adb_handle,
      SystemErrorCodeToString(GetLastError()).c_str());
  }
}

void usb_cleanup_handle(usb_handle* handle) {
  D("usb_cleanup_handle\n");
  if (NULL != handle) {
    if (NULL != handle->interface_name)
      free(handle->interface_name);
    // AdbCloseHandle(pipe) will break any threads out of pending IO calls and
    // wait until the pipe no longer uses the interface. Then we can
    // AdbCloseHandle() the interface.
    if (NULL != handle->adb_write_pipe)
      _adb_close_handle(handle->adb_write_pipe);
    if (NULL != handle->adb_read_pipe)
      _adb_close_handle(handle->adb_read_pipe);
    if (NULL != handle->adb_interface)
      _adb_close_handle(handle->adb_interface);

    handle->interface_name = NULL;
    handle->adb_write_pipe = NULL;
    handle->adb_read_pipe = NULL;
    handle->adb_interface = NULL;
  }
}

static void usb_kick_locked(usb_handle* handle) {
  // The reason the lock must be acquired before calling this function is in
  // case multiple threads are trying to kick the same device at the same time.
  usb_cleanup_handle(handle);
}

void usb_kick(usb_handle* handle) {
  D("usb_kick\n");
  if (NULL != handle) {
    adb_mutex_lock(&usb_lock);

    usb_kick_locked(handle);

    adb_mutex_unlock(&usb_lock);
  } else {
    errno = EINVAL;
  }
}

int usb_close(usb_handle* handle) {
  D("usb_close\n");

  if (NULL != handle) {
    // Remove handle from the list
    adb_mutex_lock(&usb_lock);

    if ((handle->next != handle) && (handle->prev != handle)) {
      handle->next->prev = handle->prev;
      handle->prev->next = handle->next;
      handle->prev = handle;
      handle->next = handle;
    }

    adb_mutex_unlock(&usb_lock);

    // Cleanup handle
    usb_cleanup_handle(handle);
    free(handle);
  }

  return 0;
}

int recognized_device(usb_handle* handle) {
  if (NULL == handle)
    return 0;

  // Check vendor and product id first
  USB_DEVICE_DESCRIPTOR device_desc;

  if (!AdbGetUsbDeviceDescriptor(handle->adb_interface,
                                 &device_desc)) {
    D("AdbGetUsbDeviceDescriptor failed: %s\n",
      SystemErrorCodeToString(GetLastError()).c_str());
    return 0;
  }

  // Then check interface properties
  USB_INTERFACE_DESCRIPTOR interf_desc;

  if (!AdbGetUsbInterfaceDescriptor(handle->adb_interface,
                                    &interf_desc)) {
    D("AdbGetUsbInterfaceDescriptor failed: %s\n",
      SystemErrorCodeToString(GetLastError()).c_str());
    return 0;
  }

  // Must have two endpoints
  if (2 != interf_desc.bNumEndpoints) {
    return 0;
  }

  if (is_adb_interface(device_desc.idVendor, device_desc.idProduct,
      interf_desc.bInterfaceClass, interf_desc.bInterfaceSubClass, interf_desc.bInterfaceProtocol)) {

    if(interf_desc.bInterfaceProtocol == 0x01) {
      AdbEndpointInformation endpoint_info;
      // assuming zero is a valid bulk endpoint ID
      if (AdbGetEndpointInformation(handle->adb_interface, 0, &endpoint_info)) {
        handle->zero_mask = endpoint_info.max_packet_size - 1;
        D("device zero_mask: 0x%x\n", handle->zero_mask);
      } else {
        D("AdbGetEndpointInformation failed: %s\n",
          SystemErrorCodeToString(GetLastError()).c_str());
      }
    }

    return 1;
  }

  return 0;
}

void find_devices() {
        usb_handle* handle = NULL;
  char entry_buffer[2048];
  char interf_name[2048];
  AdbInterfaceInfo* next_interface = (AdbInterfaceInfo*)(&entry_buffer[0]);
  unsigned long entry_buffer_size = sizeof(entry_buffer);
  char* copy_name;

  // Enumerate all present and active interfaces.
  ADBAPIHANDLE enum_handle =
    AdbEnumInterfaces(usb_class_id, true, true, true);

  if (NULL == enum_handle) {
    D("AdbEnumInterfaces failed: %s\n",
      SystemErrorCodeToString(GetLastError()).c_str());
    return;
  }

  while (AdbNextInterface(enum_handle, next_interface, &entry_buffer_size)) {
    // TODO: FIXME - temp hack converting wchar_t into char.
    // It would be better to change AdbNextInterface so it will return
    // interface name as single char string.
    const wchar_t* wchar_name = next_interface->device_name;
    for(copy_name = interf_name;
        L'\0' != *wchar_name;
        wchar_name++, copy_name++) {
      *copy_name = (char)(*wchar_name);
    }
    *copy_name = '\0';

    // Lets see if we already have this device in the list
    if (!known_device(interf_name)) {
      // This seems to be a new device. Open it!
        handle = do_usb_open(next_interface->device_name);
        if (NULL != handle) {
        // Lets see if this interface (device) belongs to us
        if (recognized_device(handle)) {
          D("adding a new device %s\n", interf_name);
          char serial_number[512];
          unsigned long serial_number_len = sizeof(serial_number);
          if (AdbGetSerialNumber(handle->adb_interface,
                                serial_number,
                                &serial_number_len,
                                true)) {
            // Lets make sure that we don't duplicate this device
            if (register_new_device(handle)) {
              register_usb_transport(handle, serial_number, NULL, 1);
            } else {
              D("register_new_device failed for %s\n", interf_name);
              usb_cleanup_handle(handle);
              free(handle);
            }
          } else {
            D("cannot get serial number: %s\n",
              SystemErrorCodeToString(GetLastError()).c_str());
            usb_cleanup_handle(handle);
            free(handle);
          }
        } else {
          usb_cleanup_handle(handle);
          free(handle);
        }
      }
    }

    entry_buffer_size = sizeof(entry_buffer);
  }

  if (GetLastError() != ERROR_NO_MORE_ITEMS) {
    // Only ERROR_NO_MORE_ITEMS is expected at the end of enumeration.
    D("AdbNextInterface failed: %s\n",
      SystemErrorCodeToString(GetLastError()).c_str());
  }

  _adb_close_handle(enum_handle);
}

static void kick_devices() {
  // Need to acquire lock to safely walk the list which might be modified
  // by another thread.
  adb_mutex_lock(&usb_lock);
  for (usb_handle* usb = handle_list.next; usb != &handle_list; usb = usb->next) {
    usb_kick_locked(usb);
  }
  adb_mutex_unlock(&usb_lock);
}
