use winapi::wincred::{CREDENTIALW, CRED_TYPE_GENERIC, CRED_PERSIST_LOCAL_MACHINE};
use winapi::minwindef::{FILETIME, TRUE, FALSE, DWORD, LPVOID};
use winapi::winerror::ERROR_NOT_FOUND;
use advapi32::{CredReadW, CredDeleteW, CredWriteW, CredFree};
use kernel32::GetLastError;

use std::ptr;
use std::slice;
use std::str;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use ::KeyringError;

pub struct Keyring<'a> {
    #[allow(dead_code)]
    attributes: Vec<(&'a str, &'a str)>,
    service: &'a str,
    username: &'a str,
}

struct CredentialBox {
    ptr: *mut CREDENTIALW,
}

impl Drop for CredentialBox {
    fn drop(&mut self) {
        unsafe {
            CredFree(self.ptr as LPVOID);
        }
    }
}

fn get_last_error() -> DWORD {
    unsafe { GetLastError() }
}

fn cred_read(key: &[u16]) -> Option<CredentialBox> {
    let mut credential = CredentialBox { ptr: ptr::null_mut() };

    unsafe {
        match CredReadW(key.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential.ptr) {
            FALSE => None,
            _ => Some(credential),
        }
    }
}

fn cred_write(credential: &mut CREDENTIALW) -> bool {
    unsafe { CredWriteW(credential, 0) == TRUE }
}

fn str_to_utf16(string: &str) -> Vec<u16> {
    OsStr::new(&string).encode_wide().chain(Some(0).into_iter()).collect::<Vec<_>>()
}


impl<'a> Keyring<'a> {
    pub fn new(service: &'a str, username: &'a str) -> Keyring<'a> {
        let attributes = vec![
            ("application", "rust-keyring"),
            ("service", service),
            ("username", username),
        ];
        Keyring {
            attributes: attributes,
            service: service,
            username: username,
        }
    }

    pub fn set_password(&self, password: &str) -> ::Result<()> {
        let password_bytes = password.as_ptr() as *mut u8;
        let password_len = password.len() as u32;

        let mut key = self.make_key();

        let mut credential = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: key.as_mut_ptr(),
            Comment: (&mut [0u16]).as_mut_ptr(),
            LastWritten: FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            },
            CredentialBlobSize: password_len,
            CredentialBlob: password_bytes,
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: ptr::null_mut(),
            TargetAlias: (&mut [0u16]).as_mut_ptr(),
            UserName: (&mut [0u16]).as_mut_ptr(),
        };

        match cred_write(&mut credential) {
            false => Err(KeyringError::WindowsVaultError),
            true => Ok(()),
        }
    }

    pub fn get_password(&self) -> ::Result<String> {
        let key = self.make_key();

        let credential = match cred_read(&key) {
            None => {
                return match get_last_error() {
                    ERROR_NOT_FOUND => Err(KeyringError::NoPasswordFound),
                    _ => Err(KeyringError::WindowsVaultError),
                }
            }
            Some(cred) => cred,
        };

        let password = unsafe {
            slice::from_raw_parts((*credential.ptr).CredentialBlob,
                                  (*credential.ptr).CredentialBlobSize as usize)
        };

        match str::from_utf8(password) {
            Err(_) => Err(KeyringError::NoPasswordFound),
            Ok(password) => Ok(password.to_string()),
        }
    }

    pub fn delete_password(&self) -> ::Result<()> {
        let key = self.make_key();
        match unsafe { CredDeleteW(key.as_ptr(), CRED_TYPE_GENERIC, 0) } {
            FALSE => Err(KeyringError::WindowsVaultError),
            _ => Ok(()),
        }
    }

    fn make_key(&self) -> Vec<u16> {
        let key = format!("{}|{}", self.service, self.username);
        str_to_utf16(&key)
    }
}
