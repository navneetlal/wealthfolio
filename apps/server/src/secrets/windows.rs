use std::{
    fs::File,
    io,
    os::windows::io::AsRawHandle,
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{LocalFree, ERROR_SUCCESS},
    Security::{
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SetSecurityInfo, SDDL_REVISION_1,
            SE_FILE_OBJECT,
        },
        GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    },
};

/// Restrict a vault file to its owner and SYSTEM. The handle must include WRITE_DAC.
pub(super) fn restrict_file(file: &File) -> io::Result<()> {
    // OW is the file owner; P prevents broader permissions inherited from the directory.
    let sddl: Vec<u16> = "D:P(A;;FA;;;OW)(A;;FA;;;SY)\0".encode_utf16().collect();
    // SAFETY: all handles remain alive during the calls; the descriptor owns the DACL
    // buffer until SetSecurityInfo copies it. LocalFree releases it on every exit path.
    unsafe {
        let mut descriptor = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let result = (|| {
            let mut present = 0;
            let mut defaulted = 0;
            let mut dacl = null_mut();
            if GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) == 0 {
                return Err(io::Error::last_os_error());
            }
            // Never accidentally install a NULL DACL, which grants everyone access.
            if present == 0 || dacl.is_null() {
                return Err(io::Error::other("Vault security descriptor has no DACL"));
            }
            let status = SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null(),
            );
            if status == ERROR_SUCCESS {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::Error::from_raw_os_error(status as i32).kind(),
                    format!(
                        "Cannot set vault DACL: {}",
                        io::Error::from_raw_os_error(status as i32)
                    ),
                ))
            }
        })();
        LocalFree(descriptor);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo,
    };

    #[test]
    fn persisted_vault_has_only_owner_and_system_access() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        // Replacing an existing, inherited-permissions file must retain the new ACL.
        std::fs::write(&path, b"old ciphertext").unwrap();
        super::super::atomic_write(&path, b"new ciphertext").unwrap();
        let file = File::open(path).unwrap();
        // SAFETY: Windows allocates both buffers, which remain valid until copied
        // and are freed before assertions. The file handle is live throughout.
        let sddl = unsafe {
            let mut descriptor = null_mut();
            assert_eq!(
                GetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    &mut descriptor,
                ),
                ERROR_SUCCESS
            );
            let mut output = null_mut();
            let mut length = 0;
            let converted = ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut output,
                &mut length,
            );
            LocalFree(descriptor);
            assert_ne!(converted, 0);
            let sddl =
                String::from_utf16_lossy(std::slice::from_raw_parts(output, length as usize - 1));
            LocalFree(output.cast());
            sddl
        };
        // Windows may canonicalize the order of these two allow entries.
        assert!(
            sddl == "D:P(A;;FA;;;OW)(A;;FA;;;SY)" || sddl == "D:P(A;;FA;;;SY)(A;;FA;;;OW)",
            "Unexpected vault DACL: {sddl}"
        );
    }
}
