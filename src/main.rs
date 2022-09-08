use std::fs::File;
use std::io::SeekFrom;

use libc::{c_char, size_t};
use sha2::{Digest, Sha384};
use zeroize::Zeroize;

use arch_gen::x86::bootparam::{boot_params, E820_RAM};

const TD_INFO_STRUCT_RESERVED_SIZE: usize = 0x70;
const TDVF_DESCRIPTOR_OFFSET: usize = 0x20;
const MRTD_EXTENSION_BUFFER_SIZE: usize = 0x80;
const TDH_MR_EXTEND_GRANULARITY: u64 = 0x100;
const PAGE_SIZE: u64 = 0x1_000;

const MEM_PAGE_ADD_ASCII_SIZE: usize = 0xc;
const MEM_PAGE_ADD_GPA_OFFSET: usize = 0x10;
const MEM_PAGE_ADD_GPA_SIZE: usize = 0x8;
const MR_EXTEND_ASCII_SIZE: usize = 0x9;
const MR_EXTEND_GPA_OFFSET: usize = 0x10;
const MR_EXTEND_GPA_SIZE: usize = 0x8;

#[derive(Copy, Clone, Default)]
struct BootParamsWrapper(boot_params);

#[link(name = "krunfw-sev")]
extern "C" {
    fn krunfw_get_qboot(size: *mut size_t) -> *mut c_char;
    fn krunfw_get_initrd(size: *mut size_t) -> *mut c_char;
    fn krunfw_get_kernel(load_addr: *mut u64, size: *mut size_t) -> *mut c_char;
}

/// Add an e820 region to the e820 map.
/// Returns Ok(()) if successful, or an error if there is no space left in the map.
fn add_e820_entry(params: &mut boot_params, addr: u64, size: u64, mem_type: u32) {
    params.e820_map[params.e820_entries as usize].addr = addr;
    params.e820_map[params.e820_entries as usize].size = size;
    params.e820_map[params.e820_entries as usize].type_ = mem_type;
    params.e820_entries += 1;
}

fn generate_zero_page(buf: &mut [u8], initrd_size: u32) {
    const EBDA_START: u64 = 0x9fc00;
    const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
    const KERNEL_LOADER_OTHER: u8 = 0xff;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000; // Must be non-zero.
    const HIMEM_START: u64 = 0x0010_0000;

    let mut params: BootParamsWrapper = BootParamsWrapper(boot_params::default());

    //let last_addr: u64 = 2 * 1024 * 1024 * 1024;
    let last_addr: u64 = 0x80000000;

    params.0.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    params.0.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.0.hdr.header = KERNEL_HDR_MAGIC;
    params.0.hdr.cmd_line_ptr = 0x20000;
    params.0.hdr.cmdline_size = 0x200;

    params.0.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    params.0.hdr.ramdisk_image = 0xa0_0000;
    params.0.hdr.ramdisk_size = initrd_size;

    params.0.hdr.root_flags = 2;
    params.0.hdr.syssize = (last_addr / 4096) as u32;

    add_e820_entry(&mut params.0, 0, EBDA_START, E820_RAM);
    add_e820_entry(
        &mut params.0,
        HIMEM_START,
        last_addr - HIMEM_START + 1,
        E820_RAM,
    );

    buf[0..0x1000].copy_from_slice(unsafe {
        std::slice::from_raw_parts(&params as *const _ as *const u8, 0x1000)
    });
}

fn hash_blob(sha384hasher: &mut Sha384, blob: &[u8], base_addr: u64, size: u64) {
    let nr_pages = size / PAGE_SIZE;
    let mut buf: [u8; MRTD_EXTENSION_BUFFER_SIZE] = [0; MRTD_EXTENSION_BUFFER_SIZE]; // used by page add
    let mut buffer3_128: [[u8; MRTD_EXTENSION_BUFFER_SIZE]; 3] =
        [[0; MRTD_EXTENSION_BUFFER_SIZE]; 3]; // used by mr extend

    //println!("hash_blob: base_addr={:x}, size={:x}", base_addr, size);

    for iter in 0..nr_pages {
        //println!("page: {}", iter);

        fill_buffer128_with_mem_page_add(&mut buf, base_addr + iter * PAGE_SIZE);
        sha384hasher.update(&buf);

        let granularity = TDH_MR_EXTEND_GRANULARITY;
        let iteration = PAGE_SIZE / granularity;
        let data_offset = 0;
        for chunk_iter in 0..iteration {
            //println!("iteration: {}", chunk_iter);
            fill_buffer3_128_with_mr_extend(
                &mut buffer3_128,
                base_addr + iter * PAGE_SIZE + chunk_iter * granularity,
                blob,
                data_offset as u64 + iter * PAGE_SIZE + chunk_iter * granularity,
            );

            sha384hasher.update(&buffer3_128[0]);
            sha384hasher.update(&buffer3_128[1]);
            sha384hasher.update(&buffer3_128[2]);
        }
    }
}

fn main() {
    let mut kernel_guest_addr: u64 = 0;
    let mut kernel_size: usize = 0;
    let kernel_host_addr = unsafe {
        krunfw_get_kernel(
            &mut kernel_guest_addr as *mut u64,
            &mut kernel_size as *mut usize,
        )
    };

    let mut qboot_size: usize = 0;
    let qboot_host_addr = unsafe { krunfw_get_qboot(&mut qboot_size as *mut usize) };

    let mut initrd_size: usize = 0;
    let initrd_host_addr = unsafe { krunfw_get_initrd(&mut initrd_size as *mut usize) };

    let qboot_data =
        unsafe { std::slice::from_raw_parts(qboot_host_addr as *const u8, qboot_size) };
    let kernel_data =
        unsafe { std::slice::from_raw_parts(kernel_host_addr as *const u8, kernel_size) };
    let initrd_data =
        unsafe { std::slice::from_raw_parts(initrd_host_addr as *const u8, initrd_size) };

    let mut sha384hasher = Sha384::new();

    hash_blob(
        &mut sha384hasher,
        qboot_data,
        0xffff_0000,
        qboot_size as u64,
    );
    hash_blob(
        &mut sha384hasher,
        kernel_data,
        kernel_guest_addr,
        kernel_size as u64,
    );
    hash_blob(
        &mut sha384hasher,
        initrd_data,
        0xa0_0000,
        initrd_size as u64,
    );

    let mut buf: [u8; 0x19000] = [0; 0x19000];
    generate_zero_page(&mut buf, initrd_size as u32);
    hash_blob(&mut sha384hasher, &buf, 0x7000, 0x19000u64);

    let hash = sha384hasher.finalize();
    println!("{:?}", hex::encode(hash));
}

fn fill_buffer128_with_mem_page_add(buf: &mut [u8; MRTD_EXTENSION_BUFFER_SIZE], gpa: u64) {
    buf.zeroize();

    // Byte 0 through 11 contain the ASCII string 'MEM.PAGE.ADD'.
    // Byte 16 through 23 contain the GPA (in little-endian format).
    // All the other bytes contain 0.
    buf[0..MEM_PAGE_ADD_ASCII_SIZE].copy_from_slice("MEM.PAGE.ADD".as_bytes());
    buf[MEM_PAGE_ADD_GPA_OFFSET..MEM_PAGE_ADD_GPA_OFFSET + MEM_PAGE_ADD_GPA_SIZE]
        .copy_from_slice(gpa.to_le_bytes().as_ref());
}

fn fill_buffer3_128_with_mr_extend(
    buf: &mut [[u8; MRTD_EXTENSION_BUFFER_SIZE]; 3],
    gpa: u64,
    data: &[u8],
    data_offset: u64,
) {
    buf[0].zeroize();
    buf[1].zeroize();
    buf[2].zeroize();

    // Byte 0 through 8 contain the ASCII string 'MR.EXTEND'.
    // Byte 16 through 23 contain the GPA (in little-endian format).
    // All the other bytes contain 0. The other two extension buffers contain the chunk’s content.
    buf[0][0..MR_EXTEND_ASCII_SIZE].copy_from_slice("MR.EXTEND".as_bytes());
    buf[0][MR_EXTEND_GPA_OFFSET..MR_EXTEND_GPA_OFFSET + MR_EXTEND_GPA_SIZE]
        .copy_from_slice(gpa.to_le_bytes().as_ref());

    let start = data_offset as usize;
    let end = (data_offset + 128) as usize;
    buf[1].copy_from_slice(&data[start..end]);

    let start = (data_offset + 128) as usize;
    let end = (data_offset + 256) as usize;
    buf[2].copy_from_slice(&data[start..end]);
}
