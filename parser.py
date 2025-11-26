import struct
import os
import sys

def parse_mbr_disk_image(disk_image_path):
    """
    Parse the Master Boot Record (MBR) of a disk image to extract partition table information.
    """
    print(f"Analyzing disk image: {disk_image_path}")
    print(f"File size: {os.path.getsize(disk_image_path)} bytes")
    print()
    
    try:
        with open(disk_image_path, 'rb') as f:
            # Read the entire MBR (first 512 bytes)
            mbr_data = f.read(512)
            
            if len(mbr_data) < 512:
                print("[-] Error: Disk image is too small to contain a valid MBR")
                return None
            
            # Check for MBR signature (0x55AA at offset 510)
            signature = struct.unpack('<H', mbr_data[510:512])[0]
            if signature != 0xAA55:
                print("[-] Warning: Invalid MBR signature. This may not be a valid MBR disk.")
                print(f"[-] Expected 0xAA55, got 0x{signature:04X}")
            
            print("[+] MBR Signature: Valid" if signature == 0xAA55 else "[-] MBR Signature: INVALID")
            print()
            
            # Parse partition table entries (4 entries, each 16 bytes, starting at offset 446)
            partition_table_offset = 446
            partitions = []
            
            print("Partition Table Analysis:")
            print("-" * 80)
            print(f"{'Partition':<10} {'Status':<8} {'Type':<6} {'Start LBA':<12} {'Size (Sectors)':<16} {'Size (MB)':<12}")
            print("-" * 80)
            
            for i in range(4):
                entry_offset = partition_table_offset + (i * 16)
                entry = mbr_data[entry_offset:entry_offset + 16]
                
                if entry[4] == 0x00:  # Empty partition entry
                    continue
                
                # Parse partition entry
                boot_flag = entry[0]
                partition_type = entry[4]
                start_sector = struct.unpack('<I', entry[8:12])[0]
                num_sectors = struct.unpack('<I', entry[12:16])[0]
                
                status = "Active" if boot_flag == 0x80 else "Inactive"
                size_mb = (num_sectors * 512) / (1024 * 1024)
                
                partitions.append({
                    'number': i + 1,
                    'boot_flag': boot_flag,
                    'type': partition_type,
                    'start_sector': start_sector,
                    'num_sectors': num_sectors,
                    'size_mb': size_mb
                })
                
                print(f"{i+1:<10} {status:<8} 0x{partition_type:02X}<6 {start_sector:<12} {num_sectors:<16} {size_mb:<12.2f}")
            
            return partitions
            
    except FileNotFoundError:
        print(f"Error: File '{disk_image_path}' not found")
        return None
    except Exception as e:
        print(f"Error reading disk image: {e}")
        return None

def analyze_partition_types(partitions):
    """
    Provide information about partition types and their meanings.
    """
    if not partitions:
        return
    
    print()
    print("Partition Type Analysis:")
    print("-" * 50)
    
    # Common partition types
    partition_types = {
        0x07: "NTFS/HPFS",
        0x07: "NTFS",
        0x0B: "FAT32",
        0x0C: "FAT32 (LBA)",
        0x83: "Linux Native",
        0x82: "Linux Swap",
        0x05: "Extended",
        0x0F: "Extended (LBA)",
        0xEE: "GPT Protective"
    }
    
    for partition in partitions:
        p_type = partition['type']
        type_desc = partition_types.get(p_type, "Unknown")
        print(f"Partition {partition['number']}: Type 0x{p_type:02X} = {type_desc}")

def identify_correct_second_partition(partitions, disk_image_path):
    """
    Attempt to identify and correct the second partition based on common patterns.
    """
    if not partitions or len(partitions) < 2:
        print("[-] Not enough partitions found for analysis")
        return None
    
    print()
    print("Second Partition Analysis:")
    print("-" * 50)
    
    # Common Windows partition structure:
    # Partition 1: System Reserved (small, ~100-500MB)
    # Partition 2: Main OS (large, most of the disk)
    
    second_partition = partitions[1]  # Index 1 is the second partition
    
    print(f"Second Partition Details:")
    print(f"  - Type: 0x{second_partition['type']:02X}")
    print(f"  - Start Sector: {second_partition['start_sector']}")
    print(f"  - Size: {second_partition['size_mb']:.2f} MB")
    print(f"  - Total Sectors: {second_partition['num_sectors']}")
    
    # Check if this looks like a valid NTFS partition
    if second_partition['type'] == 0x07:  # NTFS
        print("  - Status: Appears to be a valid NTFS partition")
        
        # Verify by checking for NTFS signature
        try:
            with open(disk_image_path, 'rb') as f:
                # Seek to the beginning of the partition
                f.seek(second_partition['start_sector'] * 512)
                # Read first sector of the partition
                partition_boot_sector = f.read(512)
                
                # Check for NTFS signature "NTFS    "
                if partition_boot_sector[3:11] == b'NTFS    ':
                    print("  - NTFS Signature: CONFIRMED")
                    return second_partition
                else:
                    print("  - NTFS Signature: NOT FOUND - Partition may be corrupted")
                    
        except Exception as e:
            print(f"  - Error verifying partition: {e}")
    
    return second_partition

def suggest_correction(partitions, disk_image_path):
    """
    Suggest corrections if the second partition appears invalid.
    """
    print()
    print("Correction Suggestions:")
    print("-" * 40)
    
    if len(partitions) >= 2:
        second_part = partitions[1]
        
        # Common correction: If second partition start sector seems wrong,
        # look for common patterns
        if second_part['start_sector'] < 2048:  # Unusually small start
            print(f"[-] Partition 2 start sector ({second_part['start_sector']}) seems unusually small")
            print("[+] Common Windows installations start around sector 2048 or 4096")
        
        # Check if we should look for a backup MBR or GPT
        if second_part['type'] == 0xEE:  # GPT Protective
            print("[+] This appears to be a GPT disk with protective MBR")
            print("[+] Consider using GPT parsing instead")
        
    # If no valid second partition found, suggest manual sector search
    if not partitions or len(partitions) < 2:
        print("[+] No valid second partition found in MBR")
        print("[+] Suggestions:")
        print("  1. Check if this is a GPT disk")
        print("  2. Manually search for file system signatures")
        print("  3. The 'corruption' might be in the MBR, not the partition itself")

def main():
    if len(sys.argv) != 2:
        print("Usage: python parse_partition_table.py <disk_image_file>")
        print("Example: python parse_partition_table.py image.dd")
        sys.exit(1)
    
    disk_image_path = sys.argv[1]
    
    if not os.path.exists(disk_image_path):
        print(f"Error: File '{disk_image_path}' does not exist")
        sys.exit(1)
    
    # Parse the MBR and partition table
    partitions = parse_mbr_disk_image(disk_image_path)
    
    if partitions:
        # Analyze partition types
        analyze_partition_types(partitions)
        
        # Identify and verify the second partition
        second_partition = identify_correct_second_partition(partitions, disk_image_path)
        
        # Provide correction suggestions
        suggest_correction(partitions, disk_image_path)
        
        print()
        print("Summary of findings for your report:")
        print("-" * 50)
        if partitions:
            for p in partitions:
                print(f"Partition {p['number']}: Start sector {p['start_sector']}, Size {p['size_mb']:.2f} MB, Type 0x{p['type']:02X}")
        
        if second_partition:
            print(f"\nSecond partition appears to start at sector: {second_partition['start_sector']}")
            print(f"This should be the offset used for mounting: {second_partition['start_sector'] * 512} bytes")
    
    else:
        print("[-] No partitions found or error reading disk image")

if __name__ == "__main__":
    main()