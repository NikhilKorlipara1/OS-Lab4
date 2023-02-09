//
//  nyufile.c
//  nyufile
//
//  Created by Nikhil Korlipara on 12/12/22.
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <pthread.h>
#include <openssl/sha.h>

#define SHA_DIGEST_LENGTH 20
#define EOC 0xFFFFFFFF
#define FAT_EOF 0x0FFFFFF8
#define ATTR_LONG_NAME 0x0F
#define ATTR_DIRECTORY 0x10

typedef struct mapped_disk {
    char* address;
    int fd;
    unsigned int size;
    unsigned int bytes_per_sector;
    unsigned int sectors_per_cluster;
    unsigned int fat_offset;
    int n_fats;
    unsigned int size_of_fat_in_sectors;
    int root_dir_cluster;
    int dir_entries_per_cluster;
    unsigned int cluster_size_in_bytes;
} MAPPED_DISK_T;

static MAPPED_DISK_T mapped_disk;
static char sha1_buf[SHA_DIGEST_LENGTH+1];
static char hex_sha1_buf[SHA_DIGEST_LENGTH*2+1];

#pragma pack(push,1)
typedef struct BootEntry {
  unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
  unsigned char  BS_OEMName[8];     // OEM Name in ASCII
  unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
  unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
  unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
  unsigned char  BPB_NumFATs;       // Number of FATs
  unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
  unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
  unsigned char  BPB_Media;         // Media type
  unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
  unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
  unsigned short BPB_NumHeads;      // Number of heads in storage device
  unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
  unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
  unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
  unsigned short BPB_ExtFlags;      // A flag for FAT
  unsigned short BPB_FSVer;         // The major and minor version number
  unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
  unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
  unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
  unsigned char  BPB_Reserved[12];  // Reserved
  unsigned char  BS_DrvNum;         // BIOS INT13h drive number
  unsigned char  BS_Reserved1;      // Not used
  unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
  unsigned int   BS_VolID;          // Volume serial number
  unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
  unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct DirEntry {
  unsigned char  DIR_Name[11];      // File name
  unsigned char  DIR_Attr;          // File attributes
  unsigned char  DIR_NTRes;         // Reserved
  unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
  unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
  unsigned short DIR_CrtDate;       // Created day
  unsigned short DIR_LstAccDate;    // Accessed day
  unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
  unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
  unsigned short DIR_WrtDate;       // Written day
  unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
  unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)

static unsigned int getFileSize(const char* filename);
static void mapDisk(const char* filename);
static void unmapDisk();
static int getFatEntry(int N);
static unsigned int clusterOffset(int N);
static void copyDirName(char* dest, char* DIR_Name);
static char* hexDecode(char* sha1_hex);
static char* hexEncode(char* sha1);
static void setFATValue(int N, unsigned int value);
static unsigned int le32ptoh(const void* p);
static unsigned int le16ptoh(const void* p);

static void printFileSystemInfo();
static void listRootDir();
static void recoverFile(const char*, const char*, bool);

void printUsage(char* progName) {
    printf("Usage: %s disk <options>\n", progName);
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
}

typedef enum Command {
    PRINT,
    LIST,
    RECOVER_CONTIGOUS_FILE,
    RECOVER_FILE
} Command_t;

int main(int argc, char* argv[]) {
    if (argc <= 2) {
        printUsage(argv[0]);
        exit(-1);
    }
    Command_t command;
    bool use_sha1 = false;
    char* sha1 = NULL;
    char* filename;
    int i=2;
    if (strcmp("-i", argv[i]) == 0) {
        command = PRINT;
        i = 3;
    } else if (strcmp("-l", argv[i]) == 0) {
        command = LIST;
        i = 3;
    } else if (strcmp("-r", argv[i]) == 0) {
        if (argc != 4 && argc != 6) {
            printUsage(argv[0]);
            exit(-1);
        } else if (argc == 6) {
            i = 6;
            if (strcmp("-s", argv[4]) == 0) {
                use_sha1 = true;
                if (strlen(argv[5]) != SHA_DIGEST_LENGTH*2) {
                    printUsage(argv[0]);
                    exit(-1);
                } else {
                    sha1 = hexDecode(argv[5]);
                }
            } else {
                printUsage(argv[0]);
                exit(-1);
            }
        } else {
            i = 4;
        }
        filename = argv[3];
        command = RECOVER_CONTIGOUS_FILE;
    } else if (strcmp("-R", argv[i]) == 0) {
        if (argc != 6 || strcmp("-s", argv[4]) != 0) {
            printUsage(argv[0]);
            exit(-1);
        } else {
            use_sha1 = true;
            if (strlen(argv[5]) != SHA_DIGEST_LENGTH*2) {
                printUsage(argv[0]);
                exit(-1);
            } else {
                sha1 = hexDecode(argv[5]);
            }
        }
        filename = argv[3];
        i = 6;
        command = RECOVER_FILE;
    }
    
    if (argc != i) {
        printUsage(argv[0]);
        exit(-1);
    }
    
    mapDisk(argv[1]);
    
    switch (command) {
        case PRINT:
            printFileSystemInfo();
            break;
        case LIST:
            listRootDir();
            break;
        case RECOVER_CONTIGOUS_FILE:
            recoverFile(filename, sha1, true);
            break;
        case RECOVER_FILE:
            recoverFile(filename, sha1, false);
            break;
        default:
            printUsage(argv[0]);
            goto cleanup;
    }

cleanup:
    unmapDisk();
}

/*
 [root@... cs202]# ./nyufile fat32.disk -i
 Number of FATs = 2
 Number of bytes per sector = 512
 Number of sectors per cluster = 1
 Number of reserved sectors = 32
 */
static void printFileSystemInfo() {
    BootEntry* boot_entry_ptr = (BootEntry*)mapped_disk.address;
    printf("Number of FATs = %d\n", boot_entry_ptr->BPB_NumFATs);
    printf("Number of bytes per sector = %d\n", le16ptoh(&(boot_entry_ptr->BPB_BytsPerSec)));
    printf("Number of sectors per cluster = %d\n", boot_entry_ptr->BPB_SecPerClus);
    printf("Number of reserved sectors = %d\n", le16ptoh(&(boot_entry_ptr->BPB_RsvdSecCnt)));
}

static void listRootDir() {
    int nextCluster = mapped_disk.root_dir_cluster;
    char dir_entry_name[13];
    int total_entries = 0;
    bool EOD = false;
    do {
    //    printf("listing directory entries in cluster %08x\n", nextCluster);
        char* cluster_address = mapped_disk.address + clusterOffset(nextCluster);
        for(int i=0; i < mapped_disk.dir_entries_per_cluster; i++) {
    //        printf("dirEntry i=%d\n", i);
            DirEntry* entry = (DirEntry*) (cluster_address + sizeof(DirEntry)  * i);
            if (entry->DIR_Name[0] == 0) {
		EOD = true;
                break;
            } else if (entry->DIR_Name[0] == 0xE5) {
                continue;
            } else if ((entry->DIR_Attr & ATTR_LONG_NAME) == ATTR_LONG_NAME) {
                continue; // skip dir entry if it's for LONG FILE NAME
            }
            total_entries++;
            unsigned int filesize = le32ptoh(&(entry->DIR_FileSize));
            unsigned int first_cluster_number = le16ptoh(&(entry->DIR_FstClusHI)) << 16 | le16ptoh(&(entry->DIR_FstClusLO));
            copyDirName(dir_entry_name, entry->DIR_Name);
            printf("%s", dir_entry_name);
            if (entry->DIR_Attr & ATTR_DIRECTORY) {
                printf("/");
            }
            printf(" (size = %d, starting cluster = %d)\n", filesize, first_cluster_number);
        };
	if (EOD) {
	   break;
        }
    } while (0x0FFFFFF8 > (nextCluster = getFatEntry(nextCluster)));
    printf("Total number of entries = %d\n", total_entries);
}

static void copyDirName(char* dest, char* DIR_Name) {
    memset(dest, 0, 13);
    int filename_len = 8;
    while(DIR_Name[filename_len-1] == ' ') {
        filename_len--;
    }
    memcpy(dest, DIR_Name, filename_len);
    if (DIR_Name[8] != ' ') {
        dest[filename_len] = '.';
        
        int dir_name_len = 11;
        while(DIR_Name[dir_name_len-1] == ' ') {
            dir_name_len--;
        }
        memcpy(dest+filename_len+1, DIR_Name+8, dir_name_len-8);
        if (dest[0] == 0x05) {
            dest[0] = 0xE5;
        }
    }
}

static void swap(unsigned int* a, int i, int j) {
    if (i == j)
        return;
    unsigned int t = a[i];
    a[i] = a[j];
    a[j] = t;
}

static void enumeratePermutations(unsigned int* avl, int N, int R, unsigned int* permutations, int* permutation_count, int N_orig, int R_orig) {
    
    if (R == 0) {
        for(int i=0; i<R_orig; i++) {
            permutations[(*permutation_count)*R_orig + i] = avl[i];
        }
        (*permutation_count)++;

      //  printf("N %d R %d permutation_count %d N_orig %d R_orig %d\n", N, R, *permutation_count, N_orig, R_orig);
       // fflush(stdout);
        return;
    }
    for(int i=N_orig-N; i<N_orig; i++) {
        swap(avl, R_orig-R, i);
        enumeratePermutations(avl, N-1, R-1, permutations, permutation_count, N_orig, R_orig);
        swap(avl, R_orig-R, i);
    }
}

static void getPermutations(unsigned int* avl, int N, int R, unsigned int* permutations) {
    int permutation_count = 0;
    enumeratePermutations(avl, N, R, permutations, &permutation_count, N, R);
}

static void recoverFile(const char* filename, const char* sha1, bool contiguous) {
 //   printf("attempting recovery for filename %s sha1 %s contiguous %d\n", filename, sha1, contiguous);
    int nextCluster = mapped_disk.root_dir_cluster;
    char dir_entry_name[13];
    bool found = false;
    int found_entry_idx;
    int found_in_cluster_number;
    unsigned int found_filesize;
    unsigned int found_file_first_cluster_number;
    unsigned int found_file_cluster_numbers[5];
    do {
        char* cluster_address = mapped_disk.address + clusterOffset(nextCluster);
        for(int i=0; i < mapped_disk.dir_entries_per_cluster; i++) {
            DirEntry* entry = (DirEntry*) (cluster_address + sizeof(DirEntry)  * i);
            if (entry->DIR_Name[0] == 0) {
                break;
            } else if (entry->DIR_Name[0] == 0xE5) {
                if (entry->DIR_Attr & ATTR_DIRECTORY) {
                    continue;
                } else if ((entry->DIR_Attr & ATTR_LONG_NAME) == ATTR_LONG_NAME) {
                    continue; // skip dir entry if it's for LONG FILE NAME
                } else if (found && sha1 != NULL) {
                    continue;
                }
                unsigned int filesize = le32ptoh(&(entry->DIR_FileSize));
                unsigned int first_cluster_number = le16ptoh(&(entry->DIR_FstClusHI)) << 16 | le16ptoh(&(entry->DIR_FstClusLO));
                copyDirName(dir_entry_name, entry->DIR_Name);
          //     fprintf(stderr, "checking dir_entry_name=%s filename=%s\n", dir_entry_name, filename);
                if (strcmp(&(dir_entry_name[1]), filename+1) == 0) {
                    if (sha1 != NULL) {
                        if (contiguous || filesize <= mapped_disk.cluster_size_in_bytes) {
                            char md[SHA_DIGEST_LENGTH];
                            SHA1(mapped_disk.address+clusterOffset(first_cluster_number), filesize, md);
               //         fprintf(stderr, "sha1 for dir_entry_name=%s is %s\n", dir_entry_name, hexEncode(md));
                            if (!found && memcmp(md, sha1, SHA_DIGEST_LENGTH) == 0) {
                                found = true;
                                found_entry_idx = i;
                                found_in_cluster_number = nextCluster;
                                found_filesize = filesize;
                                found_file_first_cluster_number = first_cluster_number;
                            }
                            continue;
                        } else {
                            // when file spans multiple non-contiguous clusters...
                         //   fprintf(stderr, "contiguous = %d filesize = %d\n", contiguous, filesize);
                            int number_of_clusters = filesize / mapped_disk.cluster_size_in_bytes + ((filesize % mapped_disk.cluster_size_in_bytes) > 0 ? 1 : 0);
                            
                         //   fprintf(stderr, "contiguous = %d number_of_clusters = %d\n", contiguous, number_of_clusters);
                            if (number_of_clusters > 5) {
                                printf("%s: file not found\n", filename);
                                return;
                            }
                            // find the free clusters in the first 20
                            // start looking from the 3rd FAT entry until 22
                            int n_free_clusters = 0;
                            unsigned int free_clusters[20];
                            for(int k=3; k<=22; k++) {
                                if (k == first_cluster_number) {
                                    continue;
                                }
                                char* fat_entry_address = mapped_disk.address + mapped_disk.fat_offset + k*32;
                                if (((*(unsigned int *)fat_entry_address) & 0x0fffffff) == 0) {
                                    free_clusters[n_free_clusters++] = k;
                                }
                            }
                       //     fprintf(stderr, "contiguous = %d n_free_clusters = %d\n", contiguous, n_free_clusters);
                            if (n_free_clusters < number_of_clusters-1) {
                                printf("%s: file not found\n", filename);
                                return;
                            }
                            int n_p_r=1;
                            for(int k=n_free_clusters; k > n_free_clusters-number_of_clusters+1; k--) {
                                    n_p_r *= k;
                            }
                      //      fprintf(stderr, "npr = %d n = %d r = %d\n", n_p_r, n_free_clusters, number_of_clusters-1);
                            // space needed for n_p_r permutations
                            unsigned int permutations[n_p_r * (number_of_clusters-1)];
                            
                            getPermutations(free_clusters, n_free_clusters, number_of_clusters-1, permutations);
                            /*
                            for(int k=0; i < n_p_r; i++) {
                                fprintf(stderr, "permutation %d: %d ", k, first_cluster_number);
                                for(int j=0; j < number_of_clusters-1; j++) {
                                    fprintf(stderr, "%d ", permutations[k*(number_of_clusters-1) + j]);
                                }
                                fprintf(stderr, "\n");
                            }
                             */
                            char file[filesize];
                            char* ptr = file;
                            char* loc = mapped_disk.address + clusterOffset(first_cluster_number);
                            memcpy(ptr, loc, mapped_disk.cluster_size_in_bytes);
                            for(int k=0; k < n_p_r; k++) {
                                ptr = file + mapped_disk.cluster_size_in_bytes;
                                int bytes_remaining = filesize - mapped_disk.cluster_size_in_bytes;
                         //       fprintf(stderr, "cluster chain %d ", first_cluster_number);
                                for(int j=0; j < number_of_clusters-1; j++) {
                                    int next_cluster_in_chain = permutations[k*(number_of_clusters-1) + j];
                                    loc = mapped_disk.address + clusterOffset(next_cluster_in_chain);
                                    int bytes_to_copy = bytes_remaining > mapped_disk.cluster_size_in_bytes ? mapped_disk.cluster_size_in_bytes : bytes_remaining;
                                    memcpy(ptr, loc, bytes_to_copy);
                                    bytes_remaining -= bytes_to_copy;
                                    ptr += bytes_to_copy;
                           //         fprintf(stderr, "%d ", next_cluster_in_chain);
                                }
                                char md[SHA_DIGEST_LENGTH];
                                SHA1(file, filesize, md);
                        //        fprintf(stderr, "sha1 for dir_entry_name=%s is %s\n", dir_entry_name, hexEncode(md));
                                if (!found && memcmp(md, sha1, SHA_DIGEST_LENGTH) == 0) {
                                    found = true;
                                    found_entry_idx = i;
                                    found_in_cluster_number = nextCluster;
                                    found_filesize = filesize;
                                    found_file_cluster_numbers[0] = first_cluster_number;
                                    for(int j=1; j<number_of_clusters; j++) {
                                        found_file_cluster_numbers[j] = permutations[k*(number_of_clusters-1) + j - 1];
                                    }
                              //      fprintf(stderr, "found. permutation = ");
                                    /*
                                    for(int j=0; j < number_of_clusters; j++) {
                                        fprintf(stderr, "%d ", found_file_cluster_numbers[j]);
                                    }
                                     */
                                    break;
                                }
                            }
                        }
                    } else if (!found) {
                        found = true;
                        found_entry_idx = i;
                        found_in_cluster_number = nextCluster;
                        found_filesize = filesize;
                        found_file_first_cluster_number = first_cluster_number;
                    } else {
                        printf("%s: multiple candidates found\n", filename);
                        return;
                    }
                }
                continue;
            } else if ((entry->DIR_Attr & ATTR_LONG_NAME) == ATTR_LONG_NAME) {
                continue; // skip dir entry if it's for LONG FILE NAME
            } else {
                copyDirName(dir_entry_name, entry->DIR_Name);
                if (strcmp(dir_entry_name, filename) == 0) {
                    // matches an existing directory entry. print error and return
                    printf("%s: file exists with the given name. cannot recover\n", filename);
                    return;
                }
            }
        };
    } while (0x0FFFFFF8 > (nextCluster = getFatEntry(nextCluster)));
    if (found) {
     //   printf("found_in_cluster_number=%x. found_entry_idx=%d, cluster_offset=%x\n", found_in_cluster_number, found_entry_idx, clusterOffset(found_in_cluster_number));

        char* cluster_address = mapped_disk.address + clusterOffset(found_in_cluster_number);
        DirEntry* entry = (DirEntry*) (cluster_address + sizeof(DirEntry) * found_entry_idx);
        entry->DIR_Name[0] = filename[0];
        if (sha1 != NULL) {
            printf("%s: successfully recovered with SHA-1\n", filename);
        } else {
            printf("%s: successfully recovered\n", filename);
        }
        
        int number_of_clusters_for_file = (found_filesize / mapped_disk.cluster_size_in_bytes) + ((found_filesize % mapped_disk.cluster_size_in_bytes) > 0 ? 1 : 0);
        
        if (contiguous || number_of_clusters_for_file<=1) {
            unsigned int next_cluster = FAT_EOF;
            int N = found_file_first_cluster_number;
            int i;
            for (i=1; i<number_of_clusters_for_file; i++) {
                setFATValue(N+i-1, N+i);
            }
            setFATValue(N+i-1, FAT_EOF);
        } else {
            int i;
            for (i = 1; i < number_of_clusters_for_file; i++) {
                setFATValue(found_file_cluster_numbers[i-1], found_file_cluster_numbers[i]);
            }
            setFATValue(found_file_cluster_numbers[i-1], FAT_EOF);
        }
    } else {
        printf("%s: file not found\n", filename);
    }
}

static void setFATValue(int N, unsigned int value) {
    // get current value
    for(int i=0; i<mapped_disk.n_fats; i++) {
        char* fat_entry_address = mapped_disk.address + mapped_disk.fat_offset + i*mapped_disk.size_of_fat_in_sectors*mapped_disk.bytes_per_sector + 4*N;
        //fprintf(stderr, "writing to fat_offset %x entry %d value %x\n", mapped_disk.fat_offset, N, value);
        unsigned int curr_val = le32ptoh(fat_entry_address);
        int reserved = 0xf0000000 & curr_val;
        unsigned int new_val = (value & 0x0fffffff) | reserved;
        char le_int[4] = {new_val & 0xff, (new_val & 0xff00) >> 8, (new_val & 0xff0000) >> 16, new_val >> 24};
        //fprintf(stderr, "writing to reserved %x new_val %x 0x%02x%02x%02x%02x\n", reserved, new_val, le_int[0], le_int[1], le_int[2], le_int[3]);

        memcpy(fat_entry_address, le_int, 4);
    }
}

static void mapDisk(const char* filename) {
    // compute the number of tasks needed
    int fd;
    char* address;
    unsigned int filesize = getFileSize(filename);
    if (-1 != (fd = open(filename, O_RDWR))) {
        // mmap the file
        address = (char*)mmap(NULL, filesize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 );
        if (address == MAP_FAILED) {
            fprintf(stderr, "failed to mmap file %s. exiting\n", filename);
            exit(-1);
        }
    } else {
        fprintf(stderr, "Failed to access file %s. Exiting\n", filename);
        exit(-1);
    }
    mapped_disk.address = address;
    mapped_disk.fd = fd;
    mapped_disk.size = filesize;
    
    BootEntry* boot_entry_ptr = (BootEntry*)mapped_disk.address;
    mapped_disk.root_dir_cluster = le32ptoh(&(boot_entry_ptr->BPB_RootClus));

    mapped_disk.bytes_per_sector = le16ptoh(&(boot_entry_ptr->BPB_BytsPerSec));
    mapped_disk.sectors_per_cluster = boot_entry_ptr->BPB_SecPerClus;

    
    mapped_disk.fat_offset = le16ptoh(&(boot_entry_ptr->BPB_RsvdSecCnt)) * mapped_disk.bytes_per_sector;
    
    mapped_disk.dir_entries_per_cluster = ( mapped_disk.bytes_per_sector * mapped_disk.sectors_per_cluster ) / sizeof(DirEntry);
    
    mapped_disk.n_fats = boot_entry_ptr->BPB_NumFATs;
    mapped_disk.size_of_fat_in_sectors = le32ptoh(&(boot_entry_ptr->BPB_FATSz32));
    
    mapped_disk.cluster_size_in_bytes = mapped_disk.bytes_per_sector * mapped_disk.sectors_per_cluster;
    
   // fprintf(stderr, "mapped file %s. filesize=%d, fd=%d, root_dir_offset=%x, fat_offset=%x, \n", filename, filesize, fd, clusterOffset(mapped_disk.root_dir_cluster), mapped_disk.fat_offset);
}

static unsigned int clusterOffset(int N) {
    BootEntry* boot_entry_ptr = (BootEntry*)mapped_disk.address;
    return ( le16ptoh(&(boot_entry_ptr->BPB_RsvdSecCnt)) + boot_entry_ptr->BPB_NumFATs * le32ptoh(&(boot_entry_ptr->BPB_FATSz32)) + (N - 2)*mapped_disk.sectors_per_cluster ) * mapped_disk.bytes_per_sector;
}

static void unmapDisk() {
    if (mapped_disk.address == NULL) {
        return;
    }
    munmap(mapped_disk.address, mapped_disk.size);
    close(mapped_disk.fd);
}

static unsigned int getFileSize(const char* filename) {
    struct stat sb;
    if (stat(filename, &sb) == -1) {
        fprintf(stderr, "stat failed for file %s. exiting\n", filename);
        exit(-1);
    }
    
    if ((sb.st_mode & S_IFMT) != S_IFREG) {
        fprintf(stderr, "file %s is not a regular file. exiting\n", filename);
        exit(-1);
    }
    return sb.st_size;
}

static int getFatEntry(int N) {
    unsigned int entry_offset = 4 * N;
    return le32ptoh((unsigned int*)(mapped_disk.address + mapped_disk.fat_offset + entry_offset)) & 0x0FFFFFFF; /* only 28bits are used for cluster number in fat-32 */
}

static unsigned int hexDigitToInt(char hex) {
    if (hex >= '0' && hex <= '9')
        return hex - '0';
    else if (hex >= 'a' && hex <= 'f')
        return hex - 'a' + 10;
    else if (hex >= 'A' && hex <= 'F')
        return hex - 'A' + 10;
    else {
        fprintf(stderr, "invalid hex digit %c\n", hex);
        exit(-1);
    }
}

static char* hexDecode(char* sha1_hex) {
    memset(sha1_buf, 0, SHA_DIGEST_LENGTH+1);
    char* ptr = sha1_buf;
    for(int i=0; i<SHA_DIGEST_LENGTH; i++) {
        *ptr = (char)(hexDigitToInt(sha1_hex[2*i]) << 4 | hexDigitToInt(sha1_hex[2*i+1]));
        ptr++;
    }
    return sha1_buf;
}

static char* hexEncode(char* sha1) {
    memset(hex_sha1_buf, 0, SHA_DIGEST_LENGTH*2+1);
    char* ptr = hex_sha1_buf;
    for(int i=0; i<SHA_DIGEST_LENGTH; i++) {
        sprintf(ptr+2*i, "%02x", sha1[i]);
    }
    return hex_sha1_buf;
}

static unsigned int le16ptoh(const void* p) {
    return *(unsigned short*)p;
    /*
    char* x = (char*)p;
    return (x[1] << 8) | x[0];
     */
}

static unsigned int le32ptoh(const void* p) {
    return *(unsigned int*)p;
    /*
    char* x = (char*)p;
    return (x[3] << 24) | (x[2] << 16) | (x[1] << 8) | x[0];
     */
}
