#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

#define NUM_FAT_ENTRIES_BLOCK 2048

struct superblock {
    char sig[8];
    uint16_t disk_num_blocks;
    uint16_t rootdir_index;
    uint16_t data_index;
    uint16_t num_data;
    uint8_t num_fat;
    uint8_t unused[4079];
} __attribute__((packed));
typedef struct superblock superblock_t;

struct file_allocation_table{
    uint16_t *fat_entries;
    int num_entries;
}__attribute__((packed));
typedef struct file_allocation_table fat_t;

struct file {
    char filename[FS_FILENAME_LEN];
    uint32_t size;
    uint16_t first_db_index;
    uint8_t unused[10];
} __attribute__((packed));
typedef struct file file_t;

struct rootdir {
    file_t *file_list;
    int num_files;
}__attribute__((packed));
typedef struct rootdir rootdir_t;

struct file_descriptor{
    char filename[FS_FILENAME_LEN];
    size_t offset; 
};
typedef struct file_descriptor fd_t;

superblock_t *superblock = NULL;
rootdir_t rootdir;
fat_t fat;
fd_t *file_desc = NULL;
int open_files;

int fs_mount(const char *diskname)
{
    if(block_disk_open(diskname) == -1) return -1;
    superblock = (superblock_t *)malloc(sizeof(struct superblock));
    if(block_read(0, superblock) == -1 || strncmp(superblock->sig, "ECS150FS", 8) != 0 || block_disk_count() != superblock->disk_num_blocks ) return -1;
    fat.fat_entries = malloc(superblock->num_fat*BLOCK_SIZE);
    int index = 0;
    for (int i = 1; i <= superblock->num_fat; i++) {
        if (block_read(i, &fat.fat_entries[index]) == -1) return -1;
        if (i==1 && fat.fat_entries[0] != 0xFFFF) return -1;
        index += NUM_FAT_ENTRIES_BLOCK; 
    }     
    fat.num_entries = 0;
    for (int i = 0; i <= superblock->num_data; i++){
        if (fat.fat_entries[i]){
            fat.num_entries++;
        } 
    }
    rootdir.file_list = malloc(FS_FILE_MAX_COUNT*sizeof(file_t));
    if (block_read(superblock->rootdir_index, rootdir.file_list) == -1) return -1;
    rootdir.num_files = 0;
    for(int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (rootdir.file_list[i].filename[0] != 0)
            rootdir.num_files++;
    }  
    open_files = 0;
    file_desc = (fd_t*)malloc(sizeof(fd_t)*FS_OPEN_MAX_COUNT);
    return 0;
}

int fs_umount(void)
{
    if (!superblock) return -1;
    for (int i = 0; i < FS_OPEN_MAX_COUNT; i++)
        if (strlen(file_desc[i].filename) > 0) return -1;
    
    if (block_write(superblock->rootdir_index, rootdir.file_list) == -1) return -1;

    int index = 0;
    for (int i = 1; i <= superblock->num_fat; i++) {
        if (block_write(i, &fat.fat_entries[index]) == -1) return -1;
        index += NUM_FAT_ENTRIES_BLOCK; 
    }
    free(superblock);
    free(fat.fat_entries);
    free(rootdir.file_list);
    free(file_desc);
    rootdir.num_files = 0;
    fat.num_entries = 0;

    if (block_disk_close() == -1) return -1;
    return 0;
}

int fs_info(void)
{
    if (!superblock) return -1;
    printf("FS Info:\n");
    printf("total_blk_count=%d\n",superblock->disk_num_blocks);
    printf("fat_blk_count=%d\n",superblock->num_fat);
    printf("rdir_blk=%d\n",superblock->rootdir_index);
    printf("data_blk=%d\n",superblock->data_index );
    printf("data_blk_count=%d\n",superblock->num_data );
    printf("fat_free_ratio=%d/%d\n", superblock->num_data - fat.num_entries, superblock->num_data);
    printf("rdir_free_ratio=%d/%d\n", FS_FILE_MAX_COUNT - rootdir.num_files, FS_FILE_MAX_COUNT);
    return 0;
}

int fs_create(const char *filename)
{
    if (strlen(filename) >= FS_FILENAME_LEN || filename[strlen(filename)]!= '\0'|| rootdir.num_files == FS_FILE_MAX_COUNT) return -1;
    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (strncmp(filename, rootdir.file_list[i].filename, FS_FILENAME_LEN) == 0) return -1;
    }
    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
       if (rootdir.file_list[i].filename[0] == 0){
            memcpy(rootdir.file_list[i].filename, filename, FS_FILENAME_LEN);
            rootdir.file_list[i].first_db_index = 0xFFFF;
            rootdir.file_list[i].size = 0;
            rootdir.num_files++;
            break;
       }      
    }
    return 0;
}

int fs_delete(const char *filename)
{
    if (strlen(filename) >= FS_FILENAME_LEN || filename[strlen(filename)]!= '\0' || rootdir.num_files == 0) return -1;

    file_t *file_delete = NULL;
    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (strncmp(filename, rootdir.file_list[i].filename, FS_FILENAME_LEN) == 0){
            for (int i = 0; i < FS_OPEN_MAX_COUNT; i++){
                if (strncmp(file_desc[i].filename, filename, FS_FILENAME_LEN) == 0) return -1;
            }
            file_delete = &rootdir.file_list[i];
        }
    }
    if (!file_delete) return -1;
    if (fat.fat_entries[file_delete->first_db_index] != 0xFFFF){
        fat.num_entries--;
        int current_entry = file_delete->first_db_index;
        for (; fat.fat_entries[current_entry] != 0xFFFF; current_entry = fat.fat_entries[current_entry])
        {
            fat.fat_entries[current_entry] = 0;
            fat.num_entries--;
        }   
        fat.fat_entries[current_entry] = 0;
    }
    memset(file_delete, 0, sizeof(file_t));
    rootdir.num_files--;
    return 0;
}

int fs_ls(void)
{
    if (!superblock) return -1;
    printf("FS Ls:\n");
    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (rootdir.file_list[i].filename[0] != 0)
        {
            printf("file: %s, ",rootdir.file_list[i].filename);
            printf("size: %d, ",rootdir.file_list[i].size);
            printf("data_blk: %d\n",rootdir.file_list[i].first_db_index);
        }
    }
    return 0;
}

int fs_open(const char *filename)
{
    if (strlen(filename) >= FS_FILENAME_LEN || filename[strlen(filename)]!= '\0' || open_files == FS_OPEN_MAX_COUNT) return -1;

    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (strncmp(filename, rootdir.file_list[i].filename, FS_FILENAME_LEN) == 0){
            for (int i = 0; i < FS_OPEN_MAX_COUNT; i++){
                if (strlen(file_desc[i].filename) == 0) {
                    strncpy(file_desc[i].filename, filename, FS_FILENAME_LEN);
                    open_files++;
                    return i;
                }
            } 
        }
    }
    return -1;    
}

int fs_close(int fd)
{
    if (fd >= FS_OPEN_MAX_COUNT || fd < 0 || strlen(file_desc[fd].filename) == 0) return -1;
    file_desc[fd].filename[0] = 0;
    file_desc[fd].offset = 0;
    open_files--;
    return 0;
}

int fs_stat(int fd)
{
    if (fd >= FS_OPEN_MAX_COUNT || fd < 0) return -1;
    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (strncmp(file_desc[fd].filename, rootdir.file_list[i].filename, FS_FILENAME_LEN) == 0){
            return rootdir.file_list[i].size;
        }
    }
    return -1;
}

int fs_lseek(int fd, size_t offset)
{
    if (fd >= FS_OPEN_MAX_COUNT || fd < 0) return -1;
    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (strncmp(file_desc[fd].filename, rootdir.file_list[i].filename, FS_FILENAME_LEN) == 0 && offset <= rootdir.file_list[i].size){
            file_desc[fd].offset = offset;
            return 0;
        }     
    }
    return -1;
}

int num_new_blocks(int fd, size_t count){

    int val1 = count + file_desc[fd].offset + BLOCK_SIZE -1;
    val1 /= BLOCK_SIZE;
    int val2 = fs_stat(fd) + BLOCK_SIZE -1;
    val2 /= BLOCK_SIZE;
    val1 -= val2;
    return val1;
}

int fs_write(int fd, void *buf, size_t count)
{

    if (fd >= FS_OPEN_MAX_COUNT || fd < 0) return -1;

    int index = -1;
    int i = 0;
    while(index == -1 && i < FS_FILE_MAX_COUNT){
        if (strncmp(file_desc[fd].filename, rootdir.file_list[i].filename, FS_FILENAME_LEN) == 0){
            index = i;
        } 
        i++;
    }
    if (index == -1) return -1;

    int new_blocks = num_new_blocks(fd,count);
    if (new_blocks) {
        int temp = rootdir.file_list[index].first_db_index;
        uint16_t *empty[new_blocks];
        int location[new_blocks];
        if (rootdir.file_list[index].first_db_index != 0xFFFF) {
            rootdir.file_list[index].first_db_index = fat.fat_entries[rootdir.file_list[index].first_db_index];
        }

        int num = 0; 
        int i = 0;
        while(num<new_blocks && i < superblock->num_data){
            if (fat.fat_entries[i]==0) {
                location[num] = i;
                empty[num] = &fat.fat_entries[i];
                num++;
            }
            i++;
        }
        *(empty[new_blocks - 1]) = 0xFFFF;
        i = 0;
        while(i < new_blocks - 1){
            *(empty[i]) = location[i+1];
            i++;
        }
        if (temp != 0xFFFF) 
            fat.fat_entries[temp] = location[0];
        else 
           rootdir.file_list[index].first_db_index = location[0];
        fat.num_entries += new_blocks;
    }
    if (rootdir.file_list[index].size < count + file_desc[fd].offset)
        rootdir.file_list[index].size = count + file_desc[fd].offset;

    size_t bytes = 0;
    size_t offset = file_desc[fd].offset;
    char *buffer = malloc(BLOCK_SIZE);

    for (uint16_t file_index = rootdir.file_list[index].first_db_index; file_index != 0xFFFF && count!=0; file_index = fat.fat_entries[file_index])
    {
        if (BLOCK_SIZE < offset) offset -= BLOCK_SIZE;
        else {
            int space = BLOCK_SIZE - offset;
            
            if (block_read(superblock->data_index + file_index, buffer) == -1) return -1;

            buffer += offset;

            if (count < space) {
                bytes += count;
                count = 0;
                memcpy(buffer, (char*)buf, count);
                file_desc[fd].offset += count;
            } 
            else {
                count -= space;
                bytes += space;
                memcpy(buffer, (char*)buf, space);
                file_desc[fd].offset += space;
            }
            buf += space;
            offset = 0;
            free(buffer);
            char * buffer = malloc(BLOCK_SIZE);
            if (block_write(superblock->data_index + file_index, buffer) == -1) return -1; 
        }

    }
    free(buffer);
    return bytes;
}

int fs_read(int fd, void *buf, size_t count)
{
    if (fd >= FS_OPEN_MAX_COUNT || fd < 0) return -1;

    int index = -1;
    int i = 0;
    while(index == -1 && i < FS_FILE_MAX_COUNT){
        if (strncmp(file_desc[fd].filename, rootdir.file_list[i].filename, FS_FILENAME_LEN) == 0){
            index = i;
        } 
        i++;
    }
    if (index == -1) return -1;

    if (rootdir.file_list[index].first_db_index == 0xFFFF) return 0;

    int bytes = 0;
    size_t offset = file_desc[fd].offset;
    for (uint16_t file_index = rootdir.file_list[index].first_db_index; file_index != 0xFFFF; file_index = fat.fat_entries[file_index])
    {
        char *buffer = malloc(BLOCK_SIZE);
        if (offset > BLOCK_SIZE) offset -= BLOCK_SIZE;
        else {
            if (block_read(superblock->data_index + file_index, buffer) == -1) return -1;
            buffer+= offset;
            int space = BLOCK_SIZE - offset;
            if (count < space) {
                bytes += count;
                file_desc[fd].offset += count;
                memcpy(buf,buffer, count);
                return bytes;
            } 
            else {
                memcpy(buf, buffer, BLOCK_SIZE - offset);
                count -= space;
                bytes += space;
                buf = (char*) buf;
                buf += space;
                file_desc[fd].offset += space;
                offset = 0;
                free(buffer);
            }
        }
    }
    return bytes;
}

