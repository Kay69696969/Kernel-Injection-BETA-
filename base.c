#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/uio.h>
#include <sys/syscall.h>

#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv 310
#endif
#ifndef __NR_process_vm_writev
#define __NR_process_vm_writev 311
#endif

#define TARGET_OFFSET  0x4588BC
#define MAX_ATTEMPTS 3
#define RETRY_DELAY_US 100000

typedef struct {
    void* original_addr;
    void* hooked_addr;
    uint8_t original_bytes[16];
    void* trampoline;
    int is_active;
    pid_t target_pid;
} FunctionHook;

static FunctionHook g_hooks[10]; // Support multiple hooks
static int hook_count = 0;
static pthread_mutex_t hook_mutex = PTHREAD_MUTEX_INITIALIZER;

// Global flag for conditional hooking
static int haha = 1; // Your condition variable

// Custom syscall wrappers
#ifndef SYS_process_vm_readv
ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt,
                        const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags) {
    return syscall(__NR_process_vm_readv, pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}
#endif

#ifndef SYS_process_vm_writev
ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt,
                         const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags) {
    return syscall(__NR_process_vm_writev, pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}
#endif

// Memory operations
int read_memory(pid_t pid, void *remote_addr, void *local_addr, size_t size) {
    struct iovec local_iov = { .iov_base = local_addr, .iov_len = size };
    struct iovec remote_iov = { .iov_base = remote_addr, .iov_len = size };
    
    ssize_t bytes_read = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (bytes_read == (ssize_t)size) {
        return 1;
    }
    
    // Fallback to /proc/pid/mem
    char mem_path[64];
    sprintf(mem_path, "/proc/%d/mem", pid);
    
    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd == -1) return 0;
    
    if (lseek(mem_fd, (off_t)remote_addr, SEEK_SET) == -1) {
        close(mem_fd);
        return 0;
    }
    
    ssize_t result = read(mem_fd, local_addr, size);
    close(mem_fd);
    
    return (result == (ssize_t)size);
}

int write_memory(pid_t pid, void *remote_addr, void *local_addr, size_t size) {
    struct iovec local_iov = { .iov_base = local_addr, .iov_len = size };
    struct iovec remote_iov = { .iov_base = remote_addr, .iov_len = size };
    
    ssize_t bytes_written = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (bytes_written == (ssize_t)size) {
        return 1;
    }
    
    // Fallback to /proc/pid/mem
    char mem_path[64];
    sprintf(mem_path, "/proc/%d/mem", pid);
    
    int mem_fd = open(mem_path, O_WRONLY);
    if (mem_fd == -1) return 0;
    
    if (lseek(mem_fd, (off_t)remote_addr, SEEK_SET) == -1) {
        close(mem_fd);
        return 0;
    }
    
    ssize_t result = write(mem_fd, local_addr, size);
    close(mem_fd);
    
    return (result == (ssize_t)size);
}

void* create_trampoline(pid_t pid, void* original_addr) {
    // Allocate executable memory for trampoline
    void *trampoline = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (trampoline == MAP_FAILED) {
        return NULL;
    }
    
    uint8_t original_bytes[16];
    if (!read_memory(pid, original_addr, original_bytes, 16)) {
        munmap(trampoline, 4096);
        return NULL;
    }
    
    uint8_t *tramp_ptr = (uint8_t*)trampoline;
    
    // Copy original instructions
    memcpy(tramp_ptr, original_bytes, 16);
    tramp_ptr += 16;
    
    // Add jump back to original function + 16
    uint64_t return_addr = (uint64_t)original_addr + 16;
    uint32_t *jump_code = (uint32_t*)tramp_ptr;
    
    // ARM64: ldr x17, #8; br x17; .quad return_addr
    jump_code[0] = 0x58000051;  // ldr x17, #8
    jump_code[1] = 0xD61F0220;  // br x17
    *((uint64_t*)(jump_code + 2)) = return_addr;
    
    // Clear instruction cache
    __builtin___clear_cache(trampoline, (char*)trampoline + 4096);
    
    return trampoline;
}

int find_pid(const char *process_name) {
    char command[256];
    snprintf(command, sizeof(command), "pidof %s", process_name);
    FILE *fp = popen(command, "r");
    if (!fp) return -1;
    
    int pid;
    if (fscanf(fp, "%d", &pid) != 1) {
        pclose(fp);
        return -1;
    }
    pclose(fp);
    return pid;
}

unsigned long find_lib_base(int pid, const char *lib_name) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    
    char line[1024];
    unsigned long base = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, lib_name) && strstr(line, "r-xp")) {
            unsigned long current_base;
            sscanf(line, "%lx-", &current_base);
            
            if (base == 0 || current_base < base) {
                base = current_base;
            }
        }
    }
    fclose(fp);
    
    return base;
}

typedef float (*getCam_t)(void* instance, float s);
static getCam_t original_getCam = NULL;

float new_getCam(void* instance, float s) {
    printf("[HOOK] getCam called with instance=%p, s=%f\n", instance, s);
    
    if (haha) {
        printf("[HOOK] Modifying parameter s from %f to 10.0f\n", s);
        s = 10.0f;
    }
    
    float result = original_getCam(instance, s);
    
    printf("[HOOK] getCam returning %f\n", result);
    return result;
}

int hook_function(pid_t pid, void* target_addr, void* hook_func) {
    pthread_mutex_lock(&hook_mutex);
    
    if (hook_count >= 10) {
        printf("[-] Maximum number of hooks reached\n");
        pthread_mutex_unlock(&hook_mutex);
        return 0;
    }
    
    printf("[+] Hooking function at %p\n", target_addr);
    
    FunctionHook *hook = &g_hooks[hook_count];
    
    if (!read_memory(pid, target_addr, hook->original_bytes, 16)) {
        printf("[-] Failed to read original bytes\n");
        pthread_mutex_unlock(&hook_mutex);
        return 0;
    }
    
    printf("[+] Original bytes: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", hook->original_bytes[i]);
    }
    printf("\n");
    
    hook->trampoline = create_trampoline(pid, target_addr);
    if (!hook->trampoline) {
        printf("[-] Failed to create trampoline\n");
        pthread_mutex_unlock(&hook_mutex);
        return 0;
    }
    
    original_getCam = (getCam_t)hook->trampoline;
    
    uint64_t hook_addr = (uint64_t)hook_func;
    uint32_t jump_code[] = {
        0x58000051,  // ldr x17, #8
        0xD61F0220,  // br x17
        (uint32_t)(hook_addr & 0xFFFFFFFF),         // low 32 bits
        (uint32_t)((hook_addr >> 32) & 0xFFFFFFFF)  // high 32 bits
    };
    
    if (!write_memory(pid, target_addr, jump_code, sizeof(jump_code))) {
        printf("[-] Failed to install hook\n");
        munmap(hook->trampoline, 4096);
        pthread_mutex_unlock(&hook_mutex);
        return 0;
    }
    
    hook->original_addr = target_addr;
    hook->hooked_addr = hook_func;
    hook->target_pid = pid;
    hook->is_active = 1;
    hook_count++;
    
    printf("[+] Hook installed successfully!\n");
    printf("[+] Original function can be called via trampoline at %p\n", hook->trampoline);
    
    pthread_mutex_unlock(&hook_mutex);
    return 1;
}

int unhook_function(void* target_addr) {
    pthread_mutex_lock(&hook_mutex);
    
    for (int i = 0; i < hook_count; i++) {
        FunctionHook *hook = &g_hooks[i];
        if (hook->original_addr == target_addr && hook->is_active) {
            
            printf("[+] Restoring function at %p\n", target_addr);
            
            if (!write_memory(hook->target_pid, target_addr, hook->original_bytes, 16)) {
                printf("[-] Failed to restore original bytes\n");
                pthread_mutex_unlock(&hook_mutex);
                return 0;
            }
            
            if (hook->trampoline) {
                munmap(hook->trampoline, 4096);
            }
            
            hook->is_active = 0;
            printf("[+] Function restored successfully\n");
            
            pthread_mutex_unlock(&hook_mutex);
            return 1;
        }
    }
    
    printf("[-] Hook not found for address %p\n", target_addr);
    pthread_mutex_unlock(&hook_mutex);
    return 0;
}

#define HOOK_FUNCTION(pid, addr, hook_func) hook_function(pid, addr, hook_func)
#define UNHOOK_FUNCTION(addr) unhook_function(addr)

void enable_hook() {
    haha = 1;
    printf("[+] Hook condition enabled\n");
}

void disable_hook() {
    haha = 0;
    printf("[+] Hook condition disabled\n");
}

int is_hook_enabled() {
    return haha;
}

void prompt_for_hook_status() {
    char input;
    printf("\n[+] Do you want to enable the hook at startup? (Y/N): ");
    scanf(" %c", &input);
    
    if (input == 'Y' || input == 'y') {
        enable_hook();
    } else if (input == 'N' || input == 'n') {
        disable_hook();
    } else {
        printf("[-] Invalid input. Defaulting to enabled.\n");
        enable_hook();
    }
}

__attribute__((visibility("default")))
int inject(const char *pkg_name, const char *lib_name) {
    printf("Function Hook Injector by @kay133769\n");
    printf("[+] Targeting %s (%s)\n", pkg_name, lib_name);
    
    // Ask user whether to enable hook at startup
    prompt_for_hook_status();
    
    int target_pid = find_pid(pkg_name);
    if (target_pid == -1) {
        printf("[-] Process not found: %s\n", pkg_name);
        return 1;
    }
    
    printf("[+] Found process PID: %d\n", target_pid);
    
    unsigned long base = find_lib_base(target_pid, lib_name);
    if (!base) {
        printf("[-] Library not found: %s\n", lib_name);
        return 1;
    }
    
    void *target = (void*)(base + TARGET_OFFSET);
    printf("[+] Target address: %p (base: 0x%lx + offset: 0x%x)\n", target, base, TARGET_OFFSET);
    
    if (HOOK_FUNCTION(target_pid, target, new_getCam)) {
        printf("[+] getCam hook installed successfully!\n");
        printf("[+] Hook is currently %s\n", is_hook_enabled() ? "ENABLED" : "DISABLED");
        printf("[+] You can now call enable_hook()/disable_hook() to control behavior\n");
        
        printf("[+] Hook is active. Press Ctrl+C to exit.\n");
        while (1) {
            sleep(1);
        }
        
        UNHOOK_FUNCTION(target);
    }
    
    return 0;
}

__attribute__((visibility("default")))
void toggle_hook() {
    haha = !haha;
    printf("[+] Hook condition toggled to %s\n", haha ? "ENABLED" : "DISABLED");
}

__attribute__((visibility("default")))
void set_hook_condition(int enabled) {
    haha = enabled;
    printf("[+] Hook condition set to %s\n", haha ? "ENABLED" : "DISABLED");
}