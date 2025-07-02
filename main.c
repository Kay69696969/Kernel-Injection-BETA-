#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>


typedef int (*inject_func)(const char*, const char*);

int main() {
    char pkg_name[256];
    char lib_name[256];
    
    printf("Enter target package name: ");
    fgets(pkg_name, sizeof(pkg_name), stdin);
    pkg_name[strcspn(pkg_name, "\n")] = 0; 
    
    printf("Enter target library name: ");
    fgets(lib_name, sizeof(lib_name), stdin);
    lib_name[strcspn(lib_name, "\n")] = 0; 
    
    
    void *handle = dlopen("./libbs_hook.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Error loading library: %s\n", dlerror());
        return 1;
    }
    
   
    inject_func inject = (inject_func)dlsym(handle, "inject");
    if (!inject) {
        fprintf(stderr, "Error finding symbol: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }
    
    
    printf("[+] Injecting into %s (%s)\n", pkg_name, lib_name);
    int result = inject(pkg_name, lib_name);
    
  
    dlclose(handle);
    return result;
}

