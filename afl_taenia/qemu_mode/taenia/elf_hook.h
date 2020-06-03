#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

int get_module_base_address(char const *module_filename, void *handle, void **base);
void* get_function_address(char const *module_filename, void const *module_address, char const *name);
void *elf_hook(char const *library_filename, void const *library_address, char const *function_name, void const *substitution_address);

#ifdef __cplusplus
}
#endif
