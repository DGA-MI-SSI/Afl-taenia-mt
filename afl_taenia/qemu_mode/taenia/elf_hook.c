#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
//rename standart types for convenience
#if defined __x86_64 || defined __aarch64__
    #define Elf_Ehdr Elf64_Ehdr
    #define Elf_Shdr Elf64_Shdr
    #define Elf_Sym Elf64_Sym
    #define Elf_Rel Elf64_Rela
    #define ELF_R_SYM ELF64_R_SYM
    #define REL_DYN ".rela.dyn"
    #define REL_PLT ".rela.plt"
#else
    #define Elf_Ehdr Elf32_Ehdr
    #define Elf_Shdr Elf32_Shdr
    #define Elf_Sym Elf32_Sym
    #define Elf_Rel Elf32_Rel
    #define ELF_R_SYM ELF32_R_SYM
    #define REL_DYN ".rel.dyn"
    #define REL_PLT ".rel.plt"
#endif

//==================================================================================================
static int read_header(int d, Elf_Ehdr **header)
{
    *header = (Elf_Ehdr *)malloc(sizeof(Elf_Ehdr));
    if(NULL == *header)
    {
        return errno;
    }

    if (lseek(d, 0, SEEK_SET) < 0)
    {
        free(*header);

        return errno;
    }

    if (read(d, *header, sizeof(Elf_Ehdr)) <= 0)
    {
        free(*header);

        return errno = EINVAL;
    }

    return 0;
}
//--------------------------------------------------------------------------------------------------
static int read_section_table(int d, Elf_Ehdr const *header, Elf_Shdr **table)
{
    size_t size;

    if (NULL == header)
        return EINVAL;

    size = header->e_shnum * sizeof(Elf_Shdr);
    *table = (Elf_Shdr *)malloc(size);
    if(NULL == *table)
    {
        return errno;
    }

    if (lseek(d, (__off_t)(header->e_shoff), SEEK_SET) < 0)
    {
        free(*table);

        return errno;
    }

    if (read(d, *table, size) <= 0)
    {
        free(*table);

        return errno = EINVAL;
    }

    return 0;
}
//--------------------------------------------------------------------------------------------------
static int read_string_table(int d, Elf_Shdr const *section, char const **strings)
{
    if (NULL == section)
        return EINVAL;

    *strings = (char const *)malloc(section->sh_size);
    if(NULL == *strings)
    {
        return errno;
    }

    if (lseek(d, (__off_t)(section->sh_offset), SEEK_SET) < 0)
    {
        free((void *)*strings);

        return errno;
    }

    if (read(d, (char *)*strings, section->sh_size) <= 0)
    {
        free((void *)*strings);

        return errno = EINVAL;
    }

    return 0;
}
//--------------------------------------------------------------------------------------------------
static int read_symbol_table(int d, Elf_Shdr const *section, Elf_Sym **table)
{
    if (NULL == section)
        return EINVAL;

    *table = (Elf_Sym *)malloc(section->sh_size);
    if(NULL == *table)
    {
        return errno;
    }

    if (lseek(d, (__off_t)(section->sh_offset), SEEK_SET) < 0)
    {
        free(*table);

        return errno;
    }

    if (read(d, *table, section->sh_size) <= 0)
    {
        free(*table);

        return errno = EINVAL;
    }

    return 0;
}
//--------------------------------------------------------------------------------------------------
static int section_by_index(int d, size_t const index, Elf_Shdr **section)
{
    Elf_Ehdr *header = NULL;
    Elf_Shdr *sections = NULL;

    *section = NULL;

    if (
        read_header(d, &header) ||
        read_section_table(d, header, &sections)
        )
        return errno;

    if (index < header->e_shnum)
    {
        *section = (Elf_Shdr *)malloc(sizeof(Elf_Shdr));

        if (NULL == *section)
        {
            free(header);
            free(sections);

            return errno;
        }

        memcpy(*section, sections + index, sizeof(Elf_Shdr));
    }
    else
        return EINVAL;

    free(header);
    free(sections);

    return 0;
}
//--------------------------------------------------------------------------------------------------
static int section_by_type(int d, size_t const section_type, Elf_Shdr **section)
{
    Elf_Ehdr *header = NULL;
    Elf_Shdr *sections = NULL;
    size_t i;

    *section = NULL;

    if (
        read_header(d, &header) ||
        read_section_table(d, header, &sections)
        )
        return errno;

    for (i = 0; i < header->e_shnum; ++i)
        if (section_type == sections[i].sh_type)
        {
            *section = (Elf_Shdr *)malloc(sizeof(Elf_Shdr));

            if (NULL == *section)
            {
                free(header);
                free(sections);

                return errno;
            }

            memcpy(*section, sections + i, sizeof(Elf_Shdr));

            break;
        }

    free(header);
    free(sections);

    return 0;
}
//--------------------------------------------------------------------------------------------------
int get_module_base_address(char const *module_filename, void *handle, void **base)
{
    int descriptor;  //file descriptor of shared module
    Elf_Shdr *dynsym = NULL, *strings_section = NULL;
    char const *strings = NULL;
    Elf_Sym *symbols = NULL;
    size_t i, amount;
    Elf_Sym *found = NULL;

    *base = NULL;

    descriptor = open(module_filename, O_RDONLY);

    if (descriptor < 0)
        return errno;

    if (section_by_type(descriptor, SHT_DYNSYM, &dynsym) ||  //get ".dynsym" section
        section_by_index(descriptor, dynsym->sh_link, &strings_section) ||
        read_string_table(descriptor, strings_section, &strings) ||
        read_symbol_table(descriptor, dynsym, &symbols))
    {
        free(strings_section);
        free((void *)strings);
        free(symbols);
        free(dynsym);
        close(descriptor);

        return errno;
    }

    amount = dynsym->sh_size / sizeof(Elf_Sym);

    /* Trick to get the module base address in a portable way:
     *   Find the first GLOBAL or WEAK symbol in the symbol table,
     *   look this up with dlsym, then return the difference as the base address
     */
    for (i = 0; i < amount; ++i)
    {
        switch(ELF32_ST_BIND(symbols[i].st_info)) {
        case STB_GLOBAL:
        case STB_LOCAL:
        case STB_WEAK:
            found = &symbols[i];
            break;
        default: // Not interested in this symbol
            break;
        }
    }
    if(found != NULL)
    {
        const char *name = &strings[found->st_name];
        void *sym = dlsym(handle, name); 
        if(sym != NULL)
            *base = (void*)((size_t)sym - found->st_value);
    }

    free(strings_section);
    free((void *)strings);
    free(symbols);
    free(dynsym);
    close(descriptor);

    return *base == NULL;
}
//--------------------------------------------------------------------------------------------------
void* get_function_address(char const *module_filename, void const *base_addr, char const *name)
{
    int descriptor;  //file descriptor of shared module
    Elf_Shdr *symtab = NULL, *strings_section = NULL;
    char const *strings = NULL;
    Elf_Sym *symbols = NULL;
    size_t i, amount;
    Elf_Sym *found = NULL;

    void *func_addr = NULL;

    descriptor = open(module_filename, O_RDONLY);

    if (descriptor < 0)
        return NULL;

    if (section_by_type(descriptor, SHT_SYMTAB, &symtab) ||  //get ".dynsym" section
        section_by_index(descriptor, symtab->sh_link, &strings_section) ||
        read_string_table(descriptor, strings_section, &strings) ||
        read_symbol_table(descriptor, symtab, &symbols))
    {
        free(strings_section);
        free((void *)strings);
        free(symbols);
        free(symtab);
        close(descriptor);

        return NULL;
    }

    amount = symtab->sh_size / sizeof(Elf_Sym);

    /* Trick to get the module func_addr address in a portable way:
     *   Find the first GLOBAL or WEAK symbol in the symbol table,
     *   look this up with dlsym, then return the difference as the func_addr address
     */
    for (i = 0; i < amount; ++i)
    {
        switch(ELF32_ST_BIND(symbols[i].st_info)) {
        case STB_GLOBAL:
        case STB_LOCAL:
        case STB_WEAK:
            found = &symbols[i];
            break;
        default: // Not interested in this symbol
            break;
        }
        if(found != NULL)
        {
            if (0 == strcmp(&strings[found->st_name], name))
            {
                func_addr = (void*)((size_t)base_addr + found->st_value);
            }
        }
    }
    free(strings_section);
    free((void *)strings);
    free(symbols);
    free(symtab);
    close(descriptor);

    return func_addr;
}
//==================================================================================================
