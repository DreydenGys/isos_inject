#ifndef ELF_UTIL_H_
#define ELF_UTIL_H_

#include <elf.h>
#include <libelf.h>
#include <stdbool.h>

/* This structure all kinds of information usefull for the modification
 * of the binary. */
typedef struct inject_s {
    Elf *e;
    int fd;
    Elf_Kind ek;
    Elf64_Ehdr *ehdr; // Elf Header
    Elf64_Phdr *phdr; // Program Headers
    int index_ptnote; // Index PT_NOTE
    Elf64_Phdr *ptnote; // PT_NOTE Header
    off_t off; // Offset of injected section
    size_t size; // Size of injected section
    long addr; // Modifier address
    size_t index_shstrtab; // Index .shsrtab
    size_t index; // Index of new section
    Elf64_Shdr *shdr; // Section Header(injected)
    Elf_Scn *scn; // Section(injected)

    long entry_bak; // entry point backup(for Entrypoint override)

    Elf64_Shdr *rela; // .rel.dyn(for PLT override)
    Elf64_Shdr *dynstr; // .dynstr(for PLT override)
    Elf64_Shdr *dynsym; // .dynsym(for PLT override)
    Elf64_Shdr *got; // .got.plt(for PLT override)
    long func_addr; // index of func in .got.plt(for PLT override)
} inject_t;

#define MODIFIED_SECTION ".note.ABI-tag"

/* Getting the index of PT_NOTE */
extern void get_ptnote(inject_t *data);

/* Inject code at the end of the binary */
extern int inject_code(inject_t *data, const char *path, bool add_entry);

/* Inject the new section header */
extern int inject_shdr(inject_t *data);

/* Compute the new position where we need to put a Section Header */
extern int compute_newndx(inject_t *data, Elf64_Shdr *shdr);

/* Allow to swap two section header
 *
 * e: the Elf file
 * fd: A file descriptor to the file
 * base: index of the base header
 * dest: index of the destination header
 * */
extern int move_shdr(Elf *e, int fd, size_t base, size_t dest);

/* Inject new section name */
extern int inject_scnname(inject_t *data, const char *name);

/* Overwrite the PT_NOTE program header */
extern int update_ptnote(inject_t *data);

/* Change the entrypoint */
extern int update_entrypoint(inject_t *data);

/* Overwrite the PLT */
extern int update_plt(inject_t *data, const char *funcName);

#endif // ELF_UTIL_H_
