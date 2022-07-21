#include "elf_util.h"

#include <elf.h>
#include <fcntl.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_SIZE 2048
#define PLT_ENTRY_SIZE 16
#define SIZE_JMP 2
#define INST_SIZE 6
#define ADDR_SIZE 8

/* Getting the index of PT_NOTE */
void get_ptnote(inject_t *data) {
  size_t nbr_header = data->ehdr->e_phnum;

  data->index_ptnote = -1;
  for (size_t i = 0; i < nbr_header; i++) {
    if (data->phdr[i].p_type == PT_NOTE) {
      data->index_ptnote = i;
      data->ptnote = data->phdr + i;
      break;
    }
  }
}

/* Inject code at the end of the binary */
int inject_code(inject_t *data, const char *path, bool add_entry) {
  /* Moving at the end of the binary */
  data->off = lseek(data->fd, 0, SEEK_END);
  if (data->off == -1) {
    perror("lseek:");
    return -1;
  }

  /* Add fake RIP */
  if (add_entry) {
    if (write(data->fd, "\x49\xba", 2) == -1) {
      perror("");
      return -1;
    }
    if (write(data->fd, &data->ehdr->e_entry, 4) == -1) {
      perror("");
      return -1;
    }
    if (write(data->fd, "\x00\x00\x00\x00\x41\x52", 6) == -1) {
      perror("");
      return -1;
    }
  }

  /* Injecting code into binary */
  char buffer[BUFFER_SIZE] = {0};
  size_t i = 0;
  int code_fd = open(path, O_RDONLY);

  do {
    size_t i = read(code_fd, buffer, BUFFER_SIZE);
    if (i == (size_t)-1) {
      close(code_fd);
      perror("inject code file");
      return -1;
    }

    if (write(data->fd, buffer, i) == (ssize_t)-1) {
      close(code_fd);
      perror("Failed to inject");
      return -1;
    }
    data->size += i;
  } while (i == BUFFER_SIZE && buffer[BUFFER_SIZE - 1] != EOF);

  if (close(code_fd) == -1) {
    perror("");
    return -1;
  }

  return 0;
}

/* Inject the new section header */
int inject_shdr(inject_t *data) {
  char *section_name;
  size_t index_section;
  data->scn = NULL;

  while ((data->scn = elf_nextscn(data->e, data->scn))) {
    /* Get section header */
    if ((data->shdr = elf64_getshdr(data->scn)) == NULL) {
      (void)fputs(elf_errmsg(-1), stderr);
      return -1;
    }

    /* Obtain a pointer to a string in the .shstrtab section */
    if ((section_name = elf_strptr(data->e, data->index_shstrtab,
                                   data->shdr->sh_name)) == NULL) {
      (void)fputs(elf_errmsg(-1), stderr);
      return -1;
    }

    /* Check if name is equal to .note.ABi-tag */
    if (!strcmp(section_name, MODIFIED_SECTION)) {
      data->shdr->sh_type = SHT_PROGBITS;
      data->shdr->sh_addr = data->addr;
      data->shdr->sh_offset = data->off;
      data->shdr->sh_size = data->size;
      data->shdr->sh_addralign = 16;
      data->shdr->sh_flags = data->shdr->sh_flags | SHF_EXECINSTR;

      index_section = elf_ndxscn(data->scn);

      /* Going to offset of section header */
      if (lseek(data->fd,
                data->ehdr->e_shoff + (index_section * data->ehdr->e_shentsize),
                SEEK_SET) == -1) {
        perror("");
        return -1;
      }

      /* Injecting new section header */
      if (write(data->fd, (void *)data->shdr, data->ehdr->e_shentsize) == -1) {
          perror("");
          return -1;
      }

      break;
    }
  }

  if (data->scn == NULL) {
      (void)fputs("Can't find a section to rewrite\n", stdout);
      return -1;
  }
  return 0;
}

/* Compute the new position where we need to put a Section Header */
int compute_newndx(inject_t *data, Elf64_Shdr *shdr) {
  Elf64_Shdr *other_shdr;
  Elf_Scn *other_scn = NULL;
  size_t index = 0;
  while ((other_scn = elf_nextscn(data->e, other_scn))) {
    if ((other_shdr = elf64_getshdr(other_scn)) == NULL) {
      (void)fputs(elf_errmsg(-1), stderr);
      return -1;
    }
    if (other_shdr->sh_addr == 0) {
      break;
    }
    if (shdr->sh_addr < other_shdr->sh_addr)
      break;
    index++;
  }
  return (index == 0) ? 1 : index;
}

/* Allow to swap two section header
 *
 * e: the Elf file
 * fd: A file descriptor to the file
 * base: index of the base header
 * dest: index of the destination header
 * */
int move_shdr(Elf *e, int fd, size_t base, size_t dest) {
  if (dest == base)
    return 0;

  Elf_Scn *base_scn;
  if ((base_scn = elf_getscn(e, base)) == NULL)
    return -1;
  Elf64_Shdr *base_shdr;
  if ((base_shdr = elf64_getshdr(base_scn)) == NULL)
    return -1;
  Elf64_Ehdr *ehdr;
  if ((ehdr = elf64_getehdr(e)) == NULL)
    return -1;

  int type = dest >= base ? 1 : -1;

  for(int i = 0; i < abs((int)(dest - base)); i++) {
    int index = base + ((i+1) * type);
    Elf_Scn *moving_scn;
    if ((moving_scn = elf_getscn(e, index)) == NULL)
        return -1;
    Elf64_Shdr *moving_shdr;
    if ((moving_shdr = elf64_getshdr(moving_scn)) == NULL)
      return -1;

    int dest_index = base + (i * type);
    if (lseek(fd, ehdr->e_shoff + (dest_index * ehdr->e_shentsize), SEEK_SET) == -1)
      return -1;

    if (write(fd, moving_shdr, sizeof(Elf64_Shdr)) == -1)
      return -1;
  }

  if (lseek(fd, ehdr->e_shoff + (dest * ehdr->e_shentsize), SEEK_SET) == -1)
    return -1;

  if (write(fd, base_shdr, sizeof(Elf64_Shdr)) == -1)
    return -1;

  return 0;
}

/* Inject new section name */
int inject_scnname(inject_t *data, const char *name) {
  size_t off_base = data->shdr->sh_name;
  Elf_Scn *scn = elf_getscn(data->e, data->index_shstrtab);
  if (scn == NULL) {
    (void)fputs(elf_errmsg(-1), stderr);
    return -1;
  }
  Elf64_Shdr *shdr = elf64_getshdr(scn);
  if (shdr == NULL) {
    (void)fputs(elf_errmsg(-1), stderr);
    return -1;
  }
  size_t off_str = shdr->sh_offset;

  if (lseek(data->fd, off_base + off_str, SEEK_SET) == -1) {
    perror("");
    return -1;
  }

  size_t len_str = strlen(name);
  if (write(data->fd, name, len_str) == -1) {
    perror("");
    return -1;
  }

  if (write(data->fd, "\0", 1) == -1) {
    perror("");
    return -1;
  }

  return 0;
}

/* Overwrite the PT_NOTE program header */
int update_ptnote(inject_t *data) {
  data->ptnote->p_type = PT_LOAD;
  data->ptnote->p_offset = data->off;
  data->ptnote->p_vaddr= data->addr;
  data->ptnote->p_paddr= data->addr;
  data->ptnote->p_filesz = data->size;
  data->ptnote->p_memsz = data->size;
  data->ptnote->p_align = 0x1000;
  data->ptnote->p_flags = PF_R | PF_X;

  /* Seek to offset of PT_NOTE */
  if (lseek(data->fd,
            data->ehdr->e_phoff + data->index_ptnote * data->ehdr->e_phentsize,
            SEEK_SET) == -1) {
    perror("");
    return -1;
  }

  /* Overwriting PT_NOTE program header */
  if (write(data->fd, data->ptnote,
            data->ehdr->e_phentsize) == -1) {
    perror("");
    return -1;
  }

  return 0;
}

/* Change the entrypoint */
int update_entrypoint(inject_t *data) {
  data->entry_bak = data->ehdr->e_entry;
  data->ehdr->e_entry = data->addr;
  if (lseek(data->fd, 0, SEEK_SET) == -1) {
    perror("");
    return -1;
  }
  if (write(data->fd, data->ehdr, sizeof(Elf64_Ehdr)) == -1) {
    perror("");
    return -1;
  }
  return 0;
}

/* Search a section addr in the binary from his name */
static Elf64_Shdr *addr_section(inject_t *data, const char *name) {
  Elf_Scn *scn = NULL;
  Elf64_Shdr *shdr;
  char *section_name;
  while ((scn = elf_nextscn(data->e, scn))) {
    /* Get section header */
    if ((shdr = elf64_getshdr(scn)) == NULL) {
      (void)fputs(elf_errmsg(-1), stderr);
      return NULL;
    }

    /* Obtain a pointer to a string in the .shstrtab section */
    if ((section_name = elf_strptr(data->e, data->index_shstrtab,
                                   shdr->sh_name)) == NULL) {
      (void)fputs(elf_errmsg(-1), stderr);
      return NULL;
    }
    /* Check if name is equal to *name* */
    if (!strcmp(section_name, name)) {
      return shdr;
    }
  }
  return NULL;
}

/* Find the .got.plt address of func with a given name */
static long find_func(inject_t *data, const char *name) {
  int max = data->rela->sh_size / sizeof(Elf64_Rela);
  Elf64_Rela rela_entries[max];
  Elf64_Sym sym_entries[data->dynsym->sh_size / sizeof(Elf64_Sym)];

    /* Read the .rel.dyn */
    if (lseek(data->fd, data->rela->sh_offset, SEEK_SET) == -1) {
      perror("");
      return -1;
    }

    if (read(data->fd, &rela_entries, sizeof(Elf64_Rela) * max) == -1) {
      perror("");
      return -1;
    }

    /* Read the .dynsym */
    if (lseek(data->fd, data->dynsym->sh_offset, SEEK_SET) == -1) {
      perror("");
      return -1;
    }

    if (read(data->fd, &sym_entries, sizeof(Elf64_Sym) * max) == -1) {
      perror("");
      return -1;
    }

    for (int i = 0; i < max; i++) {
      char actual_name[256];
      int index = ELF64_R_SYM(rela_entries[i].r_info);

      /* Read the name */
      if (lseek(data->fd, data->dynstr->sh_offset + sym_entries[index].st_name,
                SEEK_SET) == -1) {
        perror("");
        return -1;
      }

      size_t j = 0;
      while (1) {
        if (j >= 256) {
          (void)fputs("Error: func name abnormally long in .dynstr\n", stderr);
          return -1;
        }
        if (read(data->fd, actual_name + j, 1) == -1) {
          perror("");
          return -1;
        }
        if (actual_name[j] == 0)
          break;
        j++;
      }

    if (!strcmp(name, actual_name)) {
      return rela_entries[i].r_offset;
    }
  }
  return -1;
}

/* Overwrite the PLT */
int update_plt(inject_t *data, const char *funcName) {
  if ((data->dynsym = addr_section(data, ".dynsym")) == NULL) {
    (void)fputs("Error: Can't find .dynsym section.\n", stderr);
    return -1;
  }
  if ((data->dynstr = addr_section(data, ".dynstr")) == NULL) {
    (void)fputs("Error: Can't find .dynstr section.\n", stderr);
    return -1;
  }

  if ((data->rela = addr_section(data, ".rela.plt")) == NULL) {
    (void)fputs("error: can't find .got.plt section.\n", stderr);
    return -1;
  }

  if ((data->got = addr_section(data, ".got.plt")) == NULL) {
    (void)fputs("error: can't find .got.plt section.\n", stderr);
    return -1;
  }

  if ((data->func_addr =  find_func(data, funcName)) == -1) {
    (void)fputs("Error: Can't find function.\n", stderr);
    return -1;
  }

  long off = data->func_addr - data->got->sh_addr + data->got->sh_offset;
  if (lseek(data->fd, off, SEEK_SET) == -1) {
    perror("");
    return -1;
  }

  if (write(data->fd, &data->shdr->sh_addr, 4) == -1) {
    perror("");
    return -1;
  }

  return 0;
}
