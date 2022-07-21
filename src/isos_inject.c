#include <argp.h>
#include <elf.h>
#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elf_util.h"

#define MANDATORY_ARGS 5
#define OPTIONAL_ARGS 0
#define DEFAULT_FUNCTION "fputc"

#define LOG(msg) printf("%-40s", msg); (void)fflush(stdout)
#define OK() (void)fputs(" [OK]\n", stdout)
#define ERROR() (void)fputs(" [ERROR]\n", stdout)

/* Structure to store all the given arguments */
struct arguments {
  char *path[2];
  char *section_name;
  int64_t addr;
  bool modify_entry;
  char *function;
};

const char *argp_program_version = "isos_inject 0.1";

/* Argument parsing function for argp */
static int parse_opt(int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;
  switch (key) {
    case 'f':
      arguments->function = arg;
      break;

    case ARGP_KEY_ARG:
      if (state->arg_num >= MANDATORY_ARGS)
        argp_usage(state);

      if (state->arg_num < 2) {
        arguments->path[state->arg_num] = arg;
      } else if (state->arg_num == 2) {
        arguments->section_name = arg;
      } else if (state->arg_num == 3) {
        arguments->addr = strtol(arg, NULL, 16);
        if (arguments->addr == 0)
          errx(EXIT_FAILURE, "invalid address provided");
        if (arguments->addr == LONG_MIN || arguments->addr == LONG_MAX)
          errx(EXIT_FAILURE, "invalid address provided");
      } else {
        if (strcmp("false", arg) == 0)
          arguments->modify_entry = false;
        else
          arguments->modify_entry = true;
      }
      break;

    /* If end of argument && not enought args */
    case ARGP_KEY_END:
      if (state->arg_num < MANDATORY_ARGS)
        argp_usage(state);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

int main(int argc, char *argv[]) {
  int res;
  const char args_doc[] = "file code_file section addr modifyEntry";
  const char doc[] = "Isos_inject -- injecting code into binaries";
  const struct argp_option options[] = {
      /*{0, 'd', 0, 0, "Show a dot on the screen", 0},*/
      {"function", 'f', "FUNCTION", 0,
       "change the default function to override in PLT", 0},
      {0}};
  const struct argp argp = {options, parse_opt, args_doc, doc, 0, 0, 0};
  struct arguments arguments;
  arguments.function = DEFAULT_FUNCTION;
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  inject_t inject_data = {0};

  /* Check len of section */
  LOG("Checking len of section...");
  if (strlen(arguments.section_name) > strlen(MODIFIED_SECTION)) {
    ERROR();
    (void)fputs("section name is too long\n", stderr);
    goto err1;
  }
  OK();

  /* Checking ELF version */
  LOG("Checking elf version...");
  if (elf_version(EV_CURRENT) == EV_NONE) {
    ERROR();
    (void)fputs(elf_errmsg(-1), stderr);
    res = EXIT_FAILURE;
    goto end;
  }
  OK();

  /* Opening ELF file */
  LOG("Opening ELF file...");
  if ((inject_data.fd = open(arguments.path[0], O_RDWR, 0)) < 0) {
    perror("can't open binary");
    ERROR();
  }
  OK();

  /* Parsing ELF file */
  LOG("Parsing ELF file...");
  if ((inject_data.e = elf_begin(inject_data.fd, ELF_C_READ, NULL)) == NULL) {
    ERROR();
    (void)fputs(elf_errmsg(-1), stderr);
    goto err1;
  }
  OK();

  /* Checking ELF type */
  LOG("Checking ELF type...");
  inject_data.ek = elf_kind(inject_data.e);
  if (inject_data.ek != ELF_K_ELF) {
    ERROR();
    (void)fputs("file provided isn't an ELF file\n", stderr);
    goto err1;
  }
  OK();

  /* Getting ELF Header */
  LOG("Getting ELF Header...");
  if ((inject_data.ehdr = elf64_getehdr(inject_data.e)) == NULL) {
    ERROR();
    (void)fputs(elf_errmsg(-1), stderr);
    goto err1;
  }
  OK();

  /* Getting ELF Program Headers */
  LOG("Getting ELF Program Headers...");
  if ((inject_data.phdr = elf64_getphdr(inject_data.e)) == NULL) {
      ERROR();
      (void)fputs(elf_errmsg(-1), stderr);
      goto err1;
    }
  OK();

  /* Getting PT_NOTE index */
  LOG("Getting PT_NOTE Program Header...");
  get_ptnote(&inject_data);
  if (inject_data.index_ptnote == -1) {
    ERROR();
    (void)fputs("Unable to find PT_NOTE Header\n", stderr);
    goto err1;
  }
  OK();

  /* Injected code into binary */
  LOG("Injecting code into binary...");
  if (inject_code(&inject_data, arguments.path[1], arguments.modify_entry) == -1) {
    ERROR();
    goto err1;
  }
  OK();

  /* Modifying adress */
  inject_data.addr = arguments.addr;
  inject_data.addr += (inject_data.off % 4096) - (arguments.addr % 4096);
  printf("Address injected: 0x%lx\n", inject_data.addr);

  /* Searching index of .shstrtab */
  LOG("Getting index .shstratab...");
  if (elf_getshdrstrndx(inject_data.e, &inject_data.index_shstrtab) == -1) {
    ERROR();
    (void)fputs(elf_errmsg(-1), stderr);
    goto err1;
  }
  OK();

  /* Injecting new section header into binary */
  LOG("Injecting new section header...");
  if (inject_shdr(&inject_data) == -1) {
    ERROR();
    goto err1;
  }
  OK();

  /* Compute new position we need to put our section */
  LOG("Computing new position of section...");
  int tmp;
  if ((tmp = compute_newndx(&inject_data, inject_data.shdr)) < 0) {
    ERROR();
    goto err1;
  }
  inject_data.index = tmp;
  OK();

  /* move the section header to his new position */
  LOG("Sorting section headers...");
  if (move_shdr(inject_data.e, inject_data.fd, elf_ndxscn(inject_data.scn),
                inject_data.index) == -1) {
    ERROR();
    goto err1;
  }
  OK();

  /* Injecting section name */
  LOG("Injecting section name...");
  if (inject_scnname(&inject_data, arguments.section_name) == -1) {
    ERROR();
    goto err1;
  }
  OK();

  /* Overwriting PT_NOTE */
  LOG("Overwriting PT_NOTE...");
  if (update_ptnote(&inject_data) == -1) {
    ERROR();
    goto err1;
  }
  OK();

  if (arguments.modify_entry) {
    /* Overwriting EntryPoint */
    LOG("Overwriting entrypoint...");
    if (update_entrypoint(&inject_data) == -1) {
      ERROR();
      goto err1;
    }
    OK();
  } else {
    /* Overwriting PLT */
    LOG("Overwriting PLT...");
    if (update_plt(&inject_data, arguments.function) == -1) {
      ERROR();
      goto err1;
    }
    OK();
  }

  /* End */
  res = 0;
  goto end;

err1:
  res = EXIT_FAILURE;

end:
  if (inject_data.e != NULL)
    elf_end(inject_data.e);

  if (close(inject_data.fd))
    err(EXIT_FAILURE, "close failed");

  return res;
}
