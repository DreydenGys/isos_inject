# Code and section injection tools

## Description
The goal of this project is to create a tool that allow us to inject new code sections inside an ELF64 files.

## Installation
After cloning the repository using `git clone https://github.com/DreydenGys/isos_inject` you can easiliy build the project by using the `make` command inside of the root directory.

## Usage
```
➜ ./isos_inject --help                              
Usage: isos_inject [OPTION...] file code_file section addr modifyEntry
Isos_inject -- injecting code into binaries

  -f, --function=FUNCTION    change the default function to override in PLT
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
```

## Demo

### EntryPoint overwriting

``` shell
➜ ./isos_inject date inject .injected 0x300000 true
Checking len of section...               [OK]
Checking elf version...                  [OK]
Opening ELF file...                      [OK]
Parsing ELF file...                      [OK]
Checking ELF type...                     [OK]
Getting ELF Header...                    [OK]
Getting ELF Program Headers...           [OK]
Getting PT_NOTE Program Header...        [OK]
Injecting code into binary...            [OK]
Address injected: 0x300b70
Getting index .shstratab...              [OK]
Injecting new section header...          [OK]
Computing new position of section...     [OK]
Sorting section headers...               [OK]
Injecting section name...                [OK]
Overwriting PT_NOTE...                   [OK]
Overwriting entrypoint...                [OK]

➜ ./date
Je suis trop un hacker
sam. 16 avril 2022 18:13:35 CEST
```

### GOT hijacking

``` shell
➜ ./isos_inject date inject .injected 0x300000 false
Checking len of section...               [OK]
Checking elf version...                  [OK]
Opening ELF file...                      [OK]
Parsing ELF file...                      [OK]
Checking ELF type...                     [OK]
Getting ELF Header...                    [OK]
Getting ELF Program Headers...           [OK]
Getting PT_NOTE Program Header...        [OK]
Injecting code into binary...            [OK]
Address injected: 0x300b70
Getting index .shstratab...              [OK]
Injecting new section header...          [OK]
Computing new position of section...     [OK]
Sorting section headers...               [OK]
Injecting section name...                [OK]
Overwriting PT_NOTE...                   [OK]
Overwriting PLT...                       [OK]

➜ ./date
Je suis trop un hacker
Je suis trop un hacker
Je suis trop un hacker
Je suis trop un hacker
Je suis trop un hacker
Je suis trop un hacker
Je suis trop un hacker
sam.16avril2022181437CEST
```

## Running UBSAN and ASAN
To use the Undefined Behaviour SANitizer and the Adress SANitizer, you need to add the `DEBUG=1` argments to the make commmand line as following: `$make DEBUG=1`. Then you can simply run the progam as usual, any error will printed.
