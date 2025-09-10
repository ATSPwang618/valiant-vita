/*
 * so_util.h -- 共享对象(SO)加载工具头文件
 * 
 * 本文件定义了用于加载和管理Android共享对象(.so)文件的核心数据结构和函数接口
 * 这是整个加载器系统的核心，负责ELF文件解析、内存映射、符号解析和代码修补
 */

#ifndef __SO_UTIL_H__
#define __SO_UTIL_H__

#include "elf.h"

// 内存对齐宏：将地址x按照align边界对齐
// 使用位运算实现高效的向上对齐计算
#define ALIGN_MEM(x, align) (((x) + ((align) - 1)) & ~((align) - 1))

// 最大数据段数量：ELF文件中可包含的数据段上限
#define MAX_DATA_SEG 4

// 代码钩子结构体
// 用于在运行时修改目标函数的执行流程，实现函数拦截和重定向
typedef struct {
	uintptr_t addr;           // 目标函数的原始地址
	uintptr_t thumb_addr;     // Thumb模式地址（ARM架构相关）
	uint32_t orig_instr[2];   // 原始指令备份：保存被替换的指令
	uint32_t patch_instr[2];  // 补丁指令：用于跳转到新函数的指令
} so_hook;

// 共享对象模块结构体
// 表示一个已加载的.so文件的完整信息，包括内存布局、ELF结构和符号表
typedef struct so_module {
  struct so_module *next;   // 链表指针：指向下一个模块（用于模块链表管理）

  // 内存块ID：VitaSDK内存管理系统分配的块标识符
  SceUID patch_blockid;             // 补丁区域内存块ID
  SceUID text_blockid;              // 代码段内存块ID  
  SceUID data_blockid[MAX_DATA_SEG]; // 数据段内存块ID数组

  // 内存地址：各个段在虚拟内存中的实际地址
  uintptr_t patch_base, patch_head; // 补丁区域的基址和当前指针
  uintptr_t cave_base, cave_head;   // 代码洞穴区域（用于存放跳转代码）
  uintptr_t text_base;              // 代码段基址
  uintptr_t data_base[MAX_DATA_SEG]; // 数据段基址数组

  // 内存大小：各个段的字节大小
  size_t patch_size, cave_size;     // 补丁区域和代码洞穴大小
  size_t text_size;                 // 代码段大小
  size_t data_size[MAX_DATA_SEG];   // 数据段大小数组
  int n_data;                       // 实际数据段数量

  // ELF文件结构指针：指向解析后的ELF各个部分
  Elf32_Ehdr *ehdr;                 // ELF文件头：包含文件基本信息
  Elf32_Phdr *phdr;                 // 程序头表：描述段的加载信息
  Elf32_Shdr *shdr;                 // 节头表：描述节的详细信息

  // 动态链接相关结构
  Elf32_Dyn *dynamic;               // 动态段：包含动态链接信息
  Elf32_Sym *dynsym;                // 动态符号表：导出和导入的符号
  Elf32_Rel *reldyn;                // 动态重定位表：需要重定位的数据引用
  Elf32_Rel *relplt;                // PLT重定位表：需要重定位的函数调用

  // 初始化和符号信息
  int (** init_array)(void);        // 初始化函数数组：模块加载时需要调用的函数
  uint32_t *hash;                   // 符号哈希表：用于快速符号查找

  // 各种表的元素数量
  int num_dynamic;                  // 动态段条目数量
  int num_dynsym;                   // 动态符号数量
  int num_reldyn;                   // 动态重定位条目数量
  int num_relplt;                   // PLT重定位条目数量
  int num_init_array;               // 初始化函数数量

  // 字符串表指针
  char *soname;                     // SO文件名：共享对象的名称
  char *shstr;                      // 节名字符串表：存储节名称
  char *dynstr;                     // 动态字符串表：存储符号名称
} so_module;

// 默认动态库符号结构体
// 用于定义需要从宿主系统提供给加载模块的符号映射
typedef struct {
  char *symbol;                     // 符号名称：函数或变量的名字
  uintptr_t func;                   // 符号地址：对应的本地实现地址
} so_default_dynlib;

// 函数钩子接口：用于拦截和重定向函数调用

// Thumb模式函数钩子
// ARM架构特有：用于钩子Thumb指令集的函数
// 参数：addr - 目标地址，dst - 新函数地址
// 返回值：钩子信息结构体
so_hook hook_thumb(uintptr_t addr, uintptr_t dst);

// ARM模式函数钩子  
// 用于钩子标准ARM指令集的函数
// 参数：addr - 目标地址，dst - 新函数地址
// 返回值：钩子信息结构体
so_hook hook_arm(uintptr_t addr, uintptr_t dst);

// 自动检测模式函数钩子
// 根据地址自动判断是ARM还是Thumb模式并应用相应钩子
// 参数：addr - 目标地址，dst - 新函数地址  
// 返回值：钩子信息结构体
so_hook hook_addr(uintptr_t addr, uintptr_t dst);

// 核心加载和管理函数

// 刷新代码缓存
// 确保修改的代码被正确写入内存并使指令缓存失效
// 参数：mod - 目标模块
void so_flush_caches(so_module *mod);

// 从文件加载SO模块
// 读取SO文件并将其加载到指定内存地址
// 参数：mod - 模块结构体，filename - 文件路径，load_addr - 加载地址
// 返回值：成功返回0，失败返回负值
int so_file_load(so_module *mod, const char *filename, uintptr_t load_addr);

// 从内存加载SO模块
// 从内存缓冲区中加载SO数据
// 参数：mod - 模块结构体，buffer - 内存缓冲区，so_size - 数据大小，load_addr - 加载地址
// 返回值：成功返回0，失败返回负值
int so_mem_load(so_module *mod, void * buffer, size_t so_size, uintptr_t load_addr);

// 执行模块重定位
// 处理所有需要重定位的符号引用，修正地址偏移
// 参数：mod - 目标模块
// 返回值：成功返回0，失败返回负值
int so_relocate(so_module *mod);

// 解析模块符号
// 将模块中的未定义符号与提供的符号库进行链接
// 参数：mod - 目标模块，default_dynlib - 符号库，size_default_dynlib - 符号数量，default_dynlib_only - 是否仅使用默认库
// 返回值：成功返回0，失败返回负值
int so_resolve(so_module *mod, so_default_dynlib *default_dynlib, int size_default_dynlib, int default_dynlib_only);

// 使用虚拟符号解析模块
// 对于找不到的符号，创建虚拟实现以避免链接失败
// 参数：同so_resolve
// 返回值：成功返回0，失败返回负值
int so_resolve_with_dummy(so_module *mod, so_default_dynlib *default_dynlib, int size_default_dynlib, int default_dynlib_only);

// 修复LDMIA指令符号
// 处理特定的ARM汇编指令兼容性问题
// 参数：mod - 目标模块，symbol - 符号名称
void so_symbol_fix_ldmia(so_module *mod, const char *symbol);

// 初始化已加载模块
// 调用模块的初始化函数，完成模块加载过程
// 参数：mod - 目标模块
void so_initialize(so_module *mod);

// 查找模块符号地址
// 根据符号名在模块中查找对应的地址
// 参数：mod - 目标模块，symbol - 符号名称
// 返回值：符号地址，未找到返回0
uintptr_t so_symbol(so_module *mod, const char *symbol);

// 钩子继续执行宏
// 临时恢复原始指令，执行被钩子的函数，然后重新应用钩子
// 这允许在钩子函数中调用原始函数
#define SO_CONTINUE(type, h, ...) ({ \
  kuKernelCpuUnrestrictedMemcpy((void *)h.addr, h.orig_instr, sizeof(h.orig_instr)); \
  kuKernelFlushCaches((void *)h.addr, sizeof(h.orig_instr)); \
  type r = h.thumb_addr ? ((type(*)())h.thumb_addr)(__VA_ARGS__) : ((type(*)())h.addr)(__VA_ARGS__); \
  kuKernelCpuUnrestrictedMemcpy((void *)h.addr, h.patch_instr, sizeof(h.patch_instr)); \
  kuKernelFlushCaches((void *)h.addr, sizeof(h.patch_instr)); \
  r; \
})

#endif
