/* so_util.c -- 共享对象(.so)模块加载和钩子工具
 *
 * Copyright (C) 2021 Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.	See the LICENSE file for details.
 * 
 * 本文件实现了Android共享对象文件的加载、解析、重定位和钩子功能
 * 这是整个加载器系统的核心，负责：
 * - ELF文件的内存映射和解析
 * - 符号表的处理和符号解析
 * - 重定位表的处理
 * - ARM指令的运行时修补和钩子
 * - 动态链接和初始化
 */

#include <vitasdk.h>
#include <kubridge.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "main.h"
#include "dialog.h"
#include "so_util.h"

// PS Vita内核内存块类型定义：用户可执行内存
// 此类型的内存块允许执行代码，用于存放SO文件的代码段
#ifndef SCE_KERNEL_MEMBLOCK_TYPE_USER_RX
#define SCE_KERNEL_MEMBLOCK_TYPE_USER_RX                 (0x0C20D050)
#endif

// ARM分支指令编码结构体
// 用于解析和生成ARM分支(Branch)指令，支持条件分支和带链接的分支
typedef struct b_enc {
	union {
		struct __attribute__((__packed__)) {
			int imm24: 24;       // 24位立即数偏移（有符号）
			unsigned int l: 1;    // 链接标志：0=分支，1=带链接分支(BL)
			unsigned int enc: 3;  // 指令编码：固定为0b101
			unsigned int cond: 4; // 条件码：0b1110表示无条件执行
		} bits;
		uint32_t raw;            // 原始32位指令
	};
} b_enc;

// ARM加载/存储指令编码结构体
// 用于解析和生成ARM的LDR/STR等内存访问指令
typedef struct ldst_enc {
	union {
		struct __attribute__((__packed__)) {
			int imm12: 12;         // 12位立即数偏移
			unsigned int rt: 4;     // 源/目标寄存器编号
			unsigned int rn: 4;     // 基址寄存器编号
			unsigned int bit20_1: 1; // 加载/存储标志：0=存储，1=加载
			unsigned int w: 1;      // 写回标志：0=无写回，1=将地址写回基址寄存器
			unsigned int b: 1;      // 数据宽度：0=字(32位)，1=字节(8位)
			unsigned int u: 1;      // 偏移方向：0=从基址减去偏移，1=加上偏移
			unsigned int p: 1;      // 索引模式：0=后索引，1=预索引
			unsigned int enc: 3;    // 指令编码字段
			unsigned int cond: 4;   // 条件执行码
		} bits;
		uint32_t raw;              // 原始32位指令
	};
} ldst_enc;

// ARM分支指令常量定义
#define B_RANGE ((1 << 24) - 1)                    // 分支指令的最大跳转范围（24位）
#define B_OFFSET(x) (x + 8)                        // 分支偏移修正（ARM流水线效应）
// 分支指令生成宏：从PC跳转到DEST
#define B(PC, DEST) ((b_enc){.bits = {.cond = 0b1110, .enc = 0b101, .l = 0, .imm24 = (((intptr_t)DEST-(intptr_t)PC) / 4) - 2}})
// LDR指令生成宏：从RN+IMM地址加载数据到RT寄存器
#define LDR_OFFS(RT, RN, IMM) ((ldst_enc){.bits = {.cond = 0b1110, .enc = 0b010, .p = 1, .u = (IMM >= 0), .b = 0, .w = 0, .bit20_1 = 1, .rn = RN, .rt = RT, .imm12 = (IMM >= 0) ? IMM : -IMM}})

#define PATCH_SZ 0x10000 // 补丁区域大小：64KB的内存块
static so_module *head = NULL, *tail = NULL; // 模块链表：头指针和尾指针

// Thumb模式函数钩子实现
// 在Thumb指令集函数的入口点安装跳转钩子
// 参数：addr - 目标函数地址，dst - 钩子函数地址
// 返回值：钩子信息结构体
so_hook hook_thumb(uintptr_t addr, uintptr_t dst) {
	so_hook h;
	printf("THUMB HOOK\n"); // 调试输出
	if (addr == 0)
		return;
	
	h.thumb_addr = addr;    // 保存原始Thumb地址（最低位为1）
	addr &= ~1;             // 清除Thumb标志位，获得实际地址
	
	// 处理地址对齐：Thumb指令必须4字节对齐才能安装8字节钩子
	if (addr & 2) {
		uint16_t nop = 0xbf00; // Thumb NOP指令
		kuKernelCpuUnrestrictedMemcpy((void *)addr, &nop, sizeof(nop));
		addr += 2;          // 跳过NOP，使用下一个4字节对齐位置
		printf("THUMB UNALIGNED\n");
	}
	
	h.addr = addr;
	// 构造Thumb钩子指令：LDR PC, [PC] + 目标地址
	h.patch_instr[0] = 0xf000f8df; // LDR PC, [PC] - 从PC位置加载目标地址到PC
	h.patch_instr[1] = dst;        // 目标地址常量
	
	// 备份原始指令并安装钩子
	kuKernelCpuUnrestrictedMemcpy(&h.orig_instr, (void *)addr, sizeof(h.orig_instr));
	kuKernelCpuUnrestrictedMemcpy((void *)addr, h.patch_instr, sizeof(h.patch_instr));

	return h;
}

// ARM模式函数钩子实现
// 在ARM指令集函数的入口点安装跳转钩子
// 参数：addr - 目标函数地址，dst - 钩子函数地址
// 返回值：钩子信息结构体
so_hook hook_arm(uintptr_t addr, uintptr_t dst) {
	printf("ARM HOOK\n"); // 调试输出
	if (addr == 0)
		return;
	uint32_t hook[2];
	so_hook h;
	h.thumb_addr = 0;      // ARM模式没有Thumb地址
	h.addr = addr;
	
	// 构造ARM钩子指令：LDR PC, [PC, #-4] + 目标地址
	h.patch_instr[0] = 0xe51ff004; // LDR PC, [PC, #-4] - 从PC-4位置加载目标地址
	h.patch_instr[1] = dst;        // 目标地址常量
	
	// 备份原始指令并安装钩子
	kuKernelCpuUnrestrictedMemcpy(&h.orig_instr, (void *)addr, sizeof(h.orig_instr));
	kuKernelCpuUnrestrictedMemcpy((void *)addr, h.patch_instr, sizeof(h.patch_instr));

	return h;
}

// 自动检测地址类型并安装相应钩子
// 根据地址的最低位判断是ARM还是Thumb模式
// 参数：addr - 目标函数地址，dst - 钩子函数地址
// 返回值：钩子信息结构体
so_hook hook_addr(uintptr_t addr, uintptr_t dst) {
	if (addr == 0)
		return;
	if (addr & 1)
		return hook_thumb(addr, dst); // 最低位为1：Thumb模式
	else
		return hook_arm(addr, dst);   // 最低位为0：ARM模式
}

// 刷新SO模块的指令缓存
// 确保代码修改被正确写入内存并使指令缓存失效
// 参数：mod - 目标模块
void so_flush_caches(so_module *mod) {
	kuKernelFlushCaches((void *)mod->text_base, mod->text_size);
}

// 内部SO加载函数：从内存中解析和映射ELF文件
// 这是SO加载的核心函数，处理ELF文件的解析和内存映射
// 参数：mod - 模块结构体，so_blockid - 内存块ID，so_data - SO文件数据，load_addr - 加载地址
// 返回值：成功返回0，失败返回负值
int _so_load(so_module *mod, SceUID so_blockid, void *so_data, uintptr_t load_addr) {
	int res = 0;
	uintptr_t data_addr = 0;
	
	// 验证ELF魔数：检查文件是否为有效的ELF格式
	if (memcmp(so_data, ELFMAG, SELFMAG) != 0) {
		res = -1;
		goto err_free_so;
	}

	// 解析ELF文件头和各种表的指针
	mod->ehdr = (Elf32_Ehdr *)so_data;              // ELF文件头
	mod->phdr = (Elf32_Phdr *)((uintptr_t)so_data + mod->ehdr->e_phoff); // 程序头表
	mod->shdr = (Elf32_Shdr *)((uintptr_t)so_data + mod->ehdr->e_shoff); // 节头表

	// 节名字符串表：存储所有节名称的字符串表
	mod->shstr = (char *)((uintptr_t)so_data + mod->shdr[mod->ehdr->e_shstrndx].sh_offset);

	// 遍历程序头表：处理需要加载的段(PT_LOAD类型)
	for (int i = 0; i < mod->ehdr->e_phnum; i++) {
		if (mod->phdr[i].p_type == PT_LOAD) {
			void *prog_data;
			size_t prog_size;

			// 检查是否为可执行段（代码段）
			if ((mod->phdr[i].p_flags & PF_X) == PF_X) {
				// 为代码段分配内存：包括补丁区域、跳转代码等
				// 补丁区域位于期望分配空间的正下方
				mod->patch_size = ALIGN_MEM(PATCH_SZ, mod->phdr[i].p_align);
				SceKernelAllocMemBlockKernelOpt opt;
				memset(&opt, 0, sizeof(SceKernelAllocMemBlockKernelOpt));
				opt.size = sizeof(SceKernelAllocMemBlockKernelOpt);
				opt.attr = 0x1;
				opt.field_C = (SceUInt32)load_addr - mod->patch_size; // 补丁区域地址
				res = mod->patch_blockid = kuKernelAllocMemBlock("rx_block", SCE_KERNEL_MEMBLOCK_TYPE_USER_RX, mod->patch_size, &opt);
				if (res < 0)
					goto err_free_so;

				sceKernelGetMemBlockBase(mod->patch_blockid, &mod->patch_base);
				mod->patch_head = mod->patch_base; // 补丁区域当前分配指针
				
				// 分配代码段内存
				prog_size = ALIGN_MEM(mod->phdr[i].p_memsz, mod->phdr[i].p_align);
				memset(&opt, 0, sizeof(SceKernelAllocMemBlockKernelOpt));
				opt.size = sizeof(SceKernelAllocMemBlockKernelOpt);
				opt.attr = 0x1;
				opt.field_C = (SceUInt32)load_addr;  // 代码段的目标地址
				res = mod->text_blockid = kuKernelAllocMemBlock("rx_block", SCE_KERNEL_MEMBLOCK_TYPE_USER_RX, prog_size, &opt);
				if (res < 0)
					goto err_free_so;

				sceKernelGetMemBlockBase(mod->text_blockid, &prog_data);

				// 更新程序头中的虚拟地址为实际分配的地址
				mod->phdr[i].p_vaddr += (Elf32_Addr)prog_data;

				// 保存代码段信息
				mod->text_base = mod->phdr[i].p_vaddr;
				mod->text_size = mod->phdr[i].p_memsz;
		
				// 使用代码段的填充空间作为代码洞穴(code cave)
				// 字对齐以简化指令区域分配
				mod->cave_size = ALIGN_MEM(prog_size - mod->phdr[i].p_memsz, 0x4);
				mod->cave_base = mod->cave_head = prog_data + mod->phdr[i].p_memsz;
				mod->cave_base = ALIGN_MEM(mod->cave_base, 0x4);
				mod->cave_head = mod->cave_base;
				printf("code cave: %d bytes (@0x%08X).\n", mod->cave_size, mod->cave_base);

				data_addr = (uintptr_t)prog_data + prog_size; // 记录数据段的起始地址
			} else {
				// 处理数据段(非可执行段)
				if (data_addr == 0)
					goto err_free_so;

				// 检查数据段数量是否超过最大限制
				if (mod->n_data >= MAX_DATA_SEG)
					goto err_free_data;

				// 计算数据段所需大小（考虑地址对齐）
				prog_size = ALIGN_MEM(mod->phdr[i].p_memsz + mod->phdr[i].p_vaddr - (data_addr - mod->text_base), mod->phdr[i].p_align);

				// 分配数据段内存（读写权限）
				SceKernelAllocMemBlockKernelOpt opt;
				memset(&opt, 0, sizeof(SceKernelAllocMemBlockKernelOpt));
				opt.size = sizeof(SceKernelAllocMemBlockKernelOpt);
				opt.attr = 0x1;
				opt.field_C = (SceUInt32)data_addr; // 数据段地址
				res = mod->data_blockid[mod->n_data] = kuKernelAllocMemBlock("rw_block", SCE_KERNEL_MEMBLOCK_TYPE_USER_RW, prog_size, &opt);
				if (res < 0)
					goto err_free_text;

				sceKernelGetMemBlockBase(mod->data_blockid[mod->n_data], &prog_data);
				data_addr = (uintptr_t)prog_data + prog_size; // 更新下一段地址

				// 更新虚拟地址为实际地址
				mod->phdr[i].p_vaddr += (Elf32_Addr)mod->text_base;

				mod->data_base[mod->n_data] = mod->phdr[i].p_vaddr;
				mod->data_size[mod->n_data] = mod->phdr[i].p_memsz;
				mod->n_data++; // 增加数据段计数
			}

			// 初始化未映射的内存区域（BSS段等）
			// 分配并清零prog_size - p_filesz部分的内存
			char *zero = malloc(prog_size - mod->phdr[i].p_filesz);
			memset(zero, 0, prog_size - mod->phdr[i].p_filesz);
			kuKernelCpuUnrestrictedMemcpy(prog_data + mod->phdr[i].p_filesz, zero, prog_size - mod->phdr[i].p_filesz);
			free(zero);

			// 复制文件中的实际数据到内存
			kuKernelCpuUnrestrictedMemcpy((void *)mod->phdr[i].p_vaddr, (void *)((uintptr_t)so_data + mod->phdr[i].p_offset), mod->phdr[i].p_filesz);
		}
	}

	// 解析节头表：查找动态链接相关的重要节
	for (int i = 0; i < mod->ehdr->e_shnum; i++) {
		char *sh_name = mod->shstr + mod->shdr[i].sh_name;           // 节名称
		uintptr_t sh_addr = mod->text_base + mod->shdr[i].sh_addr;   // 节的内存地址
		size_t sh_size = mod->shdr[i].sh_size;                      // 节的大小
		
		if (strcmp(sh_name, ".dynamic") == 0) {
			// 动态段：包含动态链接器需要的信息
			mod->dynamic = (Elf32_Dyn *)sh_addr;
			mod->num_dynamic = sh_size / sizeof(Elf32_Dyn);
		} else if (strcmp(sh_name, ".dynstr") == 0) {
			// 动态字符串表：存储符号名称
			mod->dynstr = (char *)sh_addr;
		} else if (strcmp(sh_name, ".dynsym") == 0) {
			// 动态符号表：存储导入/导出符号信息
			mod->dynsym = (Elf32_Sym *)sh_addr;
			mod->num_dynsym = sh_size / sizeof(Elf32_Sym);
		} else if (strcmp(sh_name, ".rel.dyn") == 0) {
			// 数据重定位表：需要重定位的数据引用
			mod->reldyn = (Elf32_Rel *)sh_addr;
			mod->num_reldyn = sh_size / sizeof(Elf32_Rel);
		} else if (strcmp(sh_name, ".rel.plt") == 0) {
			// PLT重定位表：需要重定位的函数调用
			mod->relplt = (Elf32_Rel *)sh_addr;
			mod->num_relplt = sh_size / sizeof(Elf32_Rel);
		} else if (strcmp(sh_name, ".init_array") == 0) {
			// 初始化函数数组：模块加载时需要调用的函数
			mod->init_array = (void *)sh_addr;
			mod->num_init_array = sh_size / sizeof(void *);
		} else if (strcmp(sh_name, ".hash") == 0) {
			// 符号哈希表：用于快速符号查找
			mod->hash = (void *)sh_addr;
		}
	}

	// 验证必需的动态链接信息是否存在
	if (mod->dynamic == NULL ||
		mod->dynstr == NULL ||
		mod->dynsym == NULL ||
		mod->reldyn == NULL ||
		mod->relplt == NULL) {
		res = -2; // 缺少必需的动态链接信息
		goto err_free_data;
	}

	// 解析动态段中的额外信息
	for (int i = 0; i < mod->num_dynamic; i++) {
		switch (mod->dynamic[i].d_tag) {
		case DT_SONAME:
			// 共享对象名称
			mod->soname = mod->dynstr + mod->dynamic[i].d_un.d_ptr;
			break;
		default:
			break;
		}
	}

	sceKernelFreeMemBlock(so_blockid); // 释放原始SO文件数据的内存块

	// 将模块添加到全局模块链表
	if (!head && !tail) {
		head = mod;       // 第一个模块
		tail = mod;
	} else {
		tail->next = mod; // 添加到链表尾部
		tail = mod;
	}

	return 0; // 成功

// 错误处理：释放已分配的内存
err_free_data:
	for (int i = 0; i < mod->n_data; i++)
		sceKernelFreeMemBlock(mod->data_blockid[i]);
err_free_text:
	sceKernelFreeMemBlock(mod->text_blockid);
err_free_so:
	sceKernelFreeMemBlock(so_blockid);

	return res; // 返回错误码
}

// 从内存缓冲区加载SO模块
// 用于加载已经在内存中的SO文件数据
// 参数：mod - 模块结构体，buffer - SO文件数据缓冲区，so_size - 数据大小，load_addr - 加载地址
// 返回值：成功返回0，失败返回负值
int so_mem_load(so_module *mod, void *buffer, size_t so_size, uintptr_t load_addr) {
	SceUID so_blockid;
	void *so_data;

	memset(mod, 0, sizeof(so_module)); // 清空模块结构体

	// 为SO文件数据分配内存块（页对齐）
	so_blockid = sceKernelAllocMemBlock("so block", SCE_KERNEL_MEMBLOCK_TYPE_USER_RW, (so_size + 0xfff) & ~0xfff, NULL);
	if (so_blockid < 0)
		return so_blockid;

	sceKernelGetMemBlockBase(so_blockid, &so_data);
	sceClibMemcpy(so_data, buffer, so_size); // 复制SO数据到内存块
	
	return _so_load(mod, so_blockid, so_data, load_addr); // 调用内部加载函数
}

// 从文件加载SO模块
// 读取SO文件并加载到内存中
// 参数：mod - 模块结构体，filename - SO文件路径，load_addr - 加载地址
// 返回值：成功返回0，失败返回负值
int so_file_load(so_module *mod, const char *filename, uintptr_t load_addr) {
	SceUID so_blockid;
	void *so_data;

	memset(mod, 0, sizeof(so_module)); // 清空模块结构体

	// 打开SO文件
	SceUID fd = sceIoOpen(filename, SCE_O_RDONLY, 0);
	if (fd < 0)
		return fd;

	// 获取文件大小
	size_t so_size = sceIoLseek(fd, 0, SCE_SEEK_END);
	sceIoLseek(fd, 0, SCE_SEEK_SET);

	// 分配内存块存储文件内容
	so_blockid = sceKernelAllocMemBlock("so block", SCE_KERNEL_MEMBLOCK_TYPE_USER_RW, (so_size + 0xfff) & ~0xfff, NULL);
	if (so_blockid < 0)
		return so_blockid;

	sceKernelGetMemBlockBase(so_blockid, &so_data);

	// 读取文件内容到内存
	sceIoRead(fd, so_data, so_size);
	sceIoClose(fd);

	return _so_load(mod, so_blockid, so_data, load_addr); // 调用内部加载函数
}

// 执行SO模块的重定位
// 处理所有需要重定位的符号引用，修正地址偏移
// 参数：mod - 目标模块
// 返回值：成功返回0，失败返回负值
int so_relocate(so_module *mod) {
	// 遍历所有重定位条目（包括数据重定位和PLT重定位）
	for (int i = 0; i < mod->num_reldyn + mod->num_relplt; i++) {
		Elf32_Rel *rel = i < mod->num_reldyn ? &mod->reldyn[i] : &mod->relplt[i - mod->num_reldyn];
		Elf32_Sym *sym = &mod->dynsym[ELF32_R_SYM(rel->r_info)]; // 获取相关符号
		uintptr_t *ptr = (uintptr_t *)(mod->text_base + rel->r_offset);

		int type = ELF32_R_TYPE(rel->r_info);
		switch (type) {
		case R_ARM_ABS32:
			if (sym->st_shndx != SHN_UNDEF)
				*ptr += mod->text_base + sym->st_value;
			break;
		case R_ARM_RELATIVE:
			*ptr += mod->text_base;
			break;
		case R_ARM_GLOB_DAT:
		case R_ARM_JUMP_SLOT:
		{
			if (sym->st_shndx != SHN_UNDEF)
				*ptr = mod->text_base + sym->st_value;
			break;
		}
		default:
			fatal_error("Error unknown relocation type %x\n", type);
			break;
		}
	}

	return 0;
}

uintptr_t so_resolve_link(so_module *mod, const char *symbol) {
	for (int i = 0; i < mod->num_dynamic; i++) {
		switch (mod->dynamic[i].d_tag) {
		case DT_NEEDED:
		{
			so_module *curr = head;
			while (curr) {
				if (curr != mod && strcmp(curr->soname, mod->dynstr + mod->dynamic[i].d_un.d_ptr) == 0) {
					uintptr_t link = so_symbol(curr, symbol);
					if (link)
						return link;
				}
				curr = curr->next;
			}

			break;
		}
		default:
			break;
		}
	}

	return 0;
}

void reloc_err(uintptr_t got0)
{
	// Find to which module this missing symbol belongs
	int found = 0;
	so_module *curr = head;
	while (curr && !found) {
		for (int i = 0; i < curr->n_data; i++)
			if ((got0 >= curr->data_base[i]) && (got0 <= (uintptr_t)(curr->data_base[i] + curr->data_size[i])))
				found = 1;
		
		if (!found)
			curr = curr->next;
	}

	if (curr) {
		// Attempt to find symbol name and then display error
		for (int i = 0; i < curr->num_reldyn + curr->num_relplt; i++) {
			Elf32_Rel *rel = i < curr->num_reldyn ? &curr->reldyn[i] : &curr->relplt[i - curr->num_reldyn];
			Elf32_Sym *sym = &curr->dynsym[ELF32_R_SYM(rel->r_info)];
			uintptr_t *ptr = (uintptr_t *)(curr->text_base + rel->r_offset);

			int type = ELF32_R_TYPE(rel->r_info);
			switch (type) {
				case R_ARM_JUMP_SLOT:
				{
					if (got0 == (uintptr_t)ptr) {
						fatal_error("Unknown symbol \"%s\" (%p).\n", curr->dynstr + sym->st_name, (void*)got0);
					}
					break;
				}
			}
		}
	}

	// Ooops, this shouldn't have happened.
	fatal_error("Unknown symbol \"???\" (%p).\n", (void*)got0);
}

__attribute__((naked)) void plt0_stub()
{
	register uintptr_t got0 asm("r12");
	reloc_err(got0);
}

int so_resolve(so_module *mod, so_default_dynlib *default_dynlib, int size_default_dynlib, int default_dynlib_only) {
	for (int i = 0; i < mod->num_reldyn + mod->num_relplt; i++) {
		Elf32_Rel *rel = i < mod->num_reldyn ? &mod->reldyn[i] : &mod->relplt[i - mod->num_reldyn];
		Elf32_Sym *sym = &mod->dynsym[ELF32_R_SYM(rel->r_info)];
		uintptr_t *ptr = (uintptr_t *)(mod->text_base + rel->r_offset);

		int type = ELF32_R_TYPE(rel->r_info);
		switch (type) {
		case R_ARM_ABS32:
		case R_ARM_GLOB_DAT:
		case R_ARM_JUMP_SLOT:
		{
			if (sym->st_shndx == SHN_UNDEF) {
				int resolved = 0;
				if (!default_dynlib_only) {
					uintptr_t link = so_resolve_link(mod, mod->dynstr + sym->st_name);
					if (link) {
						// debugPrintf("Resolved from dependencies: %s\n", mod->dynstr + sym->st_name);
						if (type == R_ARM_ABS32)
							*ptr += link;
						else
							*ptr = link;
						resolved = 1;
					}
				}

				for (int j = 0; j < size_default_dynlib / sizeof(so_default_dynlib); j++) {
					if (strcmp(mod->dynstr + sym->st_name, default_dynlib[j].symbol) == 0) {
						*ptr = default_dynlib[j].func;
						resolved = 1;
						break;
					}
				}
				
				if (!resolved) {
					void *f = vglGetProcAddress(mod->dynstr + sym->st_name);
					if (f) {
						*ptr = f;
						resolved = 1;
						break;
					}
				}

				if (!resolved) {
					if (type == R_ARM_JUMP_SLOT) {
						printf("Unresolved import: %s\n", mod->dynstr + sym->st_name);
						*ptr = (uintptr_t)&plt0_stub;
					}
					else {
						//printf("Unresolved import: %s\n", mod->dynstr + sym->st_name);
					}
				}
			}

			break;
		}
		default:
			break;
		}
	}

	return 0;
}

int so_resolve_with_dummy(so_module *mod, so_default_dynlib *default_dynlib, int size_default_dynlib, int default_dynlib_only) {
	for (int i = 0; i < mod->num_reldyn + mod->num_relplt; i++) {
		Elf32_Rel *rel = i < mod->num_reldyn ? &mod->reldyn[i] : &mod->relplt[i - mod->num_reldyn];
		Elf32_Sym *sym = &mod->dynsym[ELF32_R_SYM(rel->r_info)];
		uintptr_t *ptr = (uintptr_t *)(mod->text_base + rel->r_offset);

		int type = ELF32_R_TYPE(rel->r_info);
		switch (type) {
		case R_ARM_ABS32:
		case R_ARM_GLOB_DAT:
		case R_ARM_JUMP_SLOT:
		{
			if (sym->st_shndx == SHN_UNDEF) {
				for (int j = 0; j < size_default_dynlib / sizeof(so_default_dynlib); j++) {
					if (strcmp(mod->dynstr + sym->st_name, default_dynlib[j].symbol) == 0) {
						*ptr = &ret0;
						break;
					}
				}
			}

			break;
		}
		default:
			break;
		}
	}

	return 0;
}

void so_initialize(so_module *mod) {
	for (int i = 0; i < mod->num_init_array; i++) {
		if (mod->init_array[i])
			mod->init_array[i]();
	}
}

uint32_t so_hash(const uint8_t *name) {
	uint64_t h = 0, g;
	while (*name) {
		h = (h << 4) + *name++;
		if ((g = (h & 0xf0000000)) != 0)
			h ^= g >> 24;
		h &= 0x0fffffff;
	}
	return h;
}

static int so_symbol_index(so_module *mod, const char *symbol)
{
	if (mod->hash) {
		uint32_t hash = so_hash((const uint8_t *)symbol);
		uint32_t nbucket = mod->hash[0];
		uint32_t *bucket = &mod->hash[2];
		uint32_t *chain = &bucket[nbucket];
		for (int i = bucket[hash % nbucket]; i; i = chain[i]) {
			if (mod->dynsym[i].st_shndx == SHN_UNDEF)
				continue;
			if (mod->dynsym[i].st_info != SHN_UNDEF && strcmp(mod->dynstr + mod->dynsym[i].st_name, symbol) == 0)
				return i;
		}
	}

	for (int i = 0; i < mod->num_dynsym; i++) {
		if (mod->dynsym[i].st_shndx == SHN_UNDEF)
			continue;
		if (mod->dynsym[i].st_info != SHN_UNDEF && strcmp(mod->dynstr + mod->dynsym[i].st_name, symbol) == 0)
			return i;
	}

	return -1;
}

/*
 * alloc_arena: allocates space on either patch or cave arenas, 
 * range: maximum range from allocation to dst (ignored if NULL)
 * dst: destination address
*/
static uintptr_t so_alloc_arena(so_module *so, uintptr_t range, uintptr_t dst, size_t sz) {
	// Is address in range?
	#define inrange(lsr, gtr, range) \
		(((uintptr_t)(range) == (uintptr_t)NULL) || ((uintptr_t)(range) >= ((uintptr_t)(gtr) - (uintptr_t)(lsr))))
	// Space left on block
	#define blkavail(type) (so->type##_size - (so->type##_head - so->type##_base))
	
	// keep allocations 4-byte aligned for simplicity
	sz = ALIGN_MEM(sz, 4);

	if (sz <= (blkavail(patch)) && inrange(so->patch_base, dst, range)) {
		so->patch_head += sz;
		return (so->patch_head - sz);
	} else if (sz <= (blkavail(cave)) && inrange(dst, so->cave_base, range)) {
		so->cave_head += sz;
		return (so->cave_head - sz);
	}

	return (uintptr_t)NULL;
}

static void trampoline_ldm(so_module *mod, uint32_t *dst) {
	uint32_t trampoline[1];
	uint32_t funct[20] = {0xFAFAFAFA};
	uint32_t *ptr = funct;

	int cur = 0;
	int baseReg = ((*dst) >> 16) & 0xF;
	int bitMask = (*dst) & 0xFFFF;

	uint32_t stored = NULL;
	for (int i = 0; i < 16; i++) {
		if (bitMask & (1 << i)) {
			// If the register we're reading the offset from is the same as the one we're writing,
			// delay it to the very end so that the base pointer ins't clobbered
			if (baseReg == i)
				stored = LDR_OFFS(i, baseReg, cur).raw;
			else
				*ptr++ = LDR_OFFS(i, baseReg, cur).raw;
			cur += 4;
		}
	}

	// Perform the delayed load if needed
	if (stored) {
		*ptr++ = stored;
	}

	*ptr++ = 0xe51ff004; // LDR PC, [PC, -0x4] ; jmp to [dst+0x4]
	*ptr++ = dst+1; // .dword <...>	; [dst+0x4]

	size_t trampoline_sz =	((uintptr_t)ptr - (uintptr_t)&funct[0]);
	uintptr_t patch_addr = so_alloc_arena(mod, B_RANGE, B_OFFSET(dst), trampoline_sz);

	if (!patch_addr) {
		fatal_error("Failed to patch LDMIA at 0x%08X, unable to allocate space.\n", dst);
	}
	
	// Create sign extended relative address rel_addr
	trampoline[0] = B(dst, patch_addr).raw;

	kuKernelCpuUnrestrictedMemcpy((void*)patch_addr, funct, trampoline_sz);
	kuKernelCpuUnrestrictedMemcpy(dst, trampoline, sizeof(trampoline));
}

uintptr_t so_symbol(so_module *mod, const char *symbol) {
	int index = so_symbol_index(mod, symbol);
	if (index == -1)
		return NULL;

	return mod->text_base + mod->dynsym[index].st_value;
}

void so_symbol_fix_ldmia(so_module *mod, const char *symbol) {
	// This is meant to work around crashes due to unaligned accesses (SIGBUS :/) due to certain
	// kernels not having the fault trap enabled, e.g. certain RK3326 Odroid Go Advance clone distros.
	// TODO:: Maybe enable this only with a config flag? maybe with a list of known broken functions?
	// Known to trigger on GM:S's "_Z11Shader_LoadPhjS_" - if it starts happening on other places,
	// might be worth enabling it globally.
	
	int idx = so_symbol_index(mod, symbol);
	if (idx == -1)
		return;

	uintptr_t st_addr = mod->text_base + mod->dynsym[idx].st_value;
	for (uintptr_t addr = st_addr; addr < st_addr + mod->dynsym[idx].st_size; addr+=4) {
		uint32_t inst = *(uint32_t*)(addr);
		
		//Is this an LDMIA instruction with a R0-R12 base register?
		if (((inst & 0xFFF00000) == 0xE8900000) && (((inst >> 16) & 0xF) < 13) ) {
			sceClibPrintf("Found possibly misaligned LDMIA on 0x%08X, trying to fix it... (instr: 0x%08X, to 0x%08X)\n", addr, *(uint32_t*)addr, mod->patch_head);
			trampoline_ldm(mod, addr);
		}
	}
}
