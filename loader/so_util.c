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

// 从依赖模块中解析符号链接
// 在模块的依赖库中查找指定符号的地址
// 参数：mod - 请求符号的模块，symbol - 符号名称
// 返回值：符号地址，未找到返回0
uintptr_t so_resolve_link(so_module *mod, const char *symbol) {
	// 遍历动态段，查找依赖库信息
	for (int i = 0; i < mod->num_dynamic; i++) {
		switch (mod->dynamic[i].d_tag) {
		case DT_NEEDED:
		{
			// 在已加载的模块链表中查找依赖库
			so_module *curr = head;
			while (curr) {
				// 比较SO名称，排除当前模块自身
				if (curr != mod && strcmp(curr->soname, mod->dynstr + mod->dynamic[i].d_un.d_ptr) == 0) {
					uintptr_t link = so_symbol(curr, symbol);
					if (link)
						return link; // 找到符号，返回地址
				}
				curr = curr->next; // 继续检查下一个模块
			}

			break;
		}
		default:
			break;
		}
	}

	return 0; // 未找到符号
}

// 重定位错误处理函数
// 当无法找到符号时，显示详细的错误信息并终止程序
// 参数：got0 - 发生错误的GOT表地址
void reloc_err(uintptr_t got0)
{
	// 查找这个缺失符号属于哪个模块
	int found = 0;
	so_module *curr = head;
	while (curr && !found) {
		// 检查地址是否在当前模块的数据段范围内
		for (int i = 0; i < curr->n_data; i++)
			if ((got0 >= curr->data_base[i]) && (got0 <= (uintptr_t)(curr->data_base[i] + curr->data_size[i])))
				found = 1;
		
		if (!found)
			curr = curr->next;
	}

	if (curr) {
		// 尝试找到符号名称，然后显示错误信息
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

	// 糟糕，这不应该发生
	fatal_error("Unknown symbol \"???\" (%p).\n", (void*)got0);
}

// PLT0存根函数：处理未解析符号的跳转
// 当程序尝试调用未解析的函数时，会跳转到这里并报告错误
// 使用内联汇编获取GOT表中的地址，然后调用错误处理函数
__attribute__((naked)) void plt0_stub()
{
	register uintptr_t got0 asm("r12"); // r12寄存器包含GOT表地址
	reloc_err(got0); // 调用错误处理函数
}

// 解析SO模块的未定义符号
// 将模块中的未定义符号与提供的符号库进行链接
// 参数：mod - 目标模块，default_dynlib - 默认符号库，size_default_dynlib - 符号库大小，default_dynlib_only - 是否仅使用默认库
// 返回值：成功返回0，失败返回负值
int so_resolve(so_module *mod, so_default_dynlib *default_dynlib, int size_default_dynlib, int default_dynlib_only) {
	// 遍历所有重定位条目（包括数据重定位和PLT重定位）
	for (int i = 0; i < mod->num_reldyn + mod->num_relplt; i++) {
		Elf32_Rel *rel = i < mod->num_reldyn ? &mod->reldyn[i] : &mod->relplt[i - mod->num_reldyn];
		Elf32_Sym *sym = &mod->dynsym[ELF32_R_SYM(rel->r_info)];
		uintptr_t *ptr = (uintptr_t *)(mod->text_base + rel->r_offset);

		int type = ELF32_R_TYPE(rel->r_info);
		switch (type) {
		case R_ARM_ABS32:      // 绝对地址重定位
		case R_ARM_GLOB_DAT:   // 全局数据重定位
		case R_ARM_JUMP_SLOT:  // 函数跳转槽重定位
		{
			if (sym->st_shndx == SHN_UNDEF) { // 未定义符号
				int resolved = 0;
				
				// 首先尝试从依赖模块中解析符号
				if (!default_dynlib_only) {
					uintptr_t link = so_resolve_link(mod, mod->dynstr + sym->st_name);
					if (link) {
						// debugPrintf("Resolved from dependencies: %s\n", mod->dynstr + sym->st_name);
						if (type == R_ARM_ABS32)
							*ptr += link;  // 绝对地址：加上链接地址
						else
							*ptr = link;   // 其他类型：直接设置为链接地址
						resolved = 1;
					}
				}

				// 然后在默认符号库中查找
				for (int j = 0; j < size_default_dynlib / sizeof(so_default_dynlib); j++) {
					if (strcmp(mod->dynstr + sym->st_name, default_dynlib[j].symbol) == 0) {
						*ptr = default_dynlib[j].func; // 设置为默认库中的函数地址
						resolved = 1;
						break;
					}
				}
				
				// 最后尝试从VitaGL中获取OpenGL函数
				if (!resolved) {
					void *f = vglGetProcAddress(mod->dynstr + sym->st_name);
					if (f) {
						*ptr = f;  // 设置为OpenGL函数地址
						resolved = 1;
						break;
					}
				}

				// 如果还是无法解析
				if (!resolved) {
					if (type == R_ARM_JUMP_SLOT) {
						printf("Unresolved import: %s\n", mod->dynstr + sym->st_name);
						*ptr = (uintptr_t)&plt0_stub; // 跳转槽：设置为错误处理存根
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

	return 0; // 成功
}

// 使用虚拟占位符解析SO模块符号
// 对于找不到的符号，使用返回0的虚拟函数避免链接失败
// 参数：mod - 目标模块，default_dynlib - 默认符号库，size_default_dynlib - 符号库大小，default_dynlib_only - 是否仅使用默认库
// 返回值：成功返回0，失败返回负值
int so_resolve_with_dummy(so_module *mod, so_default_dynlib *default_dynlib, int size_default_dynlib, int default_dynlib_only) {
	// 遍历所有重定位条目
	for (int i = 0; i < mod->num_reldyn + mod->num_relplt; i++) {
		Elf32_Rel *rel = i < mod->num_reldyn ? &mod->reldyn[i] : &mod->relplt[i - mod->num_reldyn];
		Elf32_Sym *sym = &mod->dynsym[ELF32_R_SYM(rel->r_info)];
		uintptr_t *ptr = (uintptr_t *)(mod->text_base + rel->r_offset);

		int type = ELF32_R_TYPE(rel->r_info);
		switch (type) {
		case R_ARM_ABS32:      // 绝对地址重定位
		case R_ARM_GLOB_DAT:   // 全局数据重定位
		case R_ARM_JUMP_SLOT:  // 函数跳转槽重定位
		{
			if (sym->st_shndx == SHN_UNDEF) { // 未定义符号
				// 在默认符号库中查找，如果找到就设置为虚拟函数(ret0)
				for (int j = 0; j < size_default_dynlib / sizeof(so_default_dynlib); j++) {
					if (strcmp(mod->dynstr + sym->st_name, default_dynlib[j].symbol) == 0) {
						*ptr = &ret0; // 设置为返回0的虚拟函数
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

	return 0; // 成功
}

// 初始化已加载的SO模块
// 调用模块的初始化函数数组中的所有函数
// 参数：mod - 目标模块
void so_initialize(so_module *mod) {
	// 遍历并调用所有初始化函数
	for (int i = 0; i < mod->num_init_array; i++) {
		if (mod->init_array[i])
			mod->init_array[i](); // 调用初始化函数
	}
}

// 计算符号名的哈希值
// 使用ELF标准的哈希算法计算符号名的哈希值
// 参数：name - 符号名称字符串
// 返回值：32位哈希值
uint32_t so_hash(const uint8_t *name) {
	uint64_t h = 0, g;
	while (*name) {
		h = (h << 4) + *name++;  // 左移4位并加上当前字符
		if ((g = (h & 0xf0000000)) != 0)
			h ^= g >> 24;        // 如果高4位非零，进行异或操作
		h &= 0x0fffffff;         // 清除高4位
	}
	return h;
}

// 根据符号名查找符号在动态符号表中的索引
// 首先使用哈希表加速查找，如果没有哈希表则线性搜索
// 参数：mod - 目标模块，symbol - 符号名称
// 返回值：符号索引，未找到返回-1
static int so_symbol_index(so_module *mod, const char *symbol)
{
	if (mod->hash) {
		// 使用哈希表进行快速查找
		uint32_t hash = so_hash((const uint8_t *)symbol);
		uint32_t nbucket = mod->hash[0];      // 哈希桶数量
		uint32_t *bucket = &mod->hash[2];     // 哈希桶数组
		uint32_t *chain = &bucket[nbucket];   // 链表数组
		
		// 在对应的哈希桶中查找符号
		for (int i = bucket[hash % nbucket]; i; i = chain[i]) {
			if (mod->dynsym[i].st_shndx == SHN_UNDEF)
				continue; // 跳过未定义符号
			if (mod->dynsym[i].st_info != SHN_UNDEF && strcmp(mod->dynstr + mod->dynsym[i].st_name, symbol) == 0)
				return i; // 找到匹配的符号
		}
	}

	// 如果没有哈希表或哈希查找失败，进行线性搜索
	for (int i = 0; i < mod->num_dynsym; i++) {
		if (mod->dynsym[i].st_shndx == SHN_UNDEF)
			continue; // 跳过未定义符号
		if (mod->dynsym[i].st_info != SHN_UNDEF && strcmp(mod->dynstr + mod->dynsym[i].st_name, symbol) == 0)
			return i; // 找到匹配的符号
	}

	return -1; // 未找到符号
}

/*
 * 内存区域分配函数：在补丁区域或代码洞穴中分配空间
 * 参数：so - SO模块，range - 与目标地址的最大距离（NULL表示忽略），dst - 目标地址，sz - 所需大小
 * 返回值：分配的地址，失败返回NULL
 */
static uintptr_t so_alloc_arena(so_module *so, uintptr_t range, uintptr_t dst, size_t sz) {
	// 检查地址是否在范围内的宏
	#define inrange(lsr, gtr, range) \
		(((uintptr_t)(range) == (uintptr_t)NULL) || ((uintptr_t)(range) >= ((uintptr_t)(gtr) - (uintptr_t)(lsr))))
	// 计算块中剩余空间的宏
	#define blkavail(type) (so->type##_size - (so->type##_head - so->type##_base))
	
	// 保持4字节对齐，简化分配过程
	sz = ALIGN_MEM(sz, 4);

	// 首先尝试在补丁区域分配
	if (sz <= (blkavail(patch)) && inrange(so->patch_base, dst, range)) {
		so->patch_head += sz;
		return (so->patch_head - sz);
	} 
	// 然后尝试在代码洞穴区域分配
	else if (sz <= (blkavail(cave)) && inrange(dst, so->cave_base, range)) {
		so->cave_head += sz;
		return (so->cave_head - sz);
	}

	return (uintptr_t)NULL; // 分配失败
}

// LDMIA指令跳转代码生成函数
// 为有问题的LDMIA指令生成等价的跳转代码，避免对齐问题
// 参数：mod - SO模块，dst - 目标指令地址
static void trampoline_ldm(so_module *mod, uint32_t *dst) {
	uint32_t trampoline[1];           // 跳转指令缓冲区
	uint32_t funct[20] = {0xFAFAFAFA}; // 替换函数缓冲区
	uint32_t *ptr = funct;

	int cur = 0;                                    // 当前偏移量
	int baseReg = ((*dst) >> 16) & 0xF;            // 基址寄存器编号
	int bitMask = (*dst) & 0xFFFF;                 // 寄存器位掩码

	uint32_t stored = NULL;
	// 遍历位掩码，为每个需要加载的寄存器生成LDR指令
	for (int i = 0; i < 16; i++) {
		if (bitMask & (1 << i)) {
			// 如果读取偏移的寄存器与要写入的寄存器相同，
			// 延迟到最后处理，避免破坏基址指针
			if (baseReg == i)
				stored = LDR_OFFS(i, baseReg, cur).raw;
			else
				*ptr++ = LDR_OFFS(i, baseReg, cur).raw; // 生成LDR指令
			cur += 4; // 更新偏移量
		}
	}

	// 执行延迟的加载操作（如果需要）
	if (stored) {
		*ptr++ = stored;
	}

	*ptr++ = 0xe51ff004; // LDR PC, [PC, -0x4] ; 跳转到[dst+0x4]
	*ptr++ = dst+1;      // .dword <...>	; [dst+0x4]

	size_t trampoline_sz =	((uintptr_t)ptr - (uintptr_t)&funct[0]);
	uintptr_t patch_addr = so_alloc_arena(mod, B_RANGE, B_OFFSET(dst), trampoline_sz);

	if (!patch_addr) {
		fatal_error("Failed to patch LDMIA at 0x%08X, unable to allocate space.\n", dst);
	}
	
	// 创建符号扩展的相对地址 rel_addr
	trampoline[0] = B(dst, patch_addr).raw;

	// 复制跳转代码到分配的空间，并安装跳转指令
	kuKernelCpuUnrestrictedMemcpy((void*)patch_addr, funct, trampoline_sz);
	kuKernelCpuUnrestrictedMemcpy(dst, trampoline, sizeof(trampoline));
}

// 根据符号名获取符号地址
// 在模块的动态符号表中查找指定符号并返回其地址
// 参数：mod - 目标模块，symbol - 符号名称
// 返回值：符号地址，未找到返回NULL
uintptr_t so_symbol(so_module *mod, const char *symbol) {
	int index = so_symbol_index(mod, symbol);
	if (index == -1)
		return NULL; // 未找到符号

	return mod->text_base + mod->dynsym[index].st_value; // 返回符号的绝对地址
}

// 修复符号中的LDMIA指令对齐问题
// 扫描指定符号的代码，查找并修复可能引起对齐问题的LDMIA指令
// 参数：mod - 目标模块，symbol - 符号名称
void so_symbol_fix_ldmia(so_module *mod, const char *symbol) {
	// 这个函数用于解决由于未对齐访问导致的崩溃问题（SIGBUS）
	// 某些内核没有启用故障陷阱，例如某些RK3326 Odroid Go Advance克隆发行版
	// TODO:: 也许只在配置标志下启用？也许使用已知有问题的函数列表？
	// 已知在GM:S的"_Z11Shader_LoadPhjS_"中触发 - 如果在其他地方也发生，
	// 可能值得全局启用。
	
	int idx = so_symbol_index(mod, symbol);
	if (idx == -1)
		return; // 未找到符号

	uintptr_t st_addr = mod->text_base + mod->dynsym[idx].st_value;
	// 扫描符号代码范围内的每个指令
	for (uintptr_t addr = st_addr; addr < st_addr + mod->dynsym[idx].st_size; addr+=4) {
		uint32_t inst = *(uint32_t*)(addr);
		
		// 检查是否为带有R0-R12基址寄存器的LDMIA指令
		if (((inst & 0xFFF00000) == 0xE8900000) && (((inst >> 16) & 0xF) < 13) ) {
			sceClibPrintf("Found possibly misaligned LDMIA on 0x%08X, trying to fix it... (instr: 0x%08X, to 0x%08X)\n", addr, *(uint32_t*)addr, mod->patch_head);
			trampoline_ldm(mod, addr); // 生成修复代码
		}
	}
}
