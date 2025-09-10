/*********************************************************************
* 文件名:     sha1.c
* 作者:       Brad Conte (brad AT bradconte.com)
* 版权:       
* 免责声明:   此代码按"原样"提供，不提供任何保证。
* 详细说明:   SHA1哈希算法的实现。
*            算法规范可在此处找到：
*             * http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf
*            此实现使用小端字节序。
* 
* SHA1算法实现文件
* 
* SHA1是一种产生160位消息摘要的密码学哈希函数，广泛用于数据完整性验证
* 本实现基于NIST FIPS 180-2标准，包含完整的SHA1计算过程
*********************************************************************/

/*************************** 头文件包含 ***************************/
#include <stdlib.h>
#include <string.h>
#include "sha1.h"

/****************************** 宏定义 ******************************/
// 左循环移位宏：将32位整数a左移b位，高位循环到低位
#define ROTLEFT(a, b) ((a << b) | (a >> (32 - b)))

/*********************** 函数定义 ***********************/

// SHA1变换函数：处理512位（64字节）数据块的核心算法
// 参数：ctx - SHA1上下文，data - 64字节输入数据块
void sha1_transform(SHA1_CTX *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, i, j, t, m[80]; // 工作变量和消息调度数组

	// 第一步：将64字节输入数据转换为16个32位大端整数
	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) + (data[j + 1] << 16) + (data[j + 2] << 8) + (data[j + 3]);
	
	// 第二步：扩展16个字为80个字（消息调度）
	// 使用XOR和左移1位的组合来生成额外的64个字
	for ( ; i < 80; ++i) {
		m[i] = (m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16]);
		m[i] = (m[i] << 1) | (m[i] >> 31); // 左循环移位1位
	}

	// 第三步：初始化工作变量为当前哈希值
	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];

	// 第四步：主循环 - 80轮变换，分为4个阶段
	
	// 阶段1：轮次0-19，使用函数f(b,c,d) = (b & c) ^ (~b & d)
	for (i = 0; i < 20; ++i) {
		t = ROTLEFT(a, 5) + ((b & c) ^ (~b & d)) + e + ctx->k[0] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	
	// 阶段2：轮次20-39，使用函数f(b,c,d) = b ^ c ^ d
	for ( ; i < 40; ++i) {
		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[1] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	
	// 阶段3：轮次40-59，使用函数f(b,c,d) = (b & c) ^ (b & d) ^ (c & d)
	for ( ; i < 60; ++i) {
		t = ROTLEFT(a, 5) + ((b & c) ^ (b & d) ^ (c & d))  + e + ctx->k[2] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	
	// 阶段4：轮次60-79，使用函数f(b,c,d) = b ^ c ^ d
	for ( ; i < 80; ++i) {
		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[3] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}

	// 第五步：将计算结果加到当前哈希值上
	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
}

// SHA1初始化函数：设置初始状态
// 参数：ctx - 要初始化的SHA1上下文
void sha1_init(SHA1_CTX *ctx)
{
	ctx->datalen = 0;  // 当前缓冲区中的数据长度
	ctx->bitlen = 0;   // 已处理的总位数
	
	// 设置SHA1的初始哈希值（标准常量）
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xc3d2e1f0;
	
	// 设置4个轮常量（SHA1标准规定）
	ctx->k[0] = 0x5a827999; // 轮次0-19使用
	ctx->k[1] = 0x6ed9eba1; // 轮次20-39使用
	ctx->k[2] = 0x8f1bbcdc; // 轮次40-59使用
	ctx->k[3] = 0xca62c1d6; // 轮次60-79使用
}

// SHA1更新函数：处理新的输入数据
// 可以多次调用来处理大量数据，内部自动处理64字节块的分割
// 参数：ctx - SHA1上下文，data - 输入数据，len - 数据长度
void sha1_update(SHA1_CTX *ctx, const BYTE data[], size_t len)
{
	size_t i;

	// 逐字节处理输入数据
	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i]; // 将字节添加到缓冲区
		ctx->datalen++;
		
		// 当缓冲区填满64字节时，处理这个数据块
		if (ctx->datalen == 64) {
			sha1_transform(ctx, ctx->data); // 执行SHA1变换
			ctx->bitlen += 512;             // 更新位计数（64字节=512位）
			ctx->datalen = 0;               // 重置缓冲区
		}
	}
}

// SHA1完成函数：执行最终填充并输出哈希值
// 参数：ctx - SHA1上下文，hash - 输出的20字节哈希值缓冲区
void sha1_final(SHA1_CTX *ctx, BYTE hash[])
{
	WORD i;

	i = ctx->datalen;

	// 填充剩余数据：SHA1要求在消息末尾添加特定的填充
	if (ctx->datalen < 56) {
		// 情况1：有足够空间在当前块中添加填充和长度信息
		ctx->data[i++] = 0x80; // 添加强制的0x80字节
		while (i < 56)
			ctx->data[i++] = 0x00; // 用0填充到第56字节
	}
	else {
		// 情况2：当前块空间不足，需要额外的块来存放长度信息
		ctx->data[i++] = 0x80; // 添加强制的0x80字节
		while (i < 64)
			ctx->data[i++] = 0x00; // 填充完当前块
		sha1_transform(ctx, ctx->data); // 处理这个填充块
		memset(ctx->data, 0, 56);       // 清空缓冲区，准备存放长度
	}

	// 在填充后添加原始消息的总长度（以位为单位）并进行变换
	ctx->bitlen += ctx->datalen * 8; // 加上缓冲区中剩余数据的位数
	
	// 将64位长度值以大端格式存储在缓冲区的最后8字节中
	ctx->data[63] = ctx->bitlen;       // 最低字节
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56; // 最高字节
	
	sha1_transform(ctx, ctx->data); // 处理最终块

	// 由于此实现使用小端字节序而SHA1使用大端字节序，
	// 在将最终状态复制到输出哈希时需要反转所有字节
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff; // 状态0的4个字节
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff; // 状态1的4个字节
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff; // 状态2的4个字节
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff; // 状态3的4个字节
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff; // 状态4的4个字节
	}
	// 最终输出：20字节的SHA1哈希值，按大端字节序排列
}
