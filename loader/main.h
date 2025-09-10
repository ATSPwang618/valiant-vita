/*
 * main.h -- 主头文件
 * 
 * 本文件包含 Valiant Hearts Vita 加载器的主要声明和函数原型
 * 定义了核心的数据结构、外部变量引用和关键函数接口
 */

#ifndef __MAIN_H__
#define __MAIN_H__

#include <psp2/touch.h>
#include "config.h"
#include "so_util.h"

// 外部引用：主要的 SO 模块对象
// 这个全局变量存储加载的游戏主模块信息
extern so_module main_mod;

// 调试输出函数声明
// 用于在调试模式下输出格式化的调试信息
// 参数：text - 格式化字符串，... - 可变参数
// 返回值：输出的字符数
int debugPrintf(char *text, ...);

// 返回值为0的占位函数
// 用于替换某些不需要实际功能的系统调用
// 返回值：总是返回0
int ret0();

// 修改线程CPU亲和性掩码的系统调用
// 用于控制线程在哪个CPU核心上运行
// 参数：thid - 线程ID，cpuAffinityMask - CPU亲和性掩码
// 返回值：成功返回0，失败返回负值
int sceKernelChangeThreadCpuAffinityMask(SceUID thid, int cpuAffinityMask);

// 根据模块名搜索内核模块的VSH函数
// 这是一个内部系统函数，用于查找已加载的内核模块
// 参数：模块名字符串，保留参数
// 返回值：模块的UID，未找到时返回无效值
SceUID _vshKernelSearchModuleByName(const char *, const void *);

// 外部引用：触摸面板信息结构体
// panelInfoFront - 前置触摸屏信息
// panelInfoBack - 后置触摸板信息
// 这些结构体包含了触摸设备的分辨率、精度等参数
extern SceTouchPanelInfo panelInfoFront, panelInfoBack;

#endif
