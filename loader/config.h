/*
 * config.h -- 配置文件头文件
 * 
 * 本文件定义了 Valiant Hearts Vita 项目的核心配置常量
 * 包括调试开关、内存加载地址和屏幕分辨率等关键参数
 */

#ifndef __CONFIG_H__
#define __CONFIG_H__

// 调试模式开关 - 启用后会输出详细的调试信息
// 正式发布版本中应注释掉以提高性能
//#define DEBUG

// SO文件的内存加载基址
// 选择此地址是为了避免与系统内存和其他模块冲突
// 0x98000000 是一个安全的用户空间地址范围
#define LOAD_ADDRESS 0x98000000

// PlayStation Vita 屏幕宽度（像素）
// PS Vita 的原生屏幕分辨率为 960x544
#define SCREEN_W 960

// PlayStation Vita 屏幕高度（像素）
// 这个分辨率是 PS Vita 硬件的固定规格
#define SCREEN_H 544

#endif
