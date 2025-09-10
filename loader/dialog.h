/*
 * dialog.h -- 对话框系统头文件
 * 
 * 本文件定义了 PS Vita 系统对话框的接口函数
 * 包括输入法(IME)对话框、消息对话框和错误处理功能
 */

#ifndef __DIALOG_H__
#define __DIALOG_H__

// 初始化输入法对话框
// 用于显示一个文本输入对话框，允许用户通过虚拟键盘输入文本
// 参数：title - 对话框标题，initial_text - 初始文本内容
// 返回值：成功返回0，失败返回负值
int init_ime_dialog(const char *title, const char *initial_text);

// 获取输入法对话框的结果
// 在用户完成输入后调用此函数获取输入的文本
// 返回值：指向输入文本的指针，失败返回NULL
char *get_ime_dialog_result(void);

// 初始化消息对话框
// 用于显示一个包含消息文本的对话框
// 参数：msg - 要显示的消息内容
// 返回值：成功返回0，失败返回负值
int init_msg_dialog(const char *msg);

// 获取消息对话框的结果
// 检查用户是否已经关闭了消息对话框
// 返回值：对话框状态值
int get_msg_dialog_result(void);

// 致命错误处理函数
// 显示错误消息并终止程序执行
// 参数：fmt - 格式化字符串，... - 可变参数
// 注意：此函数永不返回（使用 __attribute__((noreturn)) 标记）
void fatal_error(const char *fmt, ...) __attribute__((noreturn));

#endif
