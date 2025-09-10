/* dialog.c -- PS Vita通用对话框系统实现
 *
 * Copyright (C) 2021 fgsfds, Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 * 
 * 本文件实现了PS Vita系统的对话框功能，包括：
 * - 输入法(IME)对话框：用于文本输入
 * - 消息对话框：用于显示提示信息
 * - 错误处理：显示致命错误并安全退出程序
 * - UTF-8和UTF-16字符编码转换功能
 */

#include <psp2/kernel/processmgr.h>
#include <psp2/ctrl.h>
#include <psp2/ime_dialog.h>
#include <psp2/message_dialog.h>
#include <vitaGL.h>

#include <stdio.h>
#include <stdarg.h>

#include "main.h"
#include "dialog.h"

// IME对话框相关的静态缓冲区
// 这些缓冲区用于在UTF-8和UTF-16之间进行字符编码转换
static uint16_t ime_title_utf16[SCE_IME_DIALOG_MAX_TITLE_LENGTH];       // IME对话框标题（UTF-16编码）
static uint16_t ime_initial_text_utf16[SCE_IME_DIALOG_MAX_TEXT_LENGTH]; // IME初始文本（UTF-16编码）
static uint16_t ime_input_text_utf16[SCE_IME_DIALOG_MAX_TEXT_LENGTH + 1]; // IME输入文本缓冲区（UTF-16编码）
static uint8_t ime_input_text_utf8[SCE_IME_DIALOG_MAX_TEXT_LENGTH + 1];   // IME输入文本缓冲区（UTF-8编码）

// UTF-16到UTF-8编码转换函数
// 将UTF-16编码的字符串转换为UTF-8编码
// 参数：src - UTF-16源字符串，dst - UTF-8目标缓冲区
void utf16_to_utf8(const uint16_t *src, uint8_t *dst) {
  for (int i = 0; src[i]; i++) {
    if ((src[i] & 0xFF80) == 0) {
      // ASCII字符（0-127）：直接复制
      *(dst++) = src[i] & 0xFF;
    } else if((src[i] & 0xF800) == 0) {
      // 双字节字符（128-2047）：使用2字节UTF-8编码
      *(dst++) = ((src[i] >> 6) & 0xFF) | 0xC0;
      *(dst++) = (src[i] & 0x3F) | 0x80;
    } else if((src[i] & 0xFC00) == 0xD800 && (src[i + 1] & 0xFC00) == 0xDC00) {
      // 代理对（surrogate pair）：用于编码Unicode补充平面字符
      // 需要4字节UTF-8编码
      *(dst++) = (((src[i] + 64) >> 8) & 0x3) | 0xF0;
      *(dst++) = (((src[i] >> 2) + 16) & 0x3F) | 0x80;
      *(dst++) = ((src[i] >> 4) & 0x30) | 0x80 | ((src[i + 1] << 2) & 0xF);
      *(dst++) = (src[i + 1] & 0x3F) | 0x80;
      i += 1; // 跳过代理对的第二个字符
    } else {
      // 三字节字符（2048-65535）：使用3字节UTF-8编码
      *(dst++) = ((src[i] >> 12) & 0xF) | 0xE0;
      *(dst++) = ((src[i] >> 6) & 0x3F) | 0x80;
      *(dst++) = (src[i] & 0x3F) | 0x80;
    }
  }

  *dst = '\0'; // 添加字符串终止符
}

// UTF-8到UTF-16编码转换函数
// 将UTF-8编码的字符串转换为UTF-16编码
// 参数：src - UTF-8源字符串，dst - UTF-16目标缓冲区
void utf8_to_utf16(const uint8_t *src, uint16_t *dst) {
  for (int i = 0; src[i];) {
    if ((src[i] & 0xE0) == 0xE0) {
      // 三字节UTF-8字符：合并为一个UTF-16字符
      *(dst++) = ((src[i] & 0x0F) << 12) | ((src[i + 1] & 0x3F) << 6) | (src[i + 2] & 0x3F);
      i += 3;
    } else if ((src[i] & 0xC0) == 0xC0) {
      // 双字节UTF-8字符：合并为一个UTF-16字符
      *(dst++) = ((src[i] & 0x1F) << 6) | (src[i + 1] & 0x3F);
      i += 2;
    } else {
      // 单字节UTF-8字符（ASCII）：直接复制
      *(dst++) = src[i];
      i += 1;
    }
  }

  *dst = '\0'; // 添加字符串终止符
}

// 初始化输入法(IME)对话框
// 设置对话框参数并显示文本输入界面
// 参数：title - 对话框标题，initial_text - 初始显示的文本
// 返回值：成功返回0，失败返回负值
int init_ime_dialog(const char *title, const char *initial_text) {
  // 清空所有缓冲区，确保没有残留数据
  memset(ime_title_utf16, 0, sizeof(ime_title_utf16));
  memset(ime_initial_text_utf16, 0, sizeof(ime_initial_text_utf16));
  memset(ime_input_text_utf16, 0, sizeof(ime_input_text_utf16));
  memset(ime_input_text_utf8, 0, sizeof(ime_input_text_utf8));

  // 将UTF-8输入转换为UTF-16格式（PS Vita IME要求UTF-16）
  utf8_to_utf16((uint8_t *)title, ime_title_utf16);
  utf8_to_utf16((uint8_t *)initial_text, ime_initial_text_utf16);

  // 设置IME对话框参数
  SceImeDialogParam param;
  sceImeDialogParamInit(&param); // 初始化参数结构体为默认值

  param.supportedLanguages = 0x0001FFFF;          // 支持的语言集合（所有语言）
  param.languagesForced = SCE_TRUE;               // 强制使用指定语言
  param.type = SCE_IME_TYPE_BASIC_LATIN;          // 输入类型：基本拉丁字符
  param.title = ime_title_utf16;                  // 对话框标题
  param.maxTextLength = SCE_IME_DIALOG_MAX_TEXT_LENGTH; // 最大文本长度
  param.initialText = ime_initial_text_utf16;     // 初始文本
  param.inputTextBuffer = ime_input_text_utf16;   // 输入文本缓冲区

  return sceImeDialogInit(&param); // 初始化并显示IME对话框
}

// 获取输入法对话框的输入结果
// 检查对话框状态，如果用户完成输入则返回结果
// 返回值：指向输入文本的指针，对话框未完成时返回NULL
char *get_ime_dialog_result(void) {
  // 检查对话框是否已完成
  if (sceImeDialogGetStatus() != SCE_COMMON_DIALOG_STATUS_FINISHED)
    return NULL;

  // 获取用户输入结果
  SceImeDialogResult result;
  memset(&result, 0, sizeof(SceImeDialogResult));
  sceImeDialogGetResult(&result);
  
  // 只有当用户按下确认按钮时才处理输入
  if (result.button == SCE_IME_DIALOG_BUTTON_ENTER)
    utf16_to_utf8(ime_input_text_utf16, ime_input_text_utf8);
  
  sceImeDialogTerm(); // 终止对话框

  // 修复：IME对话框关闭后模拟摇杆可能停止工作
  // 重新设置控制器采样模式来恢复模拟摇杆功能
  sceCtrlSetSamplingModeExt(SCE_CTRL_MODE_ANALOG_WIDE);

  return (char *)ime_input_text_utf8;
}

// 初始化消息对话框
// 显示一个包含指定消息的对话框，只有确认按钮
// 参数：msg - 要显示的消息文本
// 返回值：成功返回0，失败返回负值
int init_msg_dialog(const char *msg) {
  // 设置用户消息参数
  SceMsgDialogUserMessageParam msg_param;
  memset(&msg_param, 0, sizeof(msg_param));
  msg_param.buttonType = SCE_MSG_DIALOG_BUTTON_TYPE_OK; // 只显示确认按钮
  msg_param.msg = (SceChar8 *)msg;                      // 消息文本

  // 设置消息对话框参数
  SceMsgDialogParam param;
  sceMsgDialogParamInit(&param);                        // 初始化参数结构体
  _sceCommonDialogSetMagicNumber(&param.commonParam);   // 设置魔数（系统要求）
  param.mode = SCE_MSG_DIALOG_MODE_USER_MSG;            // 用户消息模式
  param.userMsgParam = &msg_param;                      // 用户消息参数

  return sceMsgDialogInit(&param); // 初始化并显示消息对话框
}

// 获取消息对话框的结果
// 检查用户是否已经关闭了消息对话框
// 返回值：对话框已关闭返回1，仍在显示返回0
int get_msg_dialog_result(void) {
  // 检查对话框是否已完成
  if (sceMsgDialogGetStatus() != SCE_COMMON_DIALOG_STATUS_FINISHED)
    return 0;
  
  sceMsgDialogTerm(); // 终止对话框
  return 1;
}

// 致命错误处理函数
// 显示错误消息对话框并安全退出程序
// 参数：fmt - 格式化字符串，... - 可变参数（类似printf）
// 注意：此函数永不返回
void fatal_error(const char *fmt, ...) {
  va_list list;
  char string[512]; // 错误消息缓冲区

  // 格式化错误消息
  va_start(list, fmt);
  vsnprintf(string, sizeof(string), fmt, list);
  va_end(list);

  // 初始化VitaGL以确保能够显示对话框
  vglInit(0);
  
  // 在控制台输出错误信息（用于调试）
  sceClibPrintf("fatal_error: %s\n", string);
  
  // 显示错误对话框
  init_msg_dialog(string);

  // 等待用户确认错误对话框
  while (!get_msg_dialog_result())
    vglSwapBuffers(GL_TRUE); // 保持渲染循环

  // 安全退出程序
  sceKernelExitProcess(0);
  while (1); // 永久循环（防止函数返回）
}
