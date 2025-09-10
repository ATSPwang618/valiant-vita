# Valiant Hearts PS Vita 构建配置文件
# 本文件定义了构建 Valiant Hearts PS Vita 移植项目所需的所有配置

# 设置CMake最低版本要求
cmake_minimum_required(VERSION 2.8)

# 检查并设置VitaSDK工具链文件
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    # 使用环境变量VITASDK指定的工具链文件
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    # 如果没有设置VITASDK环境变量，报错退出
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

# 定义项目名称和支持的编程语言
project(valiant C CXX)

# 包含PS Vita专用的CMake配置
include("${VITASDK}/share/vita.cmake" REQUIRED)

# 设置应用程序元数据
set(VITA_APP_NAME "Valiant Hearts")   # PS Vita主页显示的应用名称
set(VITA_TITLEID  "VALHEARTS")        # 应用程序的唯一标识符
set(VITA_MKSFOEX_FLAGS "-d ATTRIBUTE2=12") # SFO文件的额外属性标志

# 设置C编译器标志
# -g: 生成调试信息
# -Wl,-q,--allow-multiple-definition: 允许符号的多重定义
# --wrap,sceCtrlPeekBufferPositiveExt2: 包装指定的系统函数
# -D_GNU_SOURCE: 启用GNU扩展功能
# -Wall: 启用所有警告
# -O3: 最高级别的优化
# -fdiagnostics-color=always: 始终使用彩色诊断输出
# -fno-optimize-sibling-calls: 禁用兄弟调用优化
# -mfloat-abi=softfp: 使用软浮点ABI（PS Vita要求）
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wl,-q,--allow-multiple-definition,--wrap,sceCtrlPeekBufferPositiveExt2 -D_GNU_SOURCE -Wall -O3 -fdiagnostics-color=always -fno-optimize-sibling-calls -mfloat-abi=softfp")

# 设置C++编译器标志（继承C标志并添加C++特定选项）
# -std=c++11: 使用C++11标准
# -Wno-write-strings: 禁用字符串写入警告
# -fpermissive: 允许一些非标准的C++代码
# -fno-rtti: 禁用运行时类型信息（RTTI）
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++11 -Wno-write-strings -fpermissive -fno-rtti")

# 定义可执行文件及其源文件
add_executable(valiant
  loader/main.c          # 主程序入口
  loader/dialog.c        # 对话框系统实现
  loader/so_util.c       # SO文件加载和管理工具
  loader/sha1.c          # SHA1哈希算法实现
  loader/ctype_patch.c   # Android Bionic字符类型兼容性补丁
)

# 链接必需的库文件
# 这些库提供了游戏运行所需的各种功能支持
target_link_libraries(valiant
  # 系统和线程支持库
  -Wl,--whole-archive pthread -Wl,--no-whole-archive  # 完整链接pthread库
  
  # 音频处理库
  OpenSLES        # OpenSL ES音频API
  mikmod          # MOD音乐格式支持
  sndfile         # 音频文件格式支持
  vorbisfile      # Ogg Vorbis音频解码
  vorbis          # Vorbis音频编解码器
  vorbisenc       # Vorbis音频编码器
  modplug         # 模块音乐播放支持
  opusfile        # Opus音频文件支持
  opus            # Opus音频编解码器
  ogg             # Ogg容器格式支持
  FLAC            # FLAC无损音频格式
  mpg123          # MP3音频解码
  
  # 图形和字体库
  freetype        # 字体渲染库
  png             # PNG图像格式支持
  webp            # WebP图像格式支持
  jpeg            # JPEG图像格式支持
  imgui           # 即时GUI库
  vitaGL          # PS Vita的OpenGL ES实现
  vitashark       # GPU着色器编译器
  SceShaccCgExt   # 着色器编译器扩展
  
  # 压缩和解压缩库
  z               # zlib压缩库
  zip             # ZIP文件格式支持
  zstd            # Zstandard压缩算法
  lzma            # LZMA压缩算法
  bz2             # bzip2压缩算法
  
  # 加密和安全库
  ssl             # SSL/TLS安全协议
  crypto          # 加密算法库
  
  # 数学和工具库
  m               # 数学库
  mathneon        # ARM NEON优化数学函数
  stdc++          # C++标准库
  
  # PS Vita系统库
  taihen_stub              # taiHEN插件系统
  kubridge_stub            # kubridge内核桥接
  
  # PS Vita系统服务库
  SceNet_stub              # 网络服务
  SceNetCtl_stub           # 网络控制
  SceAppMgr_stub           # 应用程序管理器
  SceAppUtil_stub          # 应用程序工具
  SceAudio_stub            # 音频服务
  SceAudioIn_stub          # 音频输入
  SceCtrl_stub             # 控制器输入
  SceCommonDialog_stub     # 通用对话框
  SceDisplay_stub          # 显示服务
  SceFios2_stub            # 文件I/O服务
  SceGxm_stub              # 图形库
  SceIme_stub              # 输入法编辑器
  SceLibcBridge_stub       # C库桥接
  SceShaccCg_stub          # 着色器编译器
  SceSysmodule_stub        # 系统模块
  ScePower_stub            # 电源管理
  SceTouch_stub            # 触摸屏
  SceMotion_stub           # 运动传感器
  SceHid_stub              # 人机接口设备
  SceVshBridge_stub        # VSH桥接
  SceKernelDmacMgr_stub    # DMA控制器
)

# 生成PS Vita可执行文件
# 将编译后的可执行文件转换为PS Vita可运行的SELF格式
# UNSAFE标志允许使用特权功能
vita_create_self(eboot.bin valiant UNSAFE)

# 生成VPK安装包
# 创建包含所有必需文件的VPK安装包
vita_create_vpk(valiant.vpk ${VITA_TITLEID} eboot.bin
  VERSION ${VITA_VERSION}                    # 应用程序版本号
  NAME ${VITA_APP_NAME}                      # 应用程序名称
  
  # 应用程序资源文件映射
  # 格式：源文件路径 目标路径
  FILE ${CMAKE_SOURCE_DIR}/livearea/icon0.png sce_sys/icon0.png                    # 应用图标
       ${CMAKE_SOURCE_DIR}/livearea/pic0.png sce_sys/pic0.png                      # 背景图片
       ${CMAKE_SOURCE_DIR}/livearea/bg0.png sce_sys/livearea/contents/bg0.png      # LiveArea背景
       ${CMAKE_SOURCE_DIR}/livearea/startup.png sce_sys/livearea/contents/startup.png  # 启动画面
       ${CMAKE_SOURCE_DIR}/livearea/template.xml sce_sys/livearea/contents/template.xml # LiveArea模板
)
