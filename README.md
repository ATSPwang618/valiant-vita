# Valiant Hearts PS Vita 移植版

<p align="center"><img src="./screenshots/game.png"></p>

这是 **《英勇之心：伟大战争》** 在 PS Vita 平台上的包装器/移植版本。

该移植通过将官方 Android ARMv7 可执行文件加载到内存中，使用本地函数解析其导入并对其进行修补以正常运行。通过这种方式，它基本上模拟了一个最小化的 Android 环境，在其中我们按原样本地运行可执行文件。

## 注意事项

- 该加载器已使用游戏的 v.1.0.4b 版本进行测试。
- 可以以低端模式启动游戏。这将确保更稳定的帧率，但会牺牲图形质量和精灵密度。

## 更新日志

### v1.1.1

- 修复了可能导致内存泄漏问题的错误。
- 修复了波兰语语言检测。

### v1.1

- 通过模拟十字键按压添加了左摇杆支持。
- 添加了多语言支持。

### v1.0

- 初始发布。

## 安装说明（终端用户）

- 通过将 `kubridge.skprx` 和 `fd_fix.skprx` 复制到您的 taiHEN 插件文件夹（通常是 `ux0:tai`）并在 `*KERNEL` 下的 `config.txt` 中添加两个条目来安装 [kubridge](https://github.com/TheOfficialFloW/kubridge/releases/) 和 [FdFix](https://github.com/TheOfficialFloW/FdFix/releases/)：
  
```
  *KERNEL
  ux0:tai/kubridge.skprx
  ux0:tai/fd_fix.skprx
```

**注意：** 如果您使用 rePatch 插件，请不要安装 fd_fix.skprx

- **可选：** 安装 [PSVshell](https://github.com/Electry/PSVshell/releases) 将您的设备超频到 500Mhz。
- 如果您还没有 `libshacccg.suprx`，请按照 [此指南](https://samilops2.gitbook.io/vita-troubleshooting-guide/shader-compiler/extract-libshacccg.suprx) 安装它。
- 从发布标签页安装 vpk 文件。
- 合法获取 Android 版《英勇之心：伟大战争》的副本，格式为 `.apk` 文件和 `.obb` 文件。
- 使用 zip 资源管理器打开 apk，从 `lib/armeabi-v7a` 文件夹中提取文件 `libuaf.so` 到 `ux0:data/valiant`。
- 将 obb 文件重命名为 `main.obb` 并放置在 `ux0:data/valiant` 中。

## 构建说明（开发者）

要构建加载器，您需要一个完全编译的 [vitasdk](https://github.com/vitasdk) 构建，并使用 softfp。  
您可以在这里找到预编译版本：https://github.com/vitasdk/buildscripts/actions/runs/1102643776。  
此外，您还需要将这些库编译为 softfp，在它们的 CFLAGS 中添加 `-mfloat-abi=softfp`：

- [SDL2_vitagl](https://github.com/Northfear/SDL/tree/vitagl)

- [libmathneon](https://github.com/Rinnegatamante/math-neon)

  - ```bash
    make install
    ```

- [vitaShaRK](https://github.com/Rinnegatamante/vitaShaRK)

  - ```bash
    make install
    ```

- [kubridge](https://github.com/TheOfficialFloW/kubridge)

  - ```bash
    mkdir build && cd build
    cmake .. && make install
    ```

- [vitaGL](https://github.com/Rinnegatamante/vitaGL)

  - ````bash
    make SOFTFP_ABI=1 HAVE_GLSL_SUPPORT=1 NO_DEBUG=1 install
    ````

满足所有这些要求后，您可以使用以下命令编译加载器：

```bash
mkdir build && cd build
cmake .. && make
```

## 快速 VPK 构建

使用提供的脚本可以快速构建 VPK 文件：

```bash
./build_vpk.sh
```

该脚本将自动创建构建目录、配置项目并生成 VPK 文件。

## 技术细节

### 项目架构

本项目采用 SO（共享对象）加载器技术，主要组成部分包括：

- **SO 加载器**：负责加载和解析 Android .so 文件
- **API 模拟层**：提供 Android 系统 API 的 PS Vita 实现
- **图形适配**：通过 VitaGL 提供 OpenGL ES 兼容性
- **音频系统**：使用 OpenSL ES 实现音频播放
- **输入处理**：将 PS Vita 控制器输入映射到 Android 游戏控件

### 支持功能

- ✅ 完整的游戏流程
- ✅ 多语言支持（自动检测系统语言）
- ✅ 触摸屏控制
- ✅ 物理按键控制
- ✅ 左摇杆支持（模拟十字键）
- ✅ 高/低画质模式切换
- ✅ 音频播放
- ✅ 存档系统

### 性能优化

- 使用 ARM NEON 指令集优化数学计算
- 支持 CPU/GPU 超频以获得更好性能
- 低端模式适配低性能设备
- 内存使用优化，避免内存泄漏

## 致谢

- TheFloW 提供的原始 .so 加载器技术
- Rinnegatamante 的 VitaGL 和相关工具
- 所有为 PS Vita 自制软件生态系统做出贡献的开发者

## 许可证

本项目基于 MIT 许可证发布。详情请参阅 LICENSE 文件。
