#!/bin/bash

# Valiant Hearts PS Vita 快速 VPK 构建脚本
# 
# 本脚本自动化构建过程，用于快速生成 VPK 安装包
# 
# 使用方法：
#   ./build_vpk.sh [clean]
# 
# 参数：
#   clean  - 清理现有构建目录后重新构建
#
# 作者：Valiant Hearts Vita 项目团队
# 版本：1.0

# 颜色定义，用于美化输出
RED='\033[0;31m'     # 红色：错误信息
GREEN='\033[0;32m'   # 绿色：成功信息
YELLOW='\033[1;33m'  # 黄色：警告信息
BLUE='\033[0;34m'    # 蓝色：信息提示
NC='\033[0m'         # 无颜色：重置颜色

# 项目信息
PROJECT_NAME="Valiant Hearts"
BUILD_DIR="build"
VPK_NAME="valiant.vpk"

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[信息]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[成功]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[警告]${NC} $1"
}

print_error() {
    echo -e "${RED}[错误]${NC} $1"
}

# 打印脚本标题
print_title() {
    echo "=================================================="
    echo "  $PROJECT_NAME PS Vita VPK 构建脚本"
    echo "=================================================="
    echo
}

# 检查必需的环境
check_environment() {
    print_info "检查构建环境..."
    
    # 检查 VITASDK 环境变量
    if [ -z "$VITASDK" ]; then
        print_error "未设置 VITASDK 环境变量"
        print_error "请设置 VITASDK 指向您的 VitaSDK 安装路径"
        print_error "例如：export VITASDK=/usr/local/vitasdk"
        exit 1
    fi
    
    print_success "VITASDK 路径: $VITASDK"
    
    # 检查 CMake
    if ! command -v cmake &> /dev/null; then
        print_error "未找到 cmake 命令"
        print_error "请确保已安装 CMake 并添加到 PATH"
        exit 1
    fi
    
    # 检查 make
    if ! command -v make &> /dev/null; then
        print_error "未找到 make 命令"
        print_error "请确保已安装 GNU Make"
        exit 1
    fi
    
    print_success "构建环境检查完成"
}

# 清理构建目录
clean_build() {
    if [ -d "$BUILD_DIR" ]; then
        print_info "清理现有构建目录..."
        rm -rf "$BUILD_DIR"
        print_success "构建目录已清理"
    fi
}

# 创建构建目录
create_build_dir() {
    print_info "创建构建目录..."
    mkdir -p "$BUILD_DIR"
    print_success "构建目录已创建"
}

# 配置项目
configure_project() {
    print_info "配置项目..."
    cd "$BUILD_DIR"
    
    if ! cmake ..; then
        print_error "CMake 配置失败"
        exit 1
    fi
    
    print_success "项目配置完成"
}

# 编译项目
build_project() {
    print_info "开始编译项目..."
    
    # 使用并行编译以加快构建速度
    CORES=$(nproc 2>/dev/null || echo 4)
    print_info "使用 $CORES 个并行编译任务"
    
    if ! make -j"$CORES"; then
        print_error "编译失败"
        exit 1
    fi
    
    print_success "项目编译完成"
}

# 检查生成的文件
check_output() {
    print_info "检查生成的文件..."
    
    if [ ! -f "$VPK_NAME" ]; then
        print_error "未找到 VPK 文件: $VPK_NAME"
        exit 1
    fi
    
    # 获取文件大小
    VPK_SIZE=$(ls -lh "$VPK_NAME" | awk '{print $5}')
    print_success "VPK 文件生成成功: $VPK_NAME ($VPK_SIZE)"
    
    # 计算文件哈希值（用于验证）
    if command -v sha256sum &> /dev/null; then
        HASH=$(sha256sum "$VPK_NAME" | cut -d' ' -f1)
        print_info "SHA256: $HASH"
    fi
}

# 显示安装说明
show_install_instructions() {
    echo
    echo "=================================================="
    echo "  安装说明"
    echo "=================================================="
    echo
    echo "1. 将生成的 $VPK_NAME 传输到您的 PS Vita"
    echo "2. 使用 VitaShell 安装 VPK 文件"
    echo "3. 按照 README.md 中的说明准备游戏文件"
    echo "4. 确保已安装必需的依赖项："
    echo "   - kubridge.skprx"
    echo "   - fd_fix.skprx (如果不使用 rePatch)"
    echo "   - libshacccg.suprx"
    echo
    echo "游戏文件路径："
    echo "   ux0:data/valiant/libuaf.so"
    echo "   ux0:data/valiant/main.obb"
    echo
}

# 主函数
main() {
    print_title
    
    # 检查命令行参数
    if [ "$1" = "clean" ]; then
        print_info "执行清理构建..."
        clean_build
    fi
    
    # 记录开始时间
    START_TIME=$(date +%s)
    
    # 执行构建步骤
    check_environment
    create_build_dir
    configure_project
    build_project
    check_output
    
    # 返回根目录
    cd ..
    
    # 计算构建时间
    END_TIME=$(date +%s)
    BUILD_TIME=$((END_TIME - START_TIME))
    
    print_success "构建完成！总用时: ${BUILD_TIME} 秒"
    
    # 显示安装说明
    show_install_instructions
}

# 错误处理：捕获脚本执行过程中的错误
set -e
trap 'print_error "构建过程中发生错误，请检查上面的错误信息"' ERR

# 确保脚本在项目根目录执行
if [ ! -f "CMakeLists.txt" ]; then
    print_error "请在项目根目录中运行此脚本"
    exit 1
fi

# 执行主函数
main "$@"