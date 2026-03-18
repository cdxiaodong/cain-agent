#!/bin/bash
# 云渗透测试工具安装脚本
# 支持: macOS, Linux (Ubuntu/Debian, CentOS/RHEL)

set -e

echo "================================"
echo "云渗透测试工具安装脚本"
echo "================================"
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检测操作系统
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macOS"
    PKG_MANAGER="brew"
elif [[ -f /etc/debian_version ]]; then
    OS="Ubuntu/Debian"
    PKG_MANAGER="apt"
elif [[ -f /etc/redhat-release ]]; then
    OS="CentOS/RHEL"
    PKG_MANAGER="yum"
else
    echo -e "${RED}不支持的操作系统${NC}"
    exit 1
fi

echo -e "${GREEN}检测到操作系统: $OS${NC}"
echo ""

# 安装基础工具
install_base_tools() {
    echo -e "${YELLOW}安装基础工具...${NC}"

    if [[ "$OS" == "macOS" ]]; then
        # 检查 brew 是否安装
        if ! command -v brew &> /dev/null; then
            echo -e "${RED}请先安装 Homebrew: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"${NC}"
            exit 1
        fi
        brew install python3 python@3.10 git wget curl jq tree
    elif [[ "$OS" == "Ubuntu/Debian" ]]; then
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip git wget curl jq tree
    elif [[ "$OS" == "CentOS/RHEL" ]]; then
        sudo yum install -y python3 python3-pip git wget curl jq tree
    fi

    echo -e "${GREEN}✓ 基础工具安装完成${NC}"
    echo ""
}

# 安装 AWS 工具
install_aws_tools() {
    echo -e "${YELLOW}安装 AWS 工具...${NC}"

    # AWS CLI
    if ! command -v aws &> /dev/null; then
        if [[ "$OS" == "macOS" ]]; then
            brew install awscli
        else
            curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
            unzip -q awscliv2.zip
            sudo ./aws/install
            rm -rf aws awscliv2.zip
        fi
    fi

    # AWS 工具
    pip3 install --user boto3 botocore

    echo -e "${GREEN}✓ AWS 工具安装完成${NC}"
    echo ""
}

# 安装 Azure 工具
install_azure_tools() {
    echo -e "${YELLOW}安装 Azure 工具...${NC}"

    # Azure CLI
    if ! command -v az &> /dev/null; then
        if [[ "$OS" == "macOS" ]]; then
            brew install azure-cli
        elif [[ "$OS" == "Ubuntu/Debian" ]]; then
            curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
        else
            sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
            sudo sh -c 'echo -e "[azure-cli]\nname=Azure CLI\nbaseurl=https://packages.microsoft.com/yumrepos/azure-cli\nenabled=1\ngpgcheck=1\ngpgkey=https://packages.microsoft.com/keys/microsoft.asc" > /etc/yum.repos.d/azure-cli.repo'
            sudo yum install -y azure-cli
        fi
    fi

    echo -e "${GREEN}✓ Azure 工具安装完成${NC}"
    echo ""
}

# 安装 GCP 工具
install_gcp_tools() {
    echo -e "${YELLOW}安装 GCP 工具...${NC}"

    # Google Cloud SDK
    if ! command -v gcloud &> /dev/null; then
        if [[ "$OS" == "macOS" ]]; then
            brew install google-cloud-sdk
        else
            curl https://sdk.cloud.google.com | bash
            exec -l $SHELL
        fi
    fi

    echo -e "${GREEN}✓ GCP 工具安装完成${NC}"
    echo ""
}

# 安装阿里云工具
install_aliyun_tools() {
    echo -e "${YELLOW}安装阿里云工具...${NC}"

    # 阿里云 CLI
    if ! command -v aliyun &> /dev/null; then
        pip3 install --user aliyun-cli
    fi

    echo -e "${GREEN}✓ 阿里云工具安装完成${NC}"
    echo ""
}

# 安装腾讯云工具
install_tencent_tools() {
    echo -e "${YELLOW}安装腾讯云工具...${NC}"

    # 腾讯云 CLI
    if ! command -v tccli &> /dev/null; then
        pip3 install --user tccli
    fi

    echo -e "${GREEN}✓ 腾讯云工具安装完成${NC}"
    echo ""
}

# 安装通用安全工具
install_security_tools() {
    echo -e "${YELLOW}安装通用安全工具...${NC}"

    # 创建工具目录
    mkdir -p ~/cloud-pentest-tools
    cd ~/cloud-pentest-tools

    # Scout Suite
    if [[ ! -d "ScoutSuite" ]]; then
        pip3 install --user scoutsuite
        git clone https://github.com/nccgroup/ScoutSuite.git
    fi

    # Pacu (AWS)
    if [[ ! -d "pacu" ]]; then
        git clone https://github.com/RhinoSecurityLabs/pacu.git
        cd pacu
        pip3 install --user -r requirements.txt
        cd ..
    fi

    # enumerate-iam
    if [[ ! -d "enumerate-iam" ]]; then
        git clone https://github.com/andresriancho/enumerate-iam.git
        cd enumerate-iam
        pip3 install --user -r requirements.txt
        cd ..
    fi

    # MicroBurst (Azure)
    if [[ ! -d "MicroBurst" ]]; then
        git clone https://github.com/NetSPI/MicroBurst.git
        pip3 install --user azure adal requests
    fi

    # GCPBucketBrute
    if [[ ! -d "GCPBucketBrute" ]]; then
        git clone https://github.com/RhinoSecurityLabs/GCPBucketBrute.git
    fi

    # Prowler
    pip3 install --user prowler

    echo -e "${GREEN}✓ 通用安全工具安装完成${NC}"
    echo ""
}

# 创建配置目录
setup_directories() {
    echo -e "${YELLOW}创建配置目录...${NC}"

    mkdir -p ~/.aws
    mkdir -p ~/.azure
    mkdir -p ~/cloud-pentest-logs

    echo -e "${GREEN}✓ 配置目录创建完成${NC}"
    echo ""
}

# 验证安装
verify_installation() {
    echo -e "${YELLOW}验证安装...${NC}"
    echo ""

    echo "AWS CLI:"
    if command -v aws &> /dev/null; then
        echo -e "  ${GREEN}✓ aws${NC} $(aws --version 2>&1 | cut -d' ' -f1)"
    else
        echo -e "  ${RED}✗ aws 未安装${NC}"
    fi

    echo "Azure CLI:"
    if command -v az &> /dev/null; then
        echo -e "  ${GREEN}✓ az${NC} $(az version 2>&1 | grep azure-cli | awk '{print $2}')"
    else
        echo -e "  ${RED}✗ az 未安装${NC}"
    fi

    echo "GCP CLI:"
    if command -v gcloud &> /dev/null; then
        echo -e "  ${GREEN}✓ gcloud${NC} $(gcloud version 2>&1 | grep Google | head -1)"
    else
        echo -e "  ${RED}✗ gcloud 未安装${NC}"
    fi

    echo "阿里云 CLI:"
    if command -v aliyun &> /dev/null; then
        echo -e "  ${GREEN}✓ aliyun${NC}"
    else
        echo -e "  ${RED}✗ aliyun 未安装${NC}"
    fi

    echo "腾讯云 CLI:"
    if command -v tccli &> /dev/null; then
        echo -e "  ${GREEN}✓ tccli${NC}"
    else
        echo -e "  ${RED}✗ tccli 未安装${NC}"
    fi

    echo ""
    echo "安全工具:"
    echo "  Scout Suite: $(pip3 show scoutsuite 2>/dev/null | grep Version | awk '{print $2}')"
    echo "  Prowler: $(pip3 show prowler 2>/dev/null | grep Version | awk '{print $2}')"
    echo ""
}

# 主菜单
main_menu() {
    echo "请选择要安装的工具:"
    echo "1) 全部安装 (推荐)"
    echo "2) 仅 AWS 工具"
    echo "3) 仅 Azure 工具"
    echo "4) 仅 GCP 工具"
    echo "5) 仅国内云工具 (阿里云/腾讯云)"
    echo "6) 仅安全工具"
    echo "7) 验证安装"
    echo "8) 退出"
    echo ""
    read -p "请输入选项 (1-8): " choice

    case $choice in
        1)
            install_base_tools
            install_aws_tools
            install_azure_tools
            install_gcp_tools
            install_aliyun_tools
            install_tencent_tools
            install_security_tools
            setup_directories
            verify_installation
            ;;
        2)
            install_base_tools
            install_aws_tools
            ;;
        3)
            install_base_tools
            install_azure_tools
            ;;
        4)
            install_base_tools
            install_gcp_tools
            ;;
        5)
            install_base_tools
            install_aliyun_tools
            install_tencent_tools
            ;;
        6)
            install_base_tools
            install_security_tools
            ;;
        7)
            verify_installation
            ;;
        8)
            echo "退出"
            exit 0
            ;;
        *)
            echo -e "${RED}无效选项${NC}"
            exit 1
            ;;
    esac
}

# 快速安装模式
if [[ "$1" == "--all" ]]; then
    install_base_tools
    install_aws_tools
    install_azure_tools
    install_gcp_tools
    install_aliyun_tools
    install_tencent_tools
    install_security_tools
    setup_directories
    verify_installation
else
    main_menu
fi

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}安装完成！${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo "工具目录: ~/cloud-pentest-tools"
echo "日志目录: ~/cloud-pentest-logs"
echo ""
echo "下一步:"
echo "1. 配置云平台凭证"
echo "2. 开始渗透测试: cd ~/cloud-pentest-tools"
echo ""
