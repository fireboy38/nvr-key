"""
许可证/注册管理模块

本模块为海康威视下载器桌面应用提供许可证和注册管理功能，包括：
- 机器码生成：基于MAC地址、主机名和磁盘序列号生成唯一机器标识
- 许可证密钥生成与验证：使用HMAC-SHA256算法生成和验证激活密钥
- 许可证存储：以Base64编码的JSON格式存储注册信息，带防篡改校验
- 试用模式：首次运行起7天试用，过期后需注册
- 密钥生成工具：供开发者/管理员为用户生成密钥

使用方式：
    # 在应用中检查许可证状态
    from core.license_manager import is_registered, is_trial_valid, get_license_info

    if is_registered():
        info = get_license_info()
        print(f"已注册，类型: {info['license_type']}")
    elif is_trial_valid():
        days = get_remaining_days()
        print(f"试用中，剩余 {days} 天")
    else:
        print("试用期已过期，请注册")

    # 管理员生成密钥
    from core.license_manager import generate_key, get_machine_code
    machine_code = get_machine_code()
    key = generate_key(machine_code, license_type="standard")

    # 命令行生成密钥
    python -m core.license_manager --generate --machine-code ABCD1234EFGH5678 --type standard
"""

import hashlib
import hmac
import json
import base64
import os
import platform
import uuid
import subprocess
import datetime
import argparse
import sys

# ============================================================
# 常量定义
# ============================================================

# HMAC密钥，用于生成和验证激活码
SECRET_KEY = b"HikVision_Downloader_2024_SecretKey_XsInfo"

# 机器码缓存（避免重复调用wmic等慢速操作）
_machine_code_cache = None

# 磁盘序列号缓存（wmic调用最慢，单独缓存）
_disk_serial_cache = None

# MAC地址缓存
_mac_address_cache = None

# 许可证数据存储目录
LICENSE_DIR = os.path.join(os.path.expanduser("~"), ".hikvision_downloader")

# 许可证数据文件路径
LICENSE_FILE = os.path.join(LICENSE_DIR, "license.dat")

# 试用信息文件路径（隐藏文件）
TRIAL_FILE = os.path.join(LICENSE_DIR, ".trial_info")

# 试用期天数
TRIAL_DAYS = 7

# 许可证类型定义
LICENSE_TYPE_TRIAL = "trial"       # 试用版，7天
LICENSE_TYPE_STANDARD = "standard" # 标准版，1年
LICENSE_TYPE_LIFETIME = "lifetime" # 终身版，永不过期

# 各许可证类型对应的有效期天数
LICENSE_DURATION = {
    LICENSE_TYPE_TRIAL: 7,
    LICENSE_TYPE_STANDARD: 365,
    LICENSE_TYPE_LIFETIME: None,  # 无限期
}


# ============================================================
# 硬件信息获取
# ============================================================

def _get_mac_address():
    """
    获取本机MAC地址（带缓存）

    使用uuid获取第一个可用的MAC地址，如果获取失败则返回默认值。
    跨平台兼容：Windows、Linux、macOS。

    Returns:
        str: MAC地址字符串（去掉冒号的大写格式），例如 "A1B2C3D4E5F6"
    """
    global _mac_address_cache
    if _mac_address_cache is not None:
        return _mac_address_cache

    try:
        mac = uuid.getnode()
        mac_str = ":".join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))
        result = mac_str.replace(":", "")
        _mac_address_cache = result
        return result
    except Exception:
        _mac_address_cache = "000000000000"
        return "000000000000"


def _get_hostname():
    """
    获取本机主机名

    跨平台兼容：Windows、Linux、macOS。

    Returns:
        str: 主机名字符串
    """
    try:
        return platform.node()
    except Exception:
        return "UNKNOWN_HOST"


def _get_disk_serial():
    """
    获取主磁盘序列号（带缓存）

    跨平台实现：
    - Windows: 使用 wmic diskdrive get serialnumber 命令
    - Linux: 尝试读取 /dev/sda 或使用 lsblk 命令
    - macOS: 使用 ioreg 命令获取磁盘信息

    如果获取失败，返回 "UNKNOWN_DISK" 作为后备值。
    结果会被缓存，避免重复调用慢速的wmic命令。

    Returns:
        str: 磁盘序列号字符串
    """
    global _disk_serial_cache
    if _disk_serial_cache is not None:
        return _disk_serial_cache

    system = platform.system()

    try:
        if system == "Windows":
            result = _get_disk_serial_windows()
        elif system == "Linux":
            result = _get_disk_serial_linux()
        elif system == "Darwin":
            result = _get_disk_serial_mac()
        else:
            result = "UNKNOWN_DISK"
    except Exception:
        result = "UNKNOWN_DISK"

    _disk_serial_cache = result
    return result


def _get_disk_serial_windows():
    """
    在Windows系统上获取磁盘序列号

    使用wmic命令获取第一个磁盘驱动器的序列号。

    Returns:
        str: 磁盘序列号，获取失败返回 "UNKNOWN_DISK"
    """
    try:
        result = subprocess.run(
            ["wmic", "diskdrive", "get", "serialnumber"],
            capture_output=True,
            text=True,
            timeout=10
        )
        lines = result.stdout.strip().split("\n")
        # 第一行是标题 "SerialNumber"，从第二行开始取数据
        for line in lines[1:]:
            serial = line.strip()
            if serial:
                return serial
        return "UNKNOWN_DISK"
    except Exception:
        return "UNKNOWN_DISK"


def _get_disk_serial_linux():
    """
    在Linux系统上获取磁盘序列号

    尝试以下方法依次获取：
    1. 使用 lsblk 命令获取第一个磁盘的序列号
    2. 使用 hdparm 命令读取 /dev/sda 的序列号
    3. 尝试读取 /sys/block/sda/device/serial 文件
    4. 以上均失败时返回后备值

    Returns:
        str: 磁盘序列号，获取失败返回 "UNKNOWN_DISK"
    """
    # 方法1：使用 lsblk
    try:
        result = subprocess.run(
            ["lsblk", "-ndo", "SERIAL", "/dev/sda"],
            capture_output=True,
            text=True,
            timeout=10
        )
        serial = result.stdout.strip()
        if serial and serial != "":
            return serial
    except Exception:
        pass

    # 方法2：使用 hdparm
    try:
        result = subprocess.run(
            ["hdparm", "-I", "/dev/sda"],
            capture_output=True,
            text=True,
            timeout=10
        )
        for line in result.stdout.split("\n"):
            if "Serial Number" in line:
                serial = line.split(":")[-1].strip()
                if serial:
                    return serial
    except Exception:
        pass

    # 方法3：从 /sys 文件系统读取
    try:
        serial_path = "/sys/block/sda/device/serial"
        if os.path.exists(serial_path):
            with open(serial_path, "r") as f:
                serial = f.read().strip()
                if serial:
                    return serial
    except Exception:
        pass

    return "UNKNOWN_DISK"


def _get_disk_serial_mac():
    """
    在macOS系统上获取磁盘序列号

    使用 ioreg 命令获取磁盘设备信息，提取序列号。

    Returns:
        str: 磁盘序列号，获取失败返回 "UNKNOWN_DISK"
    """
    try:
        result = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOMedia"],
            capture_output=True,
            text=True,
            timeout=10
        )
        for line in result.stdout.split("\n"):
            if "Serial Number" in line or "USB Serial Number" in line:
                # 提取引号中的序列号
                parts = line.split('"')
                if len(parts) >= 2:
                    serial = parts[-2]
                    if serial:
                        return serial
    except Exception:
        pass

    # 备用方法：使用 system_profiler
    try:
        result = subprocess.run(
            ["system_profiler", "SPSerialATADataType"],
            capture_output=True,
            text=True,
            timeout=10
        )
        for line in result.stdout.split("\n"):
            if "Serial Number" in line:
                serial = line.split(":")[-1].strip()
                if serial:
                    return serial
    except Exception:
        pass

    return "UNKNOWN_DISK"


# ============================================================
# 机器码生成
# ============================================================

def get_machine_code():
    """
    生成基于硬件信息的唯一机器码

    通过组合MAC地址、主机名和磁盘序列号，使用MD5哈希算法生成
    16位大写十六进制机器码。该机器码用于标识唯一设备，
    是激活密钥生成和验证的基础。

    算法: MD5("{mac_address}-{hostname}-{disk_serial}") 的前16位

    结果会被缓存，避免重复调用wmic等慢速命令。

    Returns:
        str: 16位大写十六进制机器码，例如 "A1B2C3D4E5F67890"
    """
    global _machine_code_cache
    if _machine_code_cache is not None:
        return _machine_code_cache

    mac = _get_mac_address()
    hostname = _get_hostname()
    disk_serial = _get_disk_serial()

    raw = f"{mac}-{hostname}-{disk_serial}"
    machine_code = hashlib.md5(raw.encode()).hexdigest()[:16].upper()
    _machine_code_cache = machine_code
    return machine_code


# ============================================================
# 激活密钥生成与验证
# ============================================================

def _format_key(hex_str):
    """
    将十六进制字符串格式化为 XXXX-XXXX-XXXX-XXXX 格式

    Args:
        hex_str: 16位十六进制字符串

    Returns:
        str: 格式化后的密钥字符串，例如 "A1B2-C3D4-E5F6-7890"
    """
    return "-".join(hex_str[i:i+4] for i in range(0, 16, 4))


def _unformat_key(formatted_key):
    """
    将 XXXX-XXXX-XXXX-XXXX 格式的密钥转换为纯十六进制字符串

    Args:
        formatted_key: 格式化后的密钥字符串

    Returns:
        str: 16位大写十六进制字符串
    """
    return formatted_key.replace("-", "").upper()


def generate_key(machine_code, license_type=LICENSE_TYPE_STANDARD, expiry_date=None):
    """
    根据机器码和许可证类型生成激活密钥

    使用HMAC-SHA256算法，以SECRET_KEY为密钥，以机器码（+可选过期日期）
    为消息生成激活码。对于有有效期的许可证类型，过期日期会参与HMAC计算，
    确保密钥与特定过期日期绑定。

    Args:
        machine_code (str): 16位大写十六进制机器码
        license_type (str): 许可证类型，可选值:
            - "trial": 试用版（7天）
            - "standard": 标准版（1年），默认值
            - "lifetime": 终身版（永不过期）
        expiry_date (str, optional): 过期日期，格式为 "YYYY-MM-DD"。
            如果为None，则根据license_type自动计算:
            - trial: 从今天起7天后
            - standard: 从今天起365天后
            - lifetime: 无过期日期

    Returns:
        dict: 包含以下键的字典:
            - "activation_key": 格式化的激活密钥 (XXXX-XXXX-XXXX-XXXX)
            - "license_type": 许可证类型
            - "expiry_date": 过期日期字符串（终身版为None）
            - "machine_code": 机器码

    Raises:
        ValueError: 当machine_code格式无效或license_type不支持时
    """
    # 验证机器码格式
    clean_code = machine_code.replace("-", "").upper()
    if len(clean_code) != 16:
        raise ValueError(f"机器码长度必须为16个字符，当前为 {len(clean_code)} 个字符")

    if not all(c in "0123456789ABCDEF" for c in clean_code):
        raise ValueError("机器码必须为有效的十六进制字符")

    # 验证许可证类型
    if license_type not in LICENSE_DURATION:
        raise ValueError(
            f"不支持的许可证类型: {license_type}，"
            f"可选值: {', '.join(LICENSE_DURATION.keys())}"
        )

    # 计算过期日期
    if expiry_date is None:
        duration = LICENSE_DURATION[license_type]
        if duration is None:
            expiry_date = None  # 终身版
        else:
            expiry = datetime.date.today() + datetime.timedelta(days=duration)
            expiry_date = expiry.isoformat()
    else:
        # 验证传入的过期日期格式
        try:
            datetime.date.fromisoformat(expiry_date)
        except ValueError:
            raise ValueError(f"过期日期格式无效，应为 YYYY-MM-DD: {expiry_date}")

    # 生成HMAC消息：机器码 + 过期日期（如有）
    message = clean_code
    if expiry_date:
        message = f"{clean_code}{expiry_date}"

    # 使用HMAC-SHA256生成激活码
    hmac_digest = hmac.new(SECRET_KEY, message.encode(), hashlib.sha256).hexdigest()[:16].upper()

    # 格式化为 XXXX-XXXX-XXXX-XXXX
    formatted_key = _format_key(hmac_digest)

    return {
        "activation_key": formatted_key,
        "license_type": license_type,
        "expiry_date": expiry_date,
        "machine_code": clean_code,
    }


def validate_key(machine_code, key):
    """
    验证激活密钥是否与机器码匹配

    根据激活密钥反推可能的许可证类型和过期日期，然后使用相同的HMAC算法
    重新生成密钥进行比对。该方法会尝试所有可能的许可证类型进行匹配。

    对于有过期日期的许可证，会验证过期日期是否仍然有效（未过期）。

    Args:
        machine_code (str): 16位大写十六进制机器码
        key (str): 待验证的激活密钥（支持 XXXX-XXXX-XXXX-XXXX 或16位纯字符格式）

    Returns:
        dict: 验证结果字典，包含以下键:
            - "valid" (bool): 是否验证通过
            - "license_type" (str|None): 许可证类型（验证通过时）
            - "expiry_date" (str|None): 过期日期（验证通过时）
            - "error" (str|None): 错误信息（验证失败时）
    """
    # 清理和验证机器码
    clean_code = machine_code.replace("-", "").upper()
    if len(clean_code) != 16 or not all(c in "0123456789ABCDEF" for c in clean_code):
        return {"valid": False, "license_type": None, "expiry_date": None,
                "error": "机器码格式无效"}

    # 清理和验证激活密钥
    clean_key = _unformat_key(key)
    if len(clean_key) != 16 or not all(c in "0123456789ABCDEF" for c in clean_key):
        return {"valid": False, "license_type": None, "expiry_date": None,
                "error": "激活密钥格式无效"}

    # 尝试1：匹配终身版密钥（无过期日期）
    hmac_lifetime = hmac.new(
        SECRET_KEY, clean_code.encode(), hashlib.sha256
    ).hexdigest()[:16].upper()

    if hmac_lifetime == clean_key:
        return {
            "valid": True,
            "license_type": LICENSE_TYPE_LIFETIME,
            "expiry_date": None,
            "error": None,
        }

    # 尝试2：匹配有有效期的密钥
    # 需要遍历可能的过期日期来匹配
    # 优化策略：先搜索近30天范围（最常见），找不到再扩大到400天
    today = datetime.date.today()

    # 收集有有效期的许可证类型
    timed_types = [(lt, dur) for lt, dur in LICENSE_DURATION.items() if dur is not None]

    # 分两轮搜索：第一轮近30天（快），第二轮400天（慢但全面）
    for search_range_days in [30, 400]:
        for license_type, duration in timed_types:
            start_search = today - datetime.timedelta(days=search_range_days)
            end_search = today + datetime.timedelta(days=duration + 30)

            current = start_search
            while current <= end_search:
                expiry_str = current.isoformat()
                message = f"{clean_code}{expiry_str}"
                hmac_check = hmac.new(
                    SECRET_KEY, message.encode(), hashlib.sha256
                ).hexdigest()[:16].upper()

                if hmac_check == clean_key:
                    # 验证是否过期
                    if current < today:
                        return {
                            "valid": False,
                            "license_type": license_type,
                            "expiry_date": expiry_str,
                            "error": "许可证已过期",
                        }
                    return {
                        "valid": True,
                        "license_type": license_type,
                        "expiry_date": expiry_str,
                        "error": None,
                    }
                current += datetime.timedelta(days=1)

    return {
        "valid": False,
        "license_type": None,
        "expiry_date": None,
        "error": "激活密钥与机器码不匹配",
    }


def _validate_key_fast(machine_code, key, license_type, expiry_date):
    """
    快速验证已知许可证类型和过期日期的激活密钥

    此方法用于内部快速校验，不需要遍历日期范围。
    当许可证信息已存储时使用。

    Args:
        machine_code (str): 机器码
        key (str): 激活密钥
        license_type (str): 许可证类型
        expiry_date (str|None): 过期日期

    Returns:
        bool: 密钥是否有效
    """
    clean_code = machine_code.replace("-", "").upper()
    clean_key = _unformat_key(key)

    # 构建HMAC消息
    if expiry_date:
        message = f"{clean_code}{expiry_date}"
    else:
        message = clean_code

    expected = hmac.new(
        SECRET_KEY, message.encode(), hashlib.sha256
    ).hexdigest()[:16].upper()

    return expected == clean_key


# ============================================================
# 许可证数据存储
# ============================================================

def _ensure_license_dir():
    """
    确保许可证存储目录存在

    如果目录不存在则创建，包括所有必要的父目录。
    目录路径为 ~/.hikvision_downloader/
    """
    os.makedirs(LICENSE_DIR, exist_ok=True)


def _compute_data_hash(data_str):
    """
    计算数据的校验哈希值

    使用SHA256算法对数据字符串计算哈希，用于检测数据是否被篡改。

    Args:
        data_str (str): 待计算哈希的数据字符串

    Returns:
        str: 32位十六进制哈希值
    """
    return hashlib.sha256(data_str.encode()).hexdigest()


def _save_license_data(data):
    """
    将许可证数据保存到文件

    数据以JSON格式序列化后，添加校验哈希，再整体进行Base64编码存储。
    这种方式可以：
    1. 防止普通用户直接编辑文件
    2. 通过校验哈希检测文件篡改
    3. 保持数据可读性（Base64解码后即为JSON）

    存储格式（Base64解码后）:
    {
        "hash": "<数据校验哈希>",
        "data": <实际许可证数据>
    }

    Args:
        data (dict): 许可证数据字典，应包含:
            - machine_code: 机器码
            - activation_key: 激活密钥
            - license_type: 许可证类型
            - expiry_date: 过期日期
            - registered_date: 注册日期
    """
    _ensure_license_dir()

    # 序列化数据部分
    data_str = json.dumps(data, sort_keys=True, ensure_ascii=False)

    # 计算校验哈希
    data_hash = _compute_data_hash(data_str)

    # 构建存储结构
    storage = {
        "hash": data_hash,
        "data": data,
    }

    # Base64编码
    storage_str = json.dumps(storage, sort_keys=True, ensure_ascii=False)
    encoded = base64.b64encode(storage_str.encode()).decode()

    # 写入文件
    with open(LICENSE_FILE, "w", encoding="utf-8") as f:
        f.write(encoded)


def _load_license_data():
    """
    从文件加载许可证数据

    读取Base64编码的文件内容，解码并验证数据完整性。
    如果文件不存在、格式错误或数据被篡改，返回None。

    Returns:
        dict|None: 许可证数据字典，加载失败返回None。包含:
            - machine_code: 机器码
            - activation_key: 激活密钥
            - license_type: 许可证类型
            - expiry_date: 过期日期
            - registered_date: 注册日期
    """
    if not os.path.exists(LICENSE_FILE):
        return None

    try:
        with open(LICENSE_FILE, "r", encoding="utf-8") as f:
            encoded = f.read().strip()

        # Base64解码
        storage_str = base64.b64decode(encoded).decode()
        storage = json.loads(storage_str)

        # 验证结构
        if "hash" not in storage or "data" not in storage:
            return None

        # 验证数据完整性
        data_str = json.dumps(storage["data"], sort_keys=True, ensure_ascii=False)
        expected_hash = _compute_data_hash(data_str)

        if storage["hash"] != expected_hash:
            # 数据被篡改
            return None

        return storage["data"]

    except Exception:
        return None


# ============================================================
# 试用模式管理
# ============================================================

def _get_trial_start_date():
    """
    获取试用开始日期

    从隐藏文件 ~/.hikvision_downloader/.trial_info 中读取首次运行日期。
    如果文件不存在，说明尚未开始试用，返回None。

    Returns:
        str|None: 试用开始日期（ISO格式 YYYY-MM-DD），未开始试用返回None
    """
    if not os.path.exists(TRIAL_FILE):
        return None

    try:
        with open(TRIAL_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()

        # 解码Base64
        decoded = base64.b64decode(content).decode()
        trial_info = json.loads(decoded)

        # 验证数据完整性
        if "start_date" in trial_info and "hash" in trial_info:
            data_str = trial_info["start_date"]
            expected_hash = _compute_data_hash(data_str)
            if trial_info["hash"] == expected_hash:
                return trial_info["start_date"]

        return None
    except Exception:
        return None


def _record_trial_start():
    """
    记录试用开始日期

    将当前日期记录到隐藏文件中。如果文件已存在，不做任何操作。
    日期信息使用Base64编码存储，并附加校验哈希以防篡改。

    存储格式（Base64解码后）:
    {
        "start_date": "YYYY-MM-DD",
        "hash": "<校验哈希>"
    }
    """
    if os.path.exists(TRIAL_FILE):
        return

    _ensure_license_dir()

    today = datetime.date.today().isoformat()
    data_hash = _compute_data_hash(today)

    trial_info = {
        "start_date": today,
        "hash": data_hash,
    }

    # Base64编码
    info_str = json.dumps(trial_info, ensure_ascii=False)
    encoded = base64.b64encode(info_str.encode()).decode()

    with open(TRIAL_FILE, "w", encoding="utf-8") as f:
        f.write(encoded)


def is_trial_valid():
    """
    检查试用模式是否仍然有效

    试用模式规则：
    1. 如果已经注册，则不需要试用（返回True）
    2. 如果从未运行过，自动开始7天试用
    3. 如果试用期内，返回True
    4. 如果试用期已过，返回False

    注意：此方法会自动记录首次运行日期（如果尚未记录）。

    Returns:
        bool: 试用是否有效
    """
    # 已注册则不需要试用
    if is_registered():
        return True

    # 获取或记录试用开始日期
    start_date_str = _get_trial_start_date()
    if start_date_str is None:
        _record_trial_start()
        start_date_str = datetime.date.today().isoformat()

    # 计算剩余天数
    try:
        start_date = datetime.date.fromisoformat(start_date_str)
        today = datetime.date.today()
        elapsed = (today - start_date).days

        return elapsed < TRIAL_DAYS
    except Exception:
        return False


def get_remaining_days():
    """
    获取剩余有效天数

    优先级：
    1. 如果已注册且有过期日期，返回许可证到期剩余天数
    2. 如果已注册且为终身版，返回None表示永不过期
    3. 如果在试用期内，返回试用剩余天数
    4. 如果试用已过期，返回0

    Returns:
        int|None: 剩余天数，None表示永不过期，0表示已过期
    """
    # 检查已注册的许可证
    license_data = _load_license_data()
    if license_data:
        expiry_date_str = license_data.get("expiry_date")
        if expiry_date_str is None:
            # 终身版
            return None

        try:
            expiry_date = datetime.date.fromisoformat(expiry_date_str)
            remaining = (expiry_date - datetime.date.today()).days
            return max(0, remaining)
        except Exception:
            return 0

    # 检查试用
    start_date_str = _get_trial_start_date()
    if start_date_str is None:
        _record_trial_start()
        start_date_str = datetime.date.today().isoformat()

    try:
        start_date = datetime.date.fromisoformat(start_date_str)
        trial_end = start_date + datetime.timedelta(days=TRIAL_DAYS)
        remaining = (trial_end - datetime.date.today()).days
        return max(0, remaining)
    except Exception:
        return 0


# ============================================================
# 注册管理
# ============================================================

def is_registered():
    """
    检查当前设备是否已有效注册

    验证流程：
    1. 加载存储的许可证数据
    2. 验证机器码是否匹配当前设备
    3. 验证激活密钥是否有效
    4. 验证许可证是否未过期

    Returns:
        bool: 是否已有效注册
    """
    license_data = _load_license_data()
    if not license_data:
        return False

    # 验证机器码
    current_machine_code = get_machine_code()
    stored_machine_code = license_data.get("machine_code", "").replace("-", "").upper()
    if current_machine_code != stored_machine_code:
        return False

    # 快速验证激活密钥
    activation_key = license_data.get("activation_key", "")
    license_type = license_data.get("license_type", "")
    expiry_date = license_data.get("expiry_date")

    if not _validate_key_fast(current_machine_code, activation_key, license_type, expiry_date):
        return False

    # 验证过期日期
    if expiry_date:
        try:
            expiry = datetime.date.fromisoformat(expiry_date)
            if expiry < datetime.date.today():
                return False
        except Exception:
            return False

    return True


def is_registered_quick():
    """
    快速检查是否已注册（使用缓存的机器码，不重复调用get_machine_code）

    适用于在已获取过机器码的上下文中调用，避免重复的硬件查询。

    Returns:
        bool: 是否已有效注册
    """
    license_data = _load_license_data()
    if not license_data:
        return False

    current_machine_code = get_machine_code()  # 使用缓存
    stored_machine_code = license_data.get("machine_code", "").replace("-", "").upper()
    if current_machine_code != stored_machine_code:
        return False

    activation_key = license_data.get("activation_key", "")
    license_type = license_data.get("license_type", "")
    expiry_date = license_data.get("expiry_date")

    if not _validate_key_fast(current_machine_code, activation_key, license_type, expiry_date):
        return False

    if expiry_date:
        try:
            expiry = datetime.date.fromisoformat(expiry_date)
            if expiry < datetime.date.today():
                return False
        except Exception:
            return False

    return True


def register(machine_code, key):
    """
    使用激活密钥注册设备

    注册流程：
    1. 验证激活密钥是否与提供的机器码匹配
    2. 验证许可证是否未过期
    3. 保存注册信息到本地文件

    Args:
        machine_code (str): 当前设备的机器码
        key (str): 激活密钥（XXXX-XXXX-XXXX-XXXX 格式）

    Returns:
        dict: 注册结果字典，包含以下键:
            - "success" (bool): 是否注册成功
            - "message" (str): 结果消息
            - "license_type" (str|None): 许可证类型（成功时）
            - "expiry_date" (str|None): 过期日期（成功时）
    """
    # 验证密钥
    result = validate_key(machine_code, key)

    if not result["valid"]:
        return {
            "success": False,
            "message": result.get("error", "激活密钥无效"),
            "license_type": None,
            "expiry_date": None,
        }

    # 保存注册信息
    license_data = {
        "machine_code": machine_code.replace("-", "").upper(),
        "activation_key": _unformat_key(key),
        "license_type": result["license_type"],
        "expiry_date": result.get("expiry_date"),
        "registered_date": datetime.date.today().isoformat(),
    }

    try:
        _save_license_data(license_data)
    except Exception as e:
        return {
            "success": False,
            "message": f"保存注册信息失败: {str(e)}",
            "license_type": None,
            "expiry_date": None,
        }

    type_names = {
        LICENSE_TYPE_TRIAL: "试用版",
        LICENSE_TYPE_STANDARD: "标准版",
        LICENSE_TYPE_LIFETIME: "终身版",
    }
    type_name = type_names.get(result["license_type"], result["license_type"])

    return {
        "success": True,
        "message": f"注册成功！许可证类型: {type_name}",
        "license_type": result["license_type"],
        "expiry_date": result.get("expiry_date"),
    }


def get_license_info():
    """
    获取当前许可证详细信息

    返回包含当前许可证状态的所有信息，包括注册信息、试用信息等。

    Returns:
        dict: 许可证信息字典，包含以下键:
            - "registered" (bool): 是否已注册
            - "machine_code" (str): 当前设备机器码
            - "license_type" (str|None): 许可证类型
            - "expiry_date" (str|None): 过期日期
            - "registered_date" (str|None): 注册日期
            - "remaining_days" (int|None): 剩余天数（None=永不过期）
            - "trial_valid" (bool): 试用是否有效
            - "trial_start" (str|None): 试用开始日期
    """
    current_machine_code = get_machine_code()

    info = {
        "registered": False,
        "machine_code": current_machine_code,
        "license_type": None,
        "expiry_date": None,
        "registered_date": None,
        "remaining_days": 0,
        "trial_valid": False,
        "trial_start": None,
    }

    # 尝试加载已注册的许可证
    license_data = _load_license_data()
    if license_data:
        info["license_type"] = license_data.get("license_type")
        info["expiry_date"] = license_data.get("expiry_date")
        info["registered_date"] = license_data.get("registered_date")

        # 检查是否仍然有效
        if is_registered():
            info["registered"] = True
            info["remaining_days"] = get_remaining_days()

    # 试用信息
    trial_start = _get_trial_start_date()
    if trial_start:
        info["trial_start"] = trial_start
        info["trial_valid"] = is_trial_valid()
        if not info["registered"]:
            info["remaining_days"] = get_remaining_days()

    return info


def unregister():
    """
    取消当前注册

    删除许可证文件，将设备恢复到未注册状态。
    试用信息不会被清除。

    Returns:
        bool: 是否成功取消注册
    """
    try:
        if os.path.exists(LICENSE_FILE):
            os.remove(LICENSE_FILE)
            return True
        return False
    except Exception:
        return False


# ============================================================
# 命令行工具
# ============================================================

def main():
    """
    命令行入口函数

    提供以下命令行功能：
    - --generate: 生成激活密钥
    - --machine-code: 指定机器码（与--generate配合使用）
    - --type: 指定许可证类型（trial/standard/lifetime，默认standard）
    - --expiry: 指定过期日期（YYYY-MM-DD格式，可选）
    - --show-machine-code: 显示当前设备的机器码
    - --check: 检查当前设备的许可证状态

    使用示例:
        # 显示当前设备机器码
        python -m core.license_manager --show-machine-code

        # 为指定机器码生成标准版密钥
        python -m core.license_manager --generate --machine-code A1B2C3D4E5F67890 --type standard

        # 为指定机器码生成终身版密钥
        python -m core.license_manager --generate --machine-code A1B2C3D4E5F67890 --type lifetime

        # 检查当前许可证状态
        python -m core.license_manager --check
    """
    parser = argparse.ArgumentParser(
        description="海康威视下载器 - 许可证管理工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --show-machine-code          显示当前设备机器码
  %(prog)s --generate -m A1B2C3D4E5F67890 -t standard   生成标准版密钥
  %(prog)s --generate -m A1B2C3D4E5F67890 -t lifetime    生成终身版密钥
  %(prog)s --check                       检查许可证状态
        """,
    )

    parser.add_argument(
        "--generate", "-g",
        action="store_true",
        help="生成激活密钥"
    )
    parser.add_argument(
        "--machine-code", "-m",
        type=str,
        help="机器码（16位十六进制字符）"
    )
    parser.add_argument(
        "--type", "-t",
        type=str,
        choices=["trial", "standard", "lifetime"],
        default="standard",
        help="许可证类型（默认: standard）"
    )
    parser.add_argument(
        "--expiry", "-e",
        type=str,
        help="过期日期（YYYY-MM-DD格式，可选）"
    )
    parser.add_argument(
        "--show-machine-code", "-s",
        action="store_true",
        help="显示当前设备的机器码"
    )
    parser.add_argument(
        "--check", "-c",
        action="store_true",
        help="检查当前设备的许可证状态"
    )

    args = parser.parse_args()

    # 显示机器码
    if args.show_machine_code:
        mc = get_machine_code()
        print(f"当前设备机器码: {mc}")
        return

    # 检查许可证状态
    if args.check:
        info = get_license_info()
        print("=" * 50)
        print("许可证状态检查")
        print("=" * 50)
        print(f"机器码: {info['machine_code']}")

        if info["registered"]:
            type_names = {
                LICENSE_TYPE_TRIAL: "试用版",
                LICENSE_TYPE_STANDARD: "标准版",
                LICENSE_TYPE_LIFETIME: "终身版",
            }
            type_name = type_names.get(info["license_type"], info["license_type"])
            print(f"状态: 已注册")
            print(f"许可证类型: {type_name}")
            print(f"注册日期: {info['registered_date']}")
            print(f"过期日期: {info['expiry_date'] or '永不过期'}")
            if info["remaining_days"] is None:
                print(f"剩余天数: 永不过期")
            else:
                print(f"剩余天数: {info['remaining_days']} 天")
        elif info["trial_valid"]:
            print(f"状态: 试用中")
            print(f"试用开始: {info['trial_start']}")
            print(f"剩余天数: {info['remaining_days']} 天")
        else:
            print(f"状态: 未注册（试用期已过期）")
        print("=" * 50)
        return

    # 生成密钥
    if args.generate:
        if not args.machine_code:
            print("错误: 生成密钥需要指定机器码 (--machine-code / -m)")
            sys.exit(1)

        try:
            result = generate_key(
                args.machine_code,
                license_type=args.type,
                expiry_date=args.expiry,
            )
            print("=" * 50)
            print("激活密钥已生成")
            print("=" * 50)
            print(f"机器码: {result['machine_code']}")
            print(f"激活密钥: {result['activation_key']}")
            type_names = {
                LICENSE_TYPE_TRIAL: "试用版（7天）",
                LICENSE_TYPE_STANDARD: "标准版（1年）",
                LICENSE_TYPE_LIFETIME: "终身版",
            }
            print(f"许可证类型: {type_names.get(result['license_type'], result['license_type'])}")
            print(f"过期日期: {result['expiry_date'] or '永不过期'}")
            print("=" * 50)
            print()
            print("请将以上激活密钥发送给用户进行注册。")
        except ValueError as e:
            print(f"错误: {e}")
            sys.exit(1)
        return

    # 没有指定任何操作，显示帮助
    parser.print_help()


if __name__ == "__main__":
    main()
