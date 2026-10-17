# Android Netlink Privacy Fix

恢复 Android SELinux 策略的 Netlink 隐私标志，限制普通应用通过 `RTM_GETLINK` 读取网卡信息。适用于策略重载后隐私限制异常失效的情况。

守护程序先以普通应用域执行探针。只有 SELinux 为 Enforcing、原厂策略包含对应标志、探针确认限制失效时，才恢复当前策略的两个配置位。现有访问规则保持原样。之后阻塞等待策略事件，不定时轮询。

## 使用

需要 ARM64 Android、root 和支持模块服务脚本的管理器。安装 Releases 中的 ZIP，按管理器要求加载模块。操作按钮显示 `PROTECTED`、`EXPOSED` 或无法确定的状态。

日志与修复前策略备份保存在模块自己的 `state/` 目录。卸载会停止守护程序；已经加载的内存策略在下一次策略重载或重启前仍可能生效。

## 构建

安装 Python 3、Android NDK 29，然后设置 `ANDROID_HOME`，运行 `python build.py`。需要指定其他 NDK 时设置 `ANDROID_NDK_HOME`。

实机观察来自 iQOO 15 / OriginOS 6 和 OPPO Find N3 Flip / ColorOS 16。检测结果只能说明这一条 Netlink 路径的状态。

## 许可证

原有代码采用 GPL-3.0-only，Copyright (C) 2026 Axuan。第三方代码遵循各自许可证，见 [THIRD_PARTY.md](THIRD_PARTY.md)。

版本 `v1.1.0`，包名 / 模块 ID：`android_netlink_privacy_fix`。
