MiniEAP
=======

这是一个实现了标准 EAP-MD5-Challenge 算法的 EAP 客户端，支持通过插件来修改标准数据包以通过特殊服务端的认证。目前带有一个实现锐捷 v3 (v4) 算法的插件。本插件的认证算法来自 [Hu Yunrui 的 MentoHUST 项目](https://github.com/hyrathb/mentohust)，在此表示感谢！

## 特性

#### 通用特性

* 模块化设计
可通过 CMake 选项选择所需模块（网卡实现、数据包插件、iconv/gbconv 等）。

* 网络帧收发由插件模块完成
可根据平台差异使用不同的插件。目前提供 `libpcap`（Windows 上为 Npcap）、Linux Raw Socket（`sockraw`）以及 macOS/BSD BPF 三种插件。前者兼容性好，但需链接 `libpcap`/`wpcap`；`sockraw` 不需额外动态库，但只能在 Linux 上使用。可选择任意个模块参与编译，但运行时只能选取其中之一来使用。

* 数据包修改同样由插件完成
可以在不修改主要认证流程的情况下适配各种环境。可以启用多个插件，也可将一个插件启用多次。程序会让标准 EAP 算法生成的数据包按照命令行中 `--module` 参数的顺序让数据包流经这些插件。目前提供一个锐捷 v3 认证算法插件和一个打印流经的数据包大小的示例插件。

* 所有数据包生成逻辑均采用结构体对缓冲区进行读写，拒绝 magic number 从我做起！

#### 锐捷插件特性

* 认证算法来自 [Hu Yunrui 的 MentoHUST 项目](https://github.com/hyrathb/mentohust)
* 相比原本的 MentoHUST v3 (v4) 实现，能够支持更多的字段，更容易通过验证。
* 二次认证时，支持位于修改常规字段以外的 IP 地址、网关、主 DNS 等信息，更容易通过验证。
* 所有字段都通过收集来的信息直接构造而成，不采用修改数据包模板的方式，避免各场景下偏移量不同导致的认证失败或数据包无法解析问题。
* 所有字段生成逻辑均采用结构体对缓冲区进行读写，拒绝 magic number 从我做起 x2！
* 字段中所用到的常量都有宏定义来注明其含义，定长字段的长度也通过宏定义声明，拒绝 magic number 从我做起 x3！
* 支持通过命令行来附加新的字段，也可覆盖程序生成的字段。可以在不修改代码的情况下进行适配。
* 整体程序的内存占用比 MentoHUST 小约 78%（在 256 MB 内存的 ARMv7 平台上测试）。

## 编译

需要 [CMake](https://cmake.org/) 3.20 或更高版本。

### Linux

默认启用 `sockraw`，不链接 libpcap：

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

可执行文件为 `build/minieap`。

常用选项：

* `-DENABLE_IF_IMPL_SOCKRAW=ON|OFF`（Linux 默认 ON）
* `-DENABLE_IF_IMPL_LIBPCAP=ON|OFF`（Linux 默认 OFF；开启时需系统已安装 libpcap 开发包）
* `-DENABLE_IF_IMPL_BPF=ON|OFF`（macOS/BSD 默认 ON）
* `-DENABLE_PACKET_PLUGIN_RJV3=ON|OFF`
* `-DENABLE_ICONV=ON|OFF`（Unix 默认 ON）
* `-DENABLE_DEBUG=ON` 打开调试日志

若平台提供 `iconv` 但仍乱码，确认 `ENABLE_ICONV` 为 ON。glibc 一般无需单独链接 libiconv；macOS 等独立 libiconv 时 CMake 会自动查找。

### Windows

Windows 最低版本为 Windows 8 / Windows Server 2012（使用 `PowerRegisterSuspendResumeNotification` 电源通知 API）。

1. 安装 [Npcap](https://npcap.com/) **运行时**，安装时勾选 WinPcap API 兼容模式。仅有 SDK 无法在运行时加载 `wpcap.dll`。
2. 使用 MSVC（Visual Studio）或 MinGW-w64，以及 CMake 3.20+。
3. 配置并编译（Npcap SDK 会在配置阶段自动从官网下载；也可预先解压 SDK 后指定 `-DNPCAP_SDK_DIR=`）：

```
cmake -S . -B build
cmake --build build --config Release
```

Visual Studio 生成器下可执行文件为 `build/Release/minieap.exe`；Ninja/MinGW 一般为 `build/minieap.exe`。

Windows 上强制启用 `libpcap` if_impl（链接 Npcap 的 `wpcap` / `Packet`），并默认使用内置 GBK 转换（`ENABLE_GBCONV`）。不支持 WinDivert 或 raw socket if_impl。CMake 安装不会自动注册 Windows 服务；服务部署文件位于 `deploy/`。

配置文件、PID、日志默认写在当前目录：`minieap.conf`、`minieap.pid`、`minieap.log`。

#### 睡眠 / 休眠恢复

Windows 下接收系统挂起、恢复及所选网卡的接口变化通知。电源事件使旧会话失效；接口通知只要求主线程重新检查链路，不因正常 DHCP 或 IPv6 地址变化中断认证。主线程还每秒检查所选接口是否启用、媒体是否连接，捕获或发送未报错也能发现断链。

漏掉电源通知时，程序比较包含睡眠时间和不包含睡眠时间的两个单调时钟；差值超过 2 秒即重建旧会话。对现代待机造成的进程暂停，若原本 100ms 的捕获等待超过 30 秒，也会重建会话；同步 DHCP 脚本耗时不计入该等待。重建由主线程关闭旧捕获句柄、清除 EAP / 锐捷会话及所有旧定时任务，再重新发送 EAPOL-Start。以上检测不能证明远端在线；若本地链路与时钟均无变化、服务器静默清除会话且收发不报错，仍没有可靠的协议离线信号，不能仅凭收不到 EAP 包判定掉线。

网卡尚未恢复、捕获出错、发包失败或认证阶段重试耗尽时，程序会清理会话并每隔 5 秒重新尝试。网卡就绪检查只要求接口启用且媒体已连接，不等待 IP 地址或 802.1X 认证成功。直接运行 EXE 和 WinSW 服务模式均使用此进程内恢复路径；配置错误、达到最大认证失败次数、禁止掉线重认证等原有退出策略仍保留。

RJv3 在地址尚未分配或地址查询失败时使用全零 IPv6 字段，不会因空地址列表崩溃。MD5 请求与 DHCP 二次认证所需报文由插件独立持有，不跨异步阶段借用状态机已释放的报文。`heartbeat=0` 完全禁用心跳，包括初始发送及已排队的发送回调。

可选的 Windows 回归验证（需要启用默认的 RJv3 插件及安装 Npcap 运行时）：

```
cmake -S . -B build -DMINIEAP_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

验证程序使用真实主循环、状态机、RJv3 构包、DHCP 流程、定时器和心跳代码，注入电源/接口事件、睡眠时钟、进程暂停与适配器故障，并检查原生通知注册/注销。覆盖无地址构包、正常地址变化不重认证、延迟二次认证、MD5 请求释放后的重发及零心跳间隔；不会发送真实认证报文或让电脑睡眠。真实网卡的睡眠 / 休眠恢复仍需在目标网络上实测。

## 运行

具体选项请参阅 `minieap -h` 的输出。这里列出必需的几个选项。

* `-u 用户名`
* `-p 密码`
* `-n 网卡名`

Linux 默认的网络帧收发模块是 `sockraw`。如果要使用其他模块，如 `libpcap`，则必须指定 `--if-impl libpcap`。

Windows 只有 `libpcap` 模块（底层为 Npcap），无需再指定 `--if-impl`。网卡名请使用 Npcap 设备名，例如 `\Device\NPF_{GUID}`，也可使用适配器友好名称。省略 `-n` 时会打印本机 Npcap 设备列表。抓包/802.1X 需要**以管理员身份**运行。

默认不使用任何数据包修改器，将只会发送单纯的标准 EAP 数据包。 **如需使用锐捷认证，则必须指定 `--module rjv3`。** 可以指定多个 `--module` 参数，程序会按参数的顺序让数据包流经这些插件。

参数格式支持如下几种：

* `-u myname`
* `--username myname`

注意：暂不支持 `-umyname` 这种形式，这在插件的命令行解析中将带来错误。

示例：在 en0 上使用锐捷认证，以 `libpcap` 作为网络帧收发模块，并且在数据包流经锐捷认证插件前后都打印出数据包的大小：

```
minieap -u 201000000 -p 15000000000 -n en0 --module printer --module rjv3 --module printer --if-impl libpcap
```

Windows 示例（将网卡名换成 `minieap -u x -p y` 列出的 `\Device\NPF_...`）：

```
minieap.exe -u 201000000 -p 15000000000 -n "\Device\NPF_{GUID}" --module rjv3
```

## 注意事项

本项目刚成立不久，虽然有过测试，但无法保证高可靠性。欢迎大家提出意见，谢谢！

非常感谢 HustMoon 工作室以及 Hu Yunrui 同学对这个领域做出的贡献！
