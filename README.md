# PassFiltEx (自定义 AD 密码过滤 DLL)

本项目实现了可部署到 Active Directory 域控上的密码过滤 DLL（`PassFiltEx.dll`），并参考微软官方 Password Filter 说明实现接口与校验流程。

## 已实现策略

1. 必须同时包含 4 类字符：`a-z`、`A-Z`、`0-9`、符号。
2. 不允许出现 3 个连续字符（`0-9`、`a-z`，忽略大小写）。
   - 数字按环形连续判断，`890` 也会被拦截（可配置关闭）。
3. 不允许出现 3 个重复字符（`0-9`、`a-z`、`Shift+0-9` 对应键，忽略大小写）。
   - 拦截 `aaa` / `111`，也拦截 `BbB` / `Qgq` 这类首尾重复模式。
4. 不允许出现 4 个纵向连续键盘字符（QWERTY），例如：`1qaz`、`@WSX`、`0okm`、`PL<`。
5. 密码标准化（用于字典检查）：
   - 大写转小写
   - `0 -> o`
   - `1 -> l`
   - `$ -> s`
   - `@ -> a`
6. 不允许包含字典中的单词：
   - 内置词：`pass`、`root`、`admin`、`qwer`、`asdf`、`iloveyou`
   - 扩展词：默认 `%SystemRoot%\System32\PassFiltExDict.txt`
7. 可选启用微软建议项：密码不应包含账号名或全名 token（长度 >= 3）。

---

## 推荐的“科学可运维”方案：注册表开关化

你提出的需求非常适合做成“默认全开 + 注册表按项可关闭/可调”的模型：

- **默认安全基线不变**：所有策略默认启用。
- **分阶段上线更稳妥**：可以先只启用部分策略观察影响，再逐步打开。
- **便于排障**：遇到业务系统兼容性问题，可临时关闭单条规则而不回滚 DLL。

本项目已支持在以下注册表路径读取策略：

- `HKLM\SYSTEM\CurrentControlSet\Services\PassFiltEx\Parameters`

支持的 `DWORD` 开关（`1=启用`, `0=关闭`）：

- `RequireCharClasses`
- `BlockConsecutive3`
- `BlockRepeated3`
- `BlockVerticalKeyboard4`
- `EnableDictionaryCheck`
- `EnableAccountNameCheck`
- `EnableFullNameCheck`
- `DigitWrapSequence`（控制是否将 `890` 视为连续数字）

可选字符串配置：

- `DictionaryPath`（`REG_SZ`，自定义词典路径；未配置则使用 `%SystemRoot%\System32\PassFiltExDict.txt`）

> 建议生产环境保留所有开关为 `1`，仅在灰度或排障期间临时关闭，问题确认后恢复。

### 注册表示例（PowerShell）

```powershell
$base = 'HKLM:\SYSTEM\CurrentControlSet\Services\PassFiltEx\Parameters'
New-Item -Path $base -Force | Out-Null

New-ItemProperty -Path $base -Name RequireCharClasses -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $base -Name BlockConsecutive3 -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $base -Name BlockRepeated3 -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $base -Name BlockVerticalKeyboard4 -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $base -Name EnableDictionaryCheck -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $base -Name EnableAccountNameCheck -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $base -Name EnableFullNameCheck -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $base -Name DigitWrapSequence -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $base -Name DictionaryPath -Value 'C:\Windows\System32\PassFiltExDict.txt' -PropertyType String -Force | Out-Null
```

---

## 构建

### Windows (生成 DLL)

```bash
cmake -S . -B build -DPASSFILTEX_BUILD_TESTS=ON
cmake --build build --config Release
```

在 Windows 上会生成：`PassFiltEx.dll`

### Windows 一键构建脚本（推荐）

仓库已提供脚本：`scripts/build-windows.ps1`

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-windows.ps1
```

可选参数：

- `-Configuration Release|Debug`
- `-Arch x64`（默认）
- `-SkipTests`（仅构建 DLL，不跑单测）

脚本会自动：

1. 检测 Visual Studio C++ 工具链（通过 `vswhere` + `VsDevCmd.bat`）
2. 生成并构建工程
3. 运行 `password_policy_test.exe`（默认）
4. 校验 `PassFiltEx.dll` 是否生成并输出 SHA256

### Linux/CI (仅验证策略核心)

```bash
cmake -S . -B build -DPASSFILTEX_BUILD_TESTS=ON
cmake --build build
./build/password_policy_test
```

---

## 部署到 AD 域控

1. 将 `PassFiltEx.dll` 复制到 `C:\Windows\System32`。
2. 准备词典文件（可选）：`C:\Windows\System32\PassFiltExDict.txt`（一行一个词，支持 `#` 注释）。
3. 配置密码过滤器：
   - 注册表路径：`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
   - 多字符串：`Notification Packages`
   - 添加：`PassFiltEx`（不带 `.dll`）
4. 配置策略开关（可选）：`HKLM\SYSTEM\CurrentControlSet\Services\PassFiltEx\Parameters`
5. 重启域控使策略生效。

## 注意事项

- Password Filter DLL 运行在 LSASS 进程中，请严格评估稳定性与性能。
- 建议在隔离域控充分回归后再发布生产。
