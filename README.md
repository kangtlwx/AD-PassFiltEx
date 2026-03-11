# PassFiltEx (自定义 AD 密码过滤 DLL)

本项目实现了一个可部署到 Active Directory 域控上的密码过滤 DLL（`PassFiltEx.dll`），并参考微软官方 Password Filter 说明实现接口与校验流程。

## 已实现策略

1. 必须同时包含 4 类字符：`a-z`、`A-Z`、`0-9`、符号。
2. 不允许出现 3 个连续字符（`0-9`、`a-z`，忽略大小写）。
   - 数字按环形连续判断，`890` 也会被拦截。
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
   - 扩展词：`%SystemRoot%\System32\PassFiltExDict.txt`（每行一个词，支持 `#` 注释）
7. 参考微软建议，不允许密码包含账号名或全名中的 token（长度 >= 3）。

## 构建

### Windows (生成 DLL)

```bash
cmake -S . -B build -DPASSFILTEX_BUILD_TESTS=ON
cmake --build build --config Release
```

在 Windows 上会生成：`PassFiltEx.dll`

### Linux/CI (仅验证策略核心)

Linux 下不会构建 Windows DLL，但可以编译并运行策略单元测试：

```bash
cmake -S . -B build -DPASSFILTEX_BUILD_TESTS=ON
cmake --build build
./build/password_policy_test
```

## 部署到 AD 域控

1. 将 `PassFiltEx.dll` 复制到 `C:\Windows\System32`。
2. （可选）创建 `C:\Windows\System32\PassFiltExDict.txt`，加入公司专有词（公司名、品牌名、产品名、内部缩写）。
3. 修改注册表：
   - 路径：`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
   - 多字符串值：`Notification Packages`
   - 添加：`PassFiltEx`（不带 `.dll`）
4. 重启域控使策略生效。

## 注意事项

- Password Filter DLL 运行在 LSASS 进程中，请严格评估稳定性与性能。
- 建议在隔离域控充分回归后再发布生产。
