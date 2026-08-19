# 国家电网 Home Assistant 集成

这是一个非官方 Home Assistant 自定义集成，与国家电网有限公司无隶属或授权
关系。它依赖未公开的 App 协议，服务端或 App 升级可能随时导致集成失效。

直接调用网上国网 Android App API，不启动网页、浏览器、Android、ADB 或 Frida。

集成在 Home Assistant 主机上生成稳定设备身份和腾讯 TuringFD V90 `deviceTokenTX`，通过 App
原生短信登录获得约 15 天有效的 Token，再查询绑定户号的历史每日用电量。

## 已验证能力

- 纯 Python 创建长期稳定、不同安装不冲突的设备 profile；
- 纯 Python 等价实现 Turing ARM64 feature hash，不携带或执行 APK native 库；
- JCE/Tars m90、zlib、XXTEA、RSA-2048 mode-1 `v3:` Token；
- App SM2/SM3/SM4 请求及响应信封；
- `c1/f01` 发送 `businessType=login` 短信；
- `c2/f02` 短信登录；
- 登录响应中的 Token、用户和多户号解析；
- `c11/f01` 查询本月及历史月份每日用电量；
- Token 失效时由 HA 发起短信重认证。

生产接口实测结果：

```text
发送短信：srvrt.resultCode = 0000
短信登录：srvrt.resultCode = 0000
登录消息：验证码登录成功
Token：存在
tokenExpireTime：1296000（约 15 天）
```

真实凭据、验证码、`codeKey`、Token 和完整 `deviceTokenTX` 均未写入测试日志。

## 为什么使用短信登录

同一个纯 Python 设备的密码登录会返回：

```text
RK008 网络连接超时
```

APK 代码证明 `RK008` 是类型 `777` 的复杂滑块风险码。新设备短信验证成功后，密码登录仍会
触发该滑块；而 App 原生短信登录 `c2/f02` 已实测成功。因此集成以短信登录为可靠入口，不依赖
浏览器验证码，也不保存账户密码。

## 安装

将目录复制到 Home Assistant：

```text
<HA config>/custom_components/state_grid/
```

重启 HA，在“设置 → 设备与服务 → 添加集成”中搜索“国家电网”。也可以将本仓库作为 HACS
自定义仓库安装。

运行依赖由 `manifest.json` 自动安装：

- `gmssl==3.2.2`
- `cryptography`

## 配置流程

1. 输入网上国网手机号。
2. 可选填写六位省、市、区县代码；留空也可发送登录短信。
3. 集成首次创建 256-bit 随机 seed 并存入 HA config entry。
4. seed 派生稳定的品牌、型号、Android ID、OAID、MAC 和 `AppGuid`。
5. Python 生成并按官方逻辑缓存 `deviceTokenTX` 四小时。
6. 服务端发送 6 位登录验证码。
7. 输入验证码后调用 `c2/f02`，保存登录 Token 和必要户号字段。

短信验证码和 `codeKey` 只保存在配置流内存中，成功或流结束后即丢弃。登录 Token、profile seed
和最小化后的户号字段按 HA 标准保存在 `.storage/core.config_entries`，请保护配置目录和备份。

## 查询和实体

默认每 12 小时更新，查询当前月及上一个自然月；选项中可设置 1–3 个月、6–24 小时周期。

每个户号创建：

- 最近一日电量；
- 本月总用电量；
- 本月谷/平/峰/尖电量；
- 最近一日电费（服务端返回 `thisAmt` 时）。

“最近一日电量”的 `daily_history` 属性包含合并后的每日记录。服务端缺失值保留为 `unknown`，
不会错误地填成零。

## Token 与重认证

登录 Token 约 15 天，没有独立 Refresh Token。集成行为：

1. Token 有效时直接查询；
2. 查询返回 `-200/-201` 或本地到期时触发 HA 重认证；
3. 用户点击发送短信并输入验证码；
4. 沿用原 profile seed 和设备身份获取新 Token。

整个生命周期不需要官方 App 或 Frida。

## 关键逆向修正

原始 smali 证明 mode 0/1 都压缩：

```text
zlib(0x02 || native_m90_blob)
```

RSA DER modulus 是 `00 || 256-byte modulus`。跳过符号前导 `00` 后，mode-1 RSA ciphertext 才是
协议规定的 256 字节。此前的 2040-bit 错误解析会令服务端无法解出 XXTEA key。

## 开发验证

```bash
uv run --python 3.13 --with pytest --with gmssl==3.2.2 \
  --with cryptography --with aiohttp pytest -q

uv run --python 3.13 --with ruff ruff check custom_components/state_grid
```

## 参考

- [ARC-MX/sgcc_electricity_new](https://github.com/ARC-MX/sgcc_electricity_new)
- [Bpazy/sgcc_electricity](https://github.com/Bpazy/sgcc_electricity)
- 本地 `hass-iotbull` 的 config entry、协调器和实体结构

当前实现针对网上国网 Android 3.2.3；协议或 Turing SDK 升级后可能需要更新。
