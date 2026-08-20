# 国家电网 Home Assistant 集成

这是一个非官方 Home Assistant 自定义集成，与国家电网有限公司无隶属或授权
关系。它依赖未公开的 App 协议，服务端或 App 升级可能随时导致集成失效。

直接调用网上国网 Android App API，不启动网页、浏览器、Android、ADB 或 Frida。

集成在 Home Assistant 主机上生成稳定设备身份和腾讯 TuringFD V90 `deviceTokenTX`，通过 App
原生密码登录获得约 15 天有效的 Token，再查询绑定户号的历史每日用电量。
只有服务端要求新设备安全验证时才会发送短信。

## 已验证能力

- 纯 Python 创建长期稳定、不同安装不冲突的设备 profile；
- 纯 Python 等价实现 Turing ARM64 feature hash，不携带或执行 APK native 库；
- JCE/Tars m90、zlib、XXTEA、RSA-2048 mode-1 `v3:` Token；
- App SM2/SM3/SM4 请求及响应信封；
- `c2/f01` 密码登录；
- `c1/f01` 按需发送 `businessType=logindevice` 新设备验证短信；
- `c2/f01` 携带 `code/codeKey` 完成新设备密码登录；
- 登录响应中的 Token、用户和多户号解析；
- `c11/f01` 查询本月及历史月份每日用电量；
- Token 失效时自动使用已保存密码重新登录。

历史协议实测已确认短信验证和 Token 响应的基本形状：

```text
发送短信：srvrt.resultCode = 0000
短信登录：srvrt.resultCode = 0000
登录消息：验证码登录成功
Token：存在
tokenExpireTime：1296000（约 15 天）
```

真实凭据、验证码、`codeKey`、Token 和完整 `deviceTokenTX` 均未写入测试日志。

## 认证策略

首次配置只要求输入手机号和密码。登录 Token 过期后，集成会在后台自动使用
已保存的密码登录；只有服务端返回 `4006` 新设备验证时，Home Assistant 才提示
用户输入短信验证码。

需要注意，某些账号或风控状态下，密码登录会返回：

```text
RK008 网络连接超时
```

APK 代码证明 `RK008` 是类型 `777` 的复杂滑块风险码，不是可以用六位短信码
完成的 `4006` 新设备验证。本集成不绕过滑块；如果服务端强制滑块，密码登录将失败。

## 错误诊断

配置流会显示完整、不截断的上游错误来源、错误码和消息，例如：

```text
国家电网上游返回错误 [srvrt] RK008：网络连接超时(RK008),请重试!
```

已知错误码仍使用本地语义分类，但会同时保留服务端的原始 message。HA 日志只记录
错误来源、code、异常类型和 message，不记录密码、验证码、请求体、登录 Token 或
`deviceTokenTX`。

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

1. 输入网上国网手机号和密码。
2. 集成首次创建 256-bit 随机 seed 并存入 HA config entry。
3. seed 派生稳定的品牌、型号、Android ID、OAID、MAC 和 `AppGuid`。
4. Python 生成并按官方逻辑缓存 `deviceTokenTX` 四小时。
5. 调用 `c2/f01` 密码登录。
6. 如果服务端要求 `4006` 新设备验证，发送 `logindevice` 短信并显示验证码表单。
7. 保存用户名、密码、登录 Token 和必要户号字段。

短信验证码和 `codeKey` 只保存在配置流内存中，成功或流结束后即丢弃。用户名、密码、
登录 Token、profile seed 和最小化后的户号字段保存在 `.storage/core.config_entries`。
Home Assistant 的 config entry 不对密码做额外加密，请严格保护配置目录和备份。

## 查询和实体

默认每 12 小时更新，查询当前月及上一个自然月；选项中可设置 1–3 个月、6–24 小时周期。

每个户号创建：

- 最近一日电量；
- 本月总用电量；
- 本月谷/平/峰/尖电量；
- 最近一日电费（服务端返回 `thisAmt` 时）。

“最近一日电量”的 `daily_history` 属性包含合并后的每日记录。服务端缺失值保留为 `unknown`，
不会错误地填成零。
最近一日电量和电费是已完成的历史日聚合值，因此不设置 `state_class`；本月累计电量
传感器保持 `state_class=total`。

## Token 与重认证

登录 Token 约 15 天，没有独立 Refresh Token。集成行为：

1. Token 有效时直接查询；
2. 查询返回 `-200/-201` 或本地到期时，自动使用已保存的用户名和密码登录；
3. 密码登录成功时直接保存新 Token，不提醒用户；
4. 只有服务端要求 `4006` 新设备验证时，才由 HA 发起重认证并输入短信码。

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
  --with cryptography --with aiohttp --with homeassistant==2026.2.3 pytest -q

uv run --python 3.13 --with ruff ruff check custom_components/state_grid
```

## 参考

- [ARC-MX/sgcc_electricity_new](https://github.com/ARC-MX/sgcc_electricity_new)
- [Bpazy/sgcc_electricity](https://github.com/Bpazy/sgcc_electricity)
- 本地 `hass-iotbull` 的 config entry、协调器和实体结构

当前实现针对网上国网 Android 3.2.3；协议或 Turing SDK 升级后可能需要更新。
