# 国家电网 Home Assistant 集成

将“网上国网”账户中的历史用电量接入 Home Assistant。

完成一次配置后，集成会定时更新绑定户号的每日用电量、本月累计电量和峰谷平尖电量；登录
Token 失效时会自动使用已保存的密码重新登录。日常运行不需要浏览器、官方 App 或 Android
设备。

> [!IMPORTANT]
> 这是社区维护的非官方集成，与国家电网有限公司没有隶属或授权关系。它依赖网上国网 App 的
> 非公开接口，服务端升级后可能暂时失效。请勿用于计费、结算或其他需要法律效力的场景。

[![打开 Home Assistant 并添加集成](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=state_grid)

## 功能

- 使用网上国网手机号和密码登录；
- 服务端要求新设备验证时，按提示输入短信验证码；
- 支持一个账户下的多个用电户号；
- 查询最近 1–3 个自然月的每日用电量；
- 提供本月总电量和峰、谷、平、尖分时电量；
- 默认每 12 小时更新，可配置为 6–24 小时；
- 登录 Token 过期后自动重新登录。

目前不提供账户余额、年度电费和月度账单电费。南方电网账户不适用。

## 安装

### 使用 HACS

1. 打开 HACS，进入“集成”。
2. 右上角菜单选择“自定义存储库”。
3. 添加仓库 `https://github.com/stevenjoezhang/hass-state-grid`，类别选择“集成”。
4. 搜索并下载“国家电网”。
5. 重启 Home Assistant。

### 手动安装

1. 下载本仓库。
2. 将 `custom_components/state_grid` 复制到 Home Assistant 配置目录：

   ```text
   <HA config>/custom_components/state_grid/
   ```

3. 重启 Home Assistant。

## 添加账户

1. 进入“设置 → 设备与服务”。
2. 点击“添加集成”，搜索“国家电网”。
3. 输入网上国网登录手机号和密码。
4. 如果收到新设备安全验证短信，继续输入 6 位验证码。

配置成功后，每个绑定户号会显示为一个设备，并创建对应传感器。一个网上国网账户只需添加
一次；同一账户下的多个户号会自动识别。

## 传感器

每个户号当前创建以下实体：

| 实体名称 | 单位 | 说明 |
|---|---:|---|
| 最近一日电量 | kWh | 上游已发布的最新一条每日用电量，不一定是昨天 |
| 本月用电量 | kWh | 上游月累计值；缺失时由每日记录相加 |
| 本月谷电量 | kWh | 本月谷时段累计电量 |
| 本月平电量 | kWh | 本月平时段累计电量 |
| 本月峰电量 | kWh | 本月峰时段累计电量 |
| 本月尖电量 | kWh | 本月尖时段累计电量 |
| 最近一日电费 | CNY | 仅当每日接口返回费用字段时有值，多数账户可能显示 `unknown` |

“最近一日电量”实体包含以下附加属性：

- `latest_date`：当前状态对应的日期；
- `daily_history`：已查询月份的每日记录，包含电量和可用的峰谷平尖数据。

上游缺失的数据会保留为 `unknown`，不会自动填成 `0`。因此，某个分时传感器为 `unknown`
通常表示该户号或地区没有返回该项数据，不表示整个集成不可用。

## 查询设置

在“设置 → 设备与服务 → 国家电网 → 配置”中可以调整：

| 选项 | 范围 | 默认值 |
|---|---:|---:|
| 查询最近几个月 | 1–3 个月 | 2 个月 |
| 更新间隔 | 6–24 小时 | 12 小时 |

增加查询月份会产生更多上游请求。国家电网的每日数据通常不是实时数据，最新日期以实体的
`latest_date` 属性为准。

## 登录和短信验证

- 登录 Token 通常约 15 天有效；
- Token 失效后，集成会在后台使用已保存的密码重新登录；
- 只有服务端返回新设备验证要求时，才会发送短信验证码；
- 验证码和临时 `codeKey` 不会持久保存。

某些账号或网络环境可能收到 `RK008`。这表示服务端要求官方 App 才能完成的交互式安全验证，
不是普通短信验证码。本集成不会尝试绕过该验证；遇到时请稍后重试、检查网络，或先在官方
网上国网 App 中完成登录。

## 常见问题

### 搜索不到“国家电网”

确认目录是 `custom_components/state_grid`，而不是多套一层仓库目录，并在安装后完整重启
Home Assistant。使用 HACS 时也需要在下载后重启。

### “最近一日电费”显示 unknown

当前每日接口主要返回电量和峰谷平尖数据，很多地区不会返回日电费字段。因此该实体可能长期
为 `unknown`，这不影响每日用电量查询。它也不是电费余额、应交金额或月度账单金额。

### 峰、谷、平或尖电量显示 unknown

并非所有地区、计价方式或电表都会返回完整分时数据。只要“最近一日电量”或“本月用电量”
正常，就说明基础查询已经成功。

### 数据日期不是今天或昨天

每日数据由国家电网上游生成，可能延迟发布。请查看“最近一日电量”的 `latest_date` 属性；集成
只展示上游返回的最新日期，不会将旧数据伪装成当天数据。

### 配置时提示 4006

这是新设备安全验证。集成会发送短信并显示验证码输入框，按提示完成即可。

### 配置时提示 RK008

这是服务端交互式风控，不是密码错误或 6 位短信验证。可以稍后重试、切换网络，或先在官方 App
中完成安全验证。若持续出现，请在提交 Issue 时附上错误码和消息，但不要附密码、验证码、Token
或完整日志中的请求内容。

### 修改了网上国网密码

当自动登录发现原密码失效时，Home Assistant 会发起重新认证。按照通知进入集成页面，输入新
密码即可；不需要删除并重新添加集成。

## 隐私与安全

为支持自动重新登录，以下内容会保存在 Home Assistant 的
`.storage/core.config_entries`：

- 网上国网手机号和密码；
- 登录 Token；
- 本地生成的设备 profile seed；
- 查询所需的最小户号信息。

Home Assistant 的 config entry 不会额外加密密码。请保护 Home Assistant 配置目录、备份文件
和管理员账户，不要将 `.storage` 上传到公开位置。

本集成不会要求导出官方 App 数据，不携带官方 APK 或 native SO，也不需要 ADB、Frida、模拟器
或浏览器。项目本身不包含遥测或统计上报。

## 卸载

先在“设置 → 设备与服务”中删除国家电网配置项，再通过 HACS 删除集成或手动移除
`custom_components/state_grid`，最后重启 Home Assistant。

## 获取帮助

遇到问题请前往
[GitHub Issues](https://github.com/stevenjoezhang/hass-state-grid/issues)。提交问题时建议提供：

- Home Assistant 版本和集成版本；
- 错误码及完整错误消息；
- 哪些实体正常、哪些实体为 `unknown`；
- 问题发生的大致时间和所在省份。

请务必删除手机号、户号、地址、密码、验证码、Token、`deviceTokenTX` 和 profile seed。

## 开发

项目使用纯 Python 实现网上国网 App 请求协议和本地设备 profile。当前版本针对网上国网 Android
3.2.3；App 或服务端协议升级后可能需要同步更新。

运行测试和静态检查：

```bash
uv run --python 3.13 --with pytest --with gmssl==3.2.2 \
  --with cryptography --with aiohttp --with homeassistant==2026.2.3 pytest -q

uv run --with ruff ruff check custom_components/state_grid tests
```

本项目参考了 [ARC-MX/sgcc_electricity_new](https://github.com/ARC-MX/sgcc_electricity_new)
和 [Bpazy/sgcc_electricity](https://github.com/Bpazy/sgcc_electricity) 的用户体验与实体设计。

## 许可证

[MIT License](LICENSE)
