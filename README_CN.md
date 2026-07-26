# whois-golang

[English](README.md) | 中文

[![Go Reference](https://pkg.go.dev/badge/github.com/deershark/whois-golang.svg)](https://pkg.go.dev/github.com/deershark/whois-golang)
[![CI](https://github.com/deershark/whois-golang/actions/workflows/ci.yml/badge.svg)](https://github.com/deershark/whois-golang/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/deershark/whois-golang)](https://goreportcard.com/report/github.com/deershark/whois-golang)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

零依赖的 Go 域名注册信息查询库。

**RDAP 优先，WHOIS 兜底。** 查询首先通过 [rdap.org](https://rdap.org) 引导服务（基于 [IANA RDAP bootstrap 注册表](https://data.iana.org/rdap/dns.json)，与 [deployment.rdap.org](https://deployment.rdap.org/) 同源）发起；若该后缀未接入 RDAP，自动回退到 43 端口的原始 WHOIS 协议，并用能理解各注册局迥异格式的解析器处理结果。

```
google.com   → RDAP  (rdap.verisign.com)
google.de    → WHOIS (whois.denic.de)        .de 未接入 RDAP
google.shop  → RDAP  (rdap.gmoregistry.net)  .shop 已于 2026 年关闭 43 端口
```

## 特性

- **RDAP 优先策略** —— 正确区分"该后缀没有 RDAP"（回退 whois）与"域名未注册"（报告可注册）两种情况。
- **经实战验证的 WHOIS 解析器** —— 通用 key/value 提取 + 分 TLD 规则，基于 **28 份真实注册局响应** 编写测试：`com org de jp uk ru cn fr br it eu kr hk tw tr au nl us ca xyz in io me vc` 等。
  - JPRS 括号格式（`[Created on]`、`p. [Name Server]`、从 `[State] Connected (…)` 提取到期时间）
  - Nominet 块格式（值在下一行、NS 行携带 IPv6 地址）
  - EURid / nic.it 无冒号分段、TRABIS `** Key` 装饰、KISA 韩英双语布局、TWNIC 无冒号日期、CNNIC、TCI（.ru）、registro.br 紧凑日期等
- **可用性判断** —— 按注册局识别未注册模式（`Status: free`、`No match`、`AVAILABLE`、`No entries found` 等）；被限流/空响应一律报错，绝不误报为"未注册"。
- **内嵌服务器映射表** —— 约 580 条 TLD → WHOIS 服务器映射，与 `whois.iana.org` 交叉核实；未收录的 TLD 运行时通过 IANA referral 动态发现并缓存。
- **thin registry referral 跟随**（可选）—— Verisign 式 thin 响应可进一步查询注册商自己的 WHOIS 获取完整数据。
- **IDN 支持** —— 内置 RFC 3492 punycode 编码（`münchen.de` → `xn--mnchen-3ya.de`），无任何外部依赖。

## 安装

```sh
go get github.com/deershark/whois-golang
```

## 使用

```go
package main

import (
	"fmt"

	whois "github.com/deershark/whois-golang"
)

func main() {
	c := whois.New()
	rec, err := c.Query("google.de")
	if err != nil {
		panic(err)
	}
	fmt.Println(rec.Source, rec.Server) // whois whois.denic.de
	fmt.Println(rec.Registered)         // true
	fmt.Println(rec.Parsed.Statuses)    // [connect]
	fmt.Println(rec.Parsed.NameServers) // [ns1.google.com ...]
	fmt.Println(rec.Parsed.Expiry)      // *time.Time（注册局不公开则为 nil）
}
```

### 可选项

```go
c := whois.New(
	whois.WithTimeout(15*time.Second),        // 单次请求网络超时
	whois.WithPreferRDAP(true),               // 优先 RDAP（默认开）
	whois.WithWhoisFallback(true),            // 自动回退 43 端口（默认开）
	whois.WithReferralFollowing(true),        // 跟随 "Registrar WHOIS Server" 获取 thick 数据
	whois.WithRDAPBaseURL("https://rdap.verisign.com/com/v1"), // 自定义 RDAP 端点
	whois.WithWhoisServer("test", "127.0.0.1:1043"),           // 按 TLD 固定服务器
	whois.WithHTTPClient(customHTTP),         // 自定义 *http.Client
)
```

### 返回结构

```go
type Record struct {
	Domain      string      // 规范化后的 A-label 域名
	Source      Source      // "rdap" 或 "whois"
	Server      string      // 实际应答的权威服务器
	Registered  bool        // 注册局报告未注册时为 false
	Raw         string      // 原始响应（RDAP 为 JSON，WHOIS 为文本）
	RegistryRaw string      // 跟随 referral 时保留的 thin registry 原始响应
	Parsed      *ParsedInfo // 归一化字段：日期、注册商、状态、NS、联系人等
}
```

### 辅助函数

```go
info, registered := whois.Parse("uk", rawResponse) // 离线解析 WHOIS 文本
ok := whois.IsAvailable("de", rawResponse)         // 判断是否未注册
alabel, _ := whois.ToASCII("新华网.cn")              // xn--xkrr14bows.cn
```

## 测试

```sh
go test ./...                 # 单元测试（离线：假服务器 + 真实样本）
WHOIS_LIVE=1 go test ./...    # 追加真实注册局联调（注意各局限流）
```

`testdata/` 下的样本均为 2026 年 7 月从各官方服务器真实抓取的响应，如实记录了各注册局的格式（包括 DENIC 两行式极简应答、EURid 无日期输出等边界情况）。

## 覆盖情况说明

- IANA RDAP bootstrap 中的约 1200 个 TLD 全部通过 RDAP 路径覆盖。
- 内嵌 WHOIS 映射表覆盖约 580 个 TLD，已与 IANA 交叉核实；已关闭 43 端口的注册局（`.info`、`.mobi`、`.pro`、Google 系、GMO 系如 `.shop`/`.tokyo` 等）有意未收录——它们由 RDAP 提供服务。
- 部分注册局（`.ch`、`.li`、`.at` 等）按客户端 IP 限制 43 端口访问，库会如实报错而不是猜测结果。

## 开源协议

[MIT](LICENSE)
