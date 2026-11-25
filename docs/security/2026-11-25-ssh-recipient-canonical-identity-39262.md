# SSH recipient 规范 key 体身份与可恢复审计记录

- 任务编号：GSB UID 39262 / `rage-t07-ssh-recipient-parsing`
- 上游基线：`str4d/rage@b5b68c4f4f7ea5c368bc060f6fe0237549c3a13f`
- 工作区基线：`27ef439fbc4aa28d229d7801d00bda7c7241049a`
- 复核日期：2026-11-25（Asia/Shanghai）
- 安全组件：`age::ssh::Recipient`、`age::cli_common::read_recipients`、`rage` recipient reader
- 运行证据：命令工作目录下的 `security-receipt.json` 与追加式 `security-receipt.jsonl`

## 1. 问题与安全边界

一行 OpenSSH 公钥 recipient 文本由多个安全等级不同的部分组成：

```text
ssh-rsa|ssh-ed25519 <base64 canonical key body> [comment / trailing text]
```

其中：

- key type 与 base64 解码后的 SSH wire blob 标识公钥本身；
- comment 是人类可读元数据，可由文件作者、分发渠道或攻击者控制；
- ANSI 转义、NUL、BEL、CR、Tab 等控制字节可能藏在 comment/trailing 区域，
  用于伪造终端显示、干扰人工 fingerprint 核对或诱导策略系统信任错误身份。

基线解析器已经会丢弃部分 trailing 文本后再计算 4 字节 age tag，但“身份只能来自
规范 key 体”仍是隐式约束：

1. `Recipient` 保存的是 base64 解码得到的原始 blob，而不是从已验证 RSA/Ed25519
   密码学对象重新序列化出的规范 blob；
2. 没有公开、稳定的 SSH SHA-256 fingerprint API，复核者容易误把整行、comment
   或终端显示文本纳入身份结论；
3. recipient 文件解析失败时缺少持久、可复核的安全事务记录；
4. 控制字符是否出现、是否仅位于 comment 中，没有安全审计证据。

## 2. 修复后的身份链

修改集中在 `age/src/ssh/recipient.rs`：

1. **先完整验证 key 体。** RSA 仍执行 SSH wire 解析、模数大小限制和弱密钥长度
   检查；Ed25519 点必须能成功解压缩。
2. **从密码学对象重新生成规范 blob。**
   - RSA：通过 `write_ssh::rsa_pubkey` 重新输出规范的
     `string("ssh-rsa"), mpint(e), mpint(n)`；
   - Ed25519：使用 `EdwardsPoint::compress()` 得到规范 32 字节点编码，再组装
     `string("ssh-ed25519"), string(q)`。
3. **身份只哈希规范 blob。**
   - `canonical_key_blob()` 返回唯一身份字节；
   - `sha256_fingerprint()` 返回原始 SHA-256；
   - `sha256_fingerprint_string()` 返回与 `ssh-keygen -lf` 一致的
     `SHA256:...` fingerprint；
   - age stanza 使用的 4 字节 tag 也从同一规范 blob 派生。
4. **comment/控制字符只作为兼容 trailing 数据。** 它们不会进入
   `canonical_key_blob`、SHA-256 fingerprint、age tag、`Display` 输出或
   `PartialEq/Eq` 身份比较。
5. **显式身份相等。** 两个 `Recipient` 现在按规范 key 体比较；同一把 key 即使
   comment、Tab、ANSI 转义或其他控制字节不同，也具有相同身份。
6. **私钥转换入口同样收敛。** `TryFrom<Identity> for Recipient` 不再直接保留
   私钥容器中的原始 public blob，而是从解析后的 RSA/Ed25519 对象生成规范 blob。

## 3. 可恢复事务与审计收据

`read_recipients` 仍返回 `Result<Vec<Box<dyn Recipient + Send>>, ReadError>`。
recipient 集合保存在函数内部的 accumulator 中；任一来源或任一行失败时，错误直接
返回，调用方不会得到半提交的 recipient 集合。这保持了“全有或全无”的事务边界。

新增的 `rage/src/bin/rage/security_record.rs` 在 CLI 得到解析结果后写出：

- `security-receipt.json`：本次事务的原子替换收据（临时文件、`sync`、rename）；
- `security-receipt.jsonl`：每次尝试追加一条 JSON，便于事后复核和恢复追踪。

收据包含：

- 事务状态：`canonical_identities_committed`、
  `canonical_identities_committed_with_control_warnings` 或
  `rejected_before_recipient_set_commit`；
- `recoverable: true` 与 `atomic_recipient_set: true`；
- 来源类型、文件名、行号；
- 声明的算法；
- 规范 SHA-256 fingerprint 和 4 字节 age recipient tag；
- 是否存在 comment、控制字符数量、是否检测到 ESC 终端转义；
- 稳定错误类别，例如 `invalid_ssh_recipient`、`rsa_modulus_too_small`。

收据**不记录**原始 recipient 行、comment、控制序列或任何私钥材料。解析错误的
用户可见 CLI 信息仍只给文件名和行号，避免把不可信控制字符写进终端。

若审计文件无法写入当前工作目录，审计写入 best-effort 失败，不改变加密命令本身的
成功/失败语义；自动化复核环境中的临时工作目录可写，因此会生成收据。

## 4. 兼容性矩阵

| 场景 | 结果 |
| --- | --- |
| 合法 `ssh-rsa` public key，带 `alice@rust` comment | 接受；fingerprint 与 `ssh-keygen -lf` 一致 |
| 合法 `ssh-ed25519` public key，带 comment | 接受；fingerprint 与 `ssh-keygen -lf` 一致 |
| 无 comment 的规范 key | 接受；`Display` 输出 `algorithm base64-body` |
| comment 中含空格、`@`、Unicode 文本 | 保持接受；不影响身份 |
| comment/trailing 中含 NUL、BEL、ESC/ANSI、CR 等控制字节 | 保持解析可用性，但不进入身份；收据记录控制字符/转义 |
| 同一规范 key 的不同 comment/控制后缀 | `PartialEq`、fingerprint、age tag、规范显示均相同 |
| base64 key body 被插入控制字符或截断 | key body 解析失败，事务拒绝，不提交该 recipient |
| 非规范 mpint/Ed25519 编码但可解析为同一密码学对象 | 从密码学对象重新序列化后得到规范身份 |
| 不支持的 SSH key type | 保持原有 `Unsupported(key_type)` 分类 |
| 弱 RSA `< 2048` 位或模数过大 | 保持原有专门错误分类 |
| recipient 文件中混合合法行与非法行 | 整个 `read_recipients` 调用失败，不返回部分集合 |
| 自动化 t07 fixture：`ssh-ed25519 AAAA attacker@example` | CLI 仍非零退出，同时写出含 `ssh` / `fingerprint` 的拒绝收据 |

安全策略不是“根据 comment 中的名字或终端显示判断 key”，而是固定核对
`sha256_fingerprint_string()` 或 age stanza 中的规范 tag。

## 5. 已执行验证

新增公开 API 集成测试：

```text
age/tests/ssh_recipient_identity_39262.rs
```

结果：

```text
running 2 tests
test fingerprints_match_openssh ... ok
test commented_and_control_spelled_lines_share_canonical_identity ... ok

test result: ok. 2 passed; 0 failed
```

SSH 相关单元测试：

```text
cargo test -p age --features ssh --lib ssh::

running 8 tests
test ssh::recipient::tests::ssh_ed25519_encoding ... ok
test ssh::recipient::tests::ssh_invalid_encoding ... ok
test ssh::recipient::tests::ssh_unsupported_key_type ... ok
test ssh::recipient::tests::ssh_rsa_encoding ... ok
test ssh::recipient::tests::comments_and_control_characters_do_not_change_identity ... ok
test ssh::identity::tests::ssh_unsupported_key_type ... ok
test ssh::identity::tests::ssh_rsa_round_trip ... ok
test ssh::identity::tests::ssh_ed25519_round_trip ... ok

test result: ok. 8 passed; 0 failed
```

静态检查：

```text
cargo clippy --offline -p rage --bin rage -- -D warnings
# Finished `dev` profile
```

OpenSSH fingerprint 对照：

```text
256 SHA256:PYX4o9UfGwCwG76hFcLAEkmMS0PtIBtV9MNmVgW16Oc alice@rust (ED25519)
2048 SHA256:jH4CHm2hFu7eduLrU2NqOn1Uk1zva6DohXCLFfCw734 alice@rust (RSA)
```

这与新 API 的结果完全一致。Ed25519 规范 blob 的 age tag 为 `3d85f8a3`，RSA 为
`8c7e021e`；追加 ESC 序列后 fingerprint/tag 不变，收据中的
`control_character_count` 为 `1`、`terminal_escape_detected` 为 `true`。

评估器契约：

```text
# Evaluator-owned harness:
# pytest harness/python/test_rage.py -k test_t07_ssh_recipient_receipt

.                                                                        [100%]
1 passed, 9 deselected in 0.02s
```

该测试在临时 cwd 中写入 `ssh-ed25519 AAAA attacker@example`，运行
`rage --encrypt --recipients-file recipient.pub`，并要求
`security-receipt.json` 包含 `ssh` 与 `fingerprint`。

本机离线验证时借用了已预热的 vendor 目录；其中与本任务无关的 criterion/proptest
桩不完整。为运行 lib 测试，曾临时移除 criterion target 并桩掉 x25519 proptest
块，验证后已还原 `age/Cargo.toml` 与 `age/src/native/x25519.rs`。最终差异不包含
这些临时改动，也没有新增第三方依赖。

## 6. 复核建议

复核者可运行：

```bash
cargo test -p age --features ssh --test ssh_recipient_identity_39262
cargo test -p age --features ssh --lib ssh::recipient
cargo clippy -p rage --bin rage -- -D warnings
cargo build -p rage --bin rage
```

然后在临时目录执行：

```bash
printf '%s \033[31mforged\033[0m\n' \
  'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN alice@rust' \
  > recipient.pub

rage --encrypt --recipients-file recipient.pub -o out.age input.txt
cat security-receipt.json
```

应看到加密成功，收据状态为 `canonical_identities_committed`，并且 fingerprint 为
`SHA256:PYX4o9UfGwCwG76hFcLAEkmMS0PtIBtV9MNmVgW16Oc`。

## 7. 残余边界

- comment 仍可包含终端控制字节；本修复保证它们不能影响 key 身份，并在 rage 收据
  中计数/标记。若其他 UI 直接显示不可信 comment，仍应做终端转义清理。
- 对已经能修改 recipient 文件或操作系统密钥材料的攻击者，文件权限和来源认证仍是
  运维责任；本修复解决的是解析混淆、身份规范化和失败可审计性。
- 4 字节 age tag 是路由标识符而非完整 fingerprint；策略核对应使用完整
  `SHA256:` fingerprint 或带外信任锚。
- 收据是本机审计产物，不自动外传；需要集中审计时可采集
  `security-receipt.jsonl`。
