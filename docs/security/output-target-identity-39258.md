# 输出路径身份绑定与符号链接失败关闭记录

- 任务编号：GSB UID 39258
- 目标版本：`str4d/rage@b5b68c4f4f7ea5c368bc060f6fe0237549c3a13f`
- 工作区基线：`b6ff8e3c203d1c989e8871fa3e02aa333439b56d`
- 复核日期：2026-11-25（Asia/Shanghai）
- 安全组件：`age::cli_common::file_io::OutputWriter` / `LazyFile`
- 影响调用方：`rage`、`rage-keygen` 以及启用 `cli-common` 的公开 Rust API

## 1. 安全边界与失效方式

`OutputWriter` 是公开输出 consumer。它为了保持既有行为而延迟打开文件：
`OutputWriter::new` 只做路径和覆盖检查，第一次 `write`/`flush` 时才由
`LazyFile` 打开路径。

原实现在 `allow_overwrite = true` 时直接使用
`create(true).truncate(true)` 按当前路径打开文件。若攻击者在检查后、打开前，
或在首次创建后、后续写入前，将输出路径替换为符号链接，后续打开或路径检查可能
指向另一对象，导致私钥或明文/解密输出写到攻击者选择的位置。

仅依赖 `Path::exists()` 或一次 `stat()` 不能闭合该边界，因为“检查路径”和
“打开路径”之间仍有 TOCTOU 窗口；直接使用 `O_TRUNC` 还可能在身份核对前破坏
链接目标。

## 2. 修复后的信任链

修复集中在 `age/src/cli_common/file_io.rs`：

1. **不跟随末级符号链接做构造时检查。**
   `check_output_path` 使用 `symlink_metadata(2)`/`lstat` 语义，将目标状态记为
   `Absent`、`Symlink` 或带身份的普通对象。

2. **绑定稳定对象身份。**
   Unix 上记录 `(st_dev, st_ino)` 作为 `FileIdentity`。文件成功打开后立即用
   `fstat(fd)` 取得同一身份；身份不一致便关闭描述符并返回
   `PermissionDenied`，不会写入明文。

3. **新文件由原子创建声明。**
   构造时路径不存在，或 `allow_overwrite = false` 时，统一使用
   `OpenOptions::create_new(true)`（对应 `O_CREAT | O_EXCL`）。如果路径在检查后
   被文件或符号链接占据，打开原子失败。

4. **显式 force 只覆盖已检查的普通身份。**
   对构造时已存在且非符号链接的目标，先以**不创建、不截断**方式打开，核对
   `fstat` 身份与构造时身份一致后，才对普通文件执行 `set_len(0)`。若路径被换成
   其他普通文件、符号链接或悬空符号链接，均不会截断、创建或写入外部目标。

5. **写入始终使用已绑定的文件描述符。**
   打开成功后，`Write` 调用使用同一个 owned `File`/fd。此后即使路径被替换，
   数据也不会沿新路径重定向。

6. **每次后续写入前重新核对可见路径。**
   `BoundFile::verify_path` 比较当前路径解析身份与 fd 身份。若攻击者在首次写入
   后替换路径，下一次写入/刷新前会失败关闭；实际 `write` 仍只送往已绑定 fd。
   即使确定性检查与 `write` 之间再次发生竞态，也不存在通过路径重定向写入的路径。

7. **stdout 路径不变。**
   `None` 和 `Some("-")` 仍返回 `OutputWriter::Stdout`，TTY/二进制输出策略、
   缓冲和显式二进制 stdout 行为保持原样。

新增错误文案（en-US/fr）明确给出
`err-refuse-symlink-output` 和
`err-output-target-identity-changed`，便于用户和复核者识别阻断事件。

## 3. 兼容性矩阵

| 场景 | 结果 |
| --- | --- |
| 普通不存在路径，`allow_overwrite = false` | 正常创建，保留请求的 `0600` 等模式 |
| 已存在普通文件，`allow_overwrite = false` | 仍返回 `AlreadyExists`，错误键为 `err-deny-overwrite-file` |
| 已存在普通文件，显式 `allow_overwrite = true`/force 语义 | 身份匹配后正常截断覆盖 |
| `OutputWriter::new(Some("-"), ...)` / `None` | 仍为 stdout，行为不变 |
| 构造后插入指向已存在文件的符号链接 | `create_new` 或身份核对失败，外部文件内容不变 |
| 构造前已存在符号链接 | consumer 首次写入/刷新返回 `PermissionDenied`，不跟随写入 |
| force 检查后把普通文件换成其他普通对象/符号链接 | `fstat` 身份不匹配，截断和写入前失败 |
| 换成悬空符号链接 | 不以 `O_CREAT` 创建链接目标；返回错误且外部目标不被创建 |
| 首次成功写入后替换路径 | 下一次写入前身份复核失败；外部目标不获得后续数据 |

安全策略有意不把“显式 force”解释为“允许穿过符号链接写任意对象”。force 只授权
覆盖调用方在构造时已检查到的同一普通目标身份。

## 4. 可执行回归证据

新增公开 API 集成测试
`age/tests/output_identity_security_39258.rs`，包含 9 个安全/兼容性回归测试；
`file_io.rs` 中两个既有单元测试保持通过。

集成测试：

- `ordinary_new_file_is_created_with_requested_mode`
- `explicit_force_overwrites_checked_regular_file`
- `explicit_stdout_remains_available`
- `force_creation_blocks_symlink_inserted_after_construction`
- `force_write_rejects_preexisting_symlink`
- `forbid_overwrite_dangling_symlink_fails_closed`
- `force_open_rejects_regular_identity_swap_before_truncation`
- `swapped_dangling_symlink_does_not_create_external_target`
- `later_path_replacement_fails_before_next_write`

既有单元测试：

- `lazy_existing_file_allow_overwrite`
- `lazy_existing_file_forbid_overwrite`

目标测试结果（2026-11-25）：

```text
running 9 tests in tests/output_identity_security_39258.rs
...
test result: ok. 9 passed; 0 failed

running 2 tests in cli_common::file_io::tests
test result: ok. 2 passed; 0 failed
```

同时验证：

```text
cargo check -p age --features cli-common --lib
# Finished `dev` profile

cargo build -p rage --bin rage-keygen
# Finished `dev` profile
```

本机离线 Cargo 缓存缺少部分与 `file_io` 无关的 dev-dependency crate；执行测试时，
曾临时移除无关 dev-dependencies，并在运行 lib 单元测试时暂时停用 `x25519` 的
proptest 块。测试完成后，`age/Cargo.toml`、`Cargo.lock` 和 `x25519.rs` 均已还原；
最终代码差异只包含本安全修复、i18n 文案、独立集成测试与安全记录。

## 5. 端到端复核

使用调试构建的 `rage-keygen` 在临时目录验证：

```text
normal_rc=0 normal_exists=yes mode=600
attack_rc=1 outside_exists=no
Error: Failed to write to output: Failed to open file
'.../attack.key': refusing to write output through symbolic link '.../attack.key'.
```

这表明普通密钥文件仍以 `0600` 创建，而预植符号链接不会导致外部目标文件被创建或
写入。

另用调试构建执行 `rage-keygen` → `rage -r ... -o out.age` →
`rage -d -i key -o dec.txt out.age` 的完整管道，解密结果与输入一致，说明普通新文件
和多次写入前身份复核不会破坏正常加密/解密输出。

复核者可运行：

```bash
cargo test -p age --features cli-common --lib cli_common::file_io::tests
cargo test -p age --features cli-common --test output_identity_security_39258
cargo build -p rage --bin rage-keygen
```

随后可在临时目录中把 `-o` 路径替换为符号链接并运行 `rage-keygen`；命令应非零退出，
链接目标应保持不存在或内容不变。

## 6. 残余边界

- 该修复防御输出末级路径及父路径在检查/打开窗口中的替换；Unix 身份以
  `(st_dev, st_ino)` 为准。
- 对已经能控制输出文件对象本身的攻击者（例如同一 inode 的既有硬链接），身份绑定
  会承认其为同一对象；这不是符号链接路径替换问题。
- 非 Unix 平台保留末级符号链接拒绝和 `create_new` 原子创建，但当前稳定身份字段
  使用可移植占位实现；本次攻击与测试环境为 Linux/Unix。
- 本记录不改变调用方对输出目录权限的运维责任；共享可写目录仍应使用 `0700`/粘滞位
  等深度防御措施。
