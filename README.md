# 法律证据保管与流转后台

仅使用 Python 3.11+ 标准库实现的证据保管项目。支持真实 SHA-256 入册、封存/开箱/移交、分析衍生关系、案件成员权限、法律保留、保留期限、不可变保管事件链、**跨案件复用**、**归档封存清单核验**和 JSON 报告导出。

## 运行

```bash
python3 app.py --init --seed
python3 app.py
```

访问 <http://127.0.0.1:8105>，默认数据库 `custody.db`。测试：

```bash
python3 -m unittest -v
```

演示身份：`custodian1`、`custodian2`、`analyst1`、`auditor1`、`archive_mw`（归档中间件服务账号）、`outsider`。请求使用 `X-User-Id`。

## 数据模型要点

- `custody_items`：物证本体，跨案件唯一（按 SHA-256 去重），持有保管号（`EV-000001` 形式）、实物内容、当前保管人/位置和物理状态。
- `evidence`：案件入册记录。同一物证在多个案件各有一条，本案的状态、法律保留和释放相互独立。
- `custody_events`：按物证本体串联的哈希链，每条事件带 `case_id` 标明动作归属案件。
- `archive_batches` / `archive_entries`：归档中间件批次与清单条目，保存处理结论、处理原因和权威状态指纹。

## 跨案件复用与权限隔离

- 同一份内容（SHA-256 相同）在任意案件再次入册时，**复用原保管号、原保管位置和同一条事件链**，返回 `reused: true`；链上追加 `CROSS_REUSE` 事件记录复用案件，原始记录不动。
- 释放、法律保留按**本案件入册记录**独立管理：一个案件放行或设保，不影响其他案件；他案成员越权释放返回 403。
- 所有案件都放行后物证本体才标记物理出库，只要还有一个案件在封就保留原位。

## 归档核验

归档中间件按阶段（`stage`）送封存清单，每条至少含 `custody_number`，可附 `expected_sha256` / `expected_location`：

- **同一批次号并发/重复提交只保存第一条**（数据库 UNIQUE + 提交串行化），后续提交标记 `duplicate: true` 并只补全未处理记录。
- 处理进度**逐条独立提交**；中断或失败只影响当前条目，重放（`POST /api/archive/batches/{批次号}/replay`）补全还没处理的记录，已处理记录不重做。
- 每条记录保存处理时的**权威状态指纹**（清单声明 + 实物哈希/位置/链尖 + 本案入册状态）。查看批次或生成报告时发现指纹变化，旧结论立即**作废重算**：条目标 `previous_status` 与 `recompute_count`，批次累加 `recompute_count`。
- 重算结论：`verified` / `missing`（缺件）/ `damaged`（内容与入册摘要或清单声明不符的损坏件）/ `swapped_out`（本案已放行或位置与封存位置不符的换出记录），每条附中文处理原因。
- 核验全程只读和写入归档表，**物证保管内容与事件链永不被归档流程修改**。

## 主要接口

- `POST /api/cases`：创建案件，创建人自动成为保管员。
- `POST /api/cases/{id}/members`：授予 custodian、analyst 或 auditor 角色。
- `POST /api/cases/{id}/evidence`：以 Base64 入册证据；相同内容自动跨案件复用。
- `GET /api/evidence/{id}`：元数据、共享物证视图（含各案件入册记录）、完整事件链、完整性和衍生关系。
- `POST /api/evidence/{id}/open|transfer|derive|release|hold`：开箱/移交/衍生/释放/法律保留（权限按证据所属案件校验）。
- `POST /api/cases/{id}/archive/batches`：提交封存清单（字段 `batch_number`、`stage`、`entries[]`；可选 `initial_limit` 用于分阶段处理）。
- `GET /api/cases/{id}/archive/batches`：列出本案件批次状态与条目计数。
- `GET /api/archive/batches/{id}`：批次明细，含每条记录的状态、处理原因和重算标记；查看即触发指纹对账。
- `POST /api/archive/batches/{batch_number}/replay`：中断后重放补全。
- `GET /api/cases/{id}/report`：按案件列出父/子证据关系、跨案件复用情况、哈希与事件链校验，以及所有归档批次的最新重算结果。
- 所有 `DELETE` 请求返回 405；证据和保管记录不提供删除接口。

保管事件通过前一条事件哈希串联；报告会重新计算文件哈希和事件链。项目适合流程与完整性原型，不涵盖现实中的签名证书、WORM 存储、证据文件加密或司法辖区合规认证。
