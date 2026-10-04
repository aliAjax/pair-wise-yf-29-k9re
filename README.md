# 法律证据保管与流转后台

仅使用 Python 3.11+ 标准库实现的证据保管项目。支持真实 SHA-256 入册、封存/开箱/移交、分析衍生关系、案件成员权限、法律保留、保留期限、不可变保管事件链、跨案件复用、归档封存清单核验（缺件/损坏件/换出）和 JSON 报告导出。

## 运行

```bash
python3 app.py --init --seed
python3 app.py
```

访问 <http://127.0.0.1:8105>，默认数据库 `custody.db`。测试：

```bash
python3 -m unittest -v
```

演示身份：`custodian1`、`custodian2`、`analyst1`、`auditor1`、`outsider`。请求使用 `X-User-Id`。

## 跨案件复用

证据按内容 SHA-256 去重共享。同一份内容被别的案件再次入册时，复用原保管号、位置和事件链（`ingest_evidence` 返回 `reused: true`）。各案件独立管理自己的入册记录：状态、法律保留、保留期限和释放权限按案件隔离，一个案件放行不影响另一案件。释放/开箱/移交等操作通过 `case_id`（请求体或查询参数）定位案件；未指定时按用户在各案件的成员身份解析，越权操作其他案件会被拒绝（403），身份不唯一时要求显式指定 `case_id`（409）。

## 归档封存清单核验

- `POST /api/cases/{id}/archive`：归档中间件按阶段送存封存清单。同一清单编号并发提交只保存第一条（清单头幂等），每次提交产生一个新批次。
- `GET /api/cases/{id}/archive`：列出案件的封存清单及重算摘要。
- `GET /api/archive/{id}`：查看清单的批次状态、每条条目的核验结果与处理原因。
- `POST /api/archive/{id}/replay`：中断失败后重放，补全还没处理的记录（pending 条目）。

核验结果分为：`verified`（核验通过）、`missing`（缺件）、`damaged`（损坏件）、`swapped_out`（换出记录）。清单或案件里的权威状态一变（证据释放、移交、保留变化等），旧结果作废并重算；核验只读取保管记录，原记录保持不动。

## 主要接口

- `POST /api/cases`：创建案件，创建人自动成为保管员。
- `POST /api/cases/{id}/members`：授予 custodian、analyst 或 auditor 角色。
- `POST /api/cases/{id}/evidence`：以 Base64 入册证据，服务端计算 SHA-256 和大小；同内容跨案件复用。
- `GET /api/evidence/{id}`：查看元数据、完整保管事件链、完整性结果和衍生关系；支持 `?case_id=` 与 `?content`。
- `POST /api/evidence/{id}/open`：保管员开箱。
- `POST /api/evidence/{id}/transfer`：移交保管人并记录位置。
- `POST /api/evidence/{id}/derive`：分析员从已开箱证据创建衍生证据。
- `POST /api/evidence/{id}/hold`：审计员或案件创建人设置/解除法律保留。
- `POST /api/evidence/{id}/release`：存在法律保留时拒绝释放；可带 `case_id`。
- `GET /api/cases/{id}/report`：按案件列出父证据、子证据、重算结果与审计日志。
- 归档接口：`POST/GET /api/cases/{id}/archive`、`GET /api/archive/{id}`、`POST /api/archive/{id}/replay`。
- 所有 `DELETE` 请求返回 405；证据和保管记录不提供删除接口。

保管事件通过前一条事件哈希串联；报告会重新计算文件哈希和事件链。项目适合流程与完整性原型，不涵盖现实中的签名证书、WORM 存储、证据文件加密或司法辖区合规认证。
