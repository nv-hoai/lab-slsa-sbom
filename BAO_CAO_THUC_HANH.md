# Báo cáo thực hành: An toàn chuỗi cung ứng phần mềm (SLSA, SBOM, Cosign)

- **Ngày thực hiện:** 09/11/2026
- **Repo:** <https://github.com/nv-hoai/lab-slsa-sbom> (public, nhánh `main`)
- **Tag release:** `v1.0.0`
- **Commit:** commit cuối trên `main` (tag `v1.0.0`)
- **Trạng thái:** đã hoàn thành mã nguồn, workflow và kiểm chứng cục bộ; GitHub Actions chưa chạy được vì tài khoản GitHub đang bị khóa do vấn đề thanh toán (billing), xem mục 5.

## 1. Cấu trúc dự án

```text
lab-slsa-sbom/
├── .github/workflows/
│   ├── sbom.yml              # Bài 1: SPDX + CycloneDX + Grype
│   ├── cosign-sign.yml       # Bài 2: keyless signing + verify
│   └── slsa-provenance.yml   # Bài 3: SLSA L3 provenance
├── evidence/
│   ├── sbom.spdx.json        # SBOM sinh cục bộ bằng Syft
│   ├── sbom.cyclonedx.json
│   ├── grype-before-fix.txt  # Kết quả quét trước khi nâng cấp
│   ├── grype-after-fix.txt   # Kết quả quét sau khi nâng cấp
│   ├── grype-before-fix.sarif
│   └── grype-after-fix.sarif
├── app.py                    # Flask app: / và /health
├── main.py                   # Hàm dùng chung + CLI
├── requirements.txt          # Flask 3.1.3, requests 2.34.2
├── opencode.json             # MCP google-workspace copy từ ../soa
├── LICENSE
└── README.md
```

## 2. Bài 1 — SBOM SPDX + CycloneDX và quét Grype

### 2.1. Những gì đã triển khai

Workflow `.github/workflows/sbom.yml` chạy khi push/PR vào `main` và có
`workflow_dispatch`. Các bước chính:

1. Checkout mã nguồn, cài Python 3.12.
2. Cài dependency vào `.python-packages` để Syft nhìn thấy cả dependency
   chuyển tiếp (transitive), không chỉ các gói khai báo trực tiếp.
3. Sinh `sbom.spdx.json` bằng `anchore/sbom-action` (`format: spdx-json`).
4. Sinh `sbom.cyclonedx.json` bằng `anchore/sbom-action`
   (`format: cyclonedx-json`).
5. Quét chính tệp CycloneDX bằng `anchore/scan-action@v7` với
   `sbom: sbom.cyclonedx.json`, `fail-build: false`,
   `severity-cutoff: high`, xuất SARIF.
6. Upload cả hai SBOM vào artifact `project-sbom-reports` và báo cáo lỗ hổng
   vào artifact `vulnerability-scan-report`.

So với mẫu trong đề, mình đã sửa lỗi thụt dòng của bước
`actions/upload-artifact` và bổ sung đúng yêu cầu Bước 5: thêm CycloneDX và
`anchore/scan-action@7`. Toàn bộ action bên thứ ba được pin bằng commit SHA
40 ký tự.

### 2.2. Kiểm chứng cục bộ

Do Actions bị khóa, mình chạy lại quy trình bằng Syft `1.57.0` và Grype
`0.121.2` trên cùng mã nguồn:

| Chỉ số | Kết quả |
| --- | --- |
| Số package trong SPDX | 26 (gồm package gốc `.`) |
| Số component trong CycloneDX | 57 (32 file + 25 library) |
| Số gói PyPI duy nhất | 12 |
| Định dạng | `spdx-json`, `cyclonedx-json` |

Kiểm tra 4 trường tối thiểu theo NTIA trên `sbom.spdx.json`:

| Trường NTIA | Kết quả |
| --- | --- |
| Name | 26/26 package |
| Version / PURL | 25/25 package phụ thuộc (package gốc `.` không có version) |
| Supplier | 17/26 package có supplier cụ thể, còn lại `NOASSERTION` |
| Hash | 0/26 package có `checksums` trong SPDX; 0/14 component PyPI có `hashes` trong CycloneDX |

Ví dụ package `requests`:

```json
{
  "name": "requests",
  "versionInfo": "2.34.2",
  "supplier": "Person: Kenneth Reitz (me@kennethreitz.org)",
  "externalRefs": [
    { "referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.34.2" }
  ]
}
```

**Nhận xét:** SBOM do Syft sinh từ package manifest có đủ Name, Version và
PURL, nhưng không tự động đủ Hash cấp package. Đây là điểm cần lưu ý khi đối
chiếu NTIA: cần enrich thêm hash từ registry/lockfile hoặc dùng công cụ sinh
SBOM từ artifact đã đóng gói nếu muốn đủ cả 4 trường.

### 2.3. Kết quả quét lỗ hổng

Lần quét đầu với `requests==2.32.3`, `flask==3.0.3` phát hiện 3 lỗ hổng:

| Package | Bản cài | Bản vá | Mã lỗ hổng | Mức độ |
| --- | --- | --- | --- | --- |
| requests | 2.32.3 | 2.32.4 | GHSA-9hjg-9r4m-mvj7 | Medium |
| requests | 2.32.3 | 2.33.0 | GHSA-gc5v-m9x4-r6x2 | Medium |
| flask | 3.0.3 | 3.1.3 | GHSA-68rp-wp8r-4726 | Low |

Sau khi nâng lên `Flask==3.1.3` và `requests==2.34.2`, quét lại báo
**No vulnerabilities found**. Đây là vòng lặp đúng của supply-chain security:
sinh SBOM → quét → vá → sinh lại SBOM → quét lại.

## 3. Bài 2 — Ký số keyless với Sigstore Cosign

Workflow `.github/workflows/cosign-sign.yml` chạy khi push tag `v*` hoặc chạy
tay, với quyền tối thiểu:

```yaml
permissions:
  contents: read
  id-token: write   # bắt buộc để lấy OIDC token từ GitHub
```

Luồng thực hiện:

1. Đóng gói `release.tar.gz` từ `app.py`, `main.py`, `requirements.txt`.
2. Tính `release.tar.gz.sha256`.
3. Cài Cosign bằng `sigstore/cosign-installer` (pin SHA).
4. `cosign sign-blob --yes` để ký keyless; sinh `release.tar.gz.sig` và
   `release.tar.gz.pem`.
5. `cosign verify-blob` với `--certificate-identity` trỏ đúng repo, đúng
   workflow và đúng ref, `--certificate-oidc-issuer` là
   `https://token.actions.githubusercontent.com`.
6. Upload cả 4 tệp vào artifact `release-signed-package`.

Mình đã sửa lỗi cú pháp trong mẫu đề bài: biểu thức
`${ github.repository_owner }` không hợp lệ, được thay bằng
`${{ github.repository }}`; thêm `--yes` để Cosign không chờ xác nhận tương
tác trên runner.

**Kết quả mong đợi:** 4 tệp `release.tar.gz`, `.sig`, `.pem`, `.sha256`;
log của bước verify có `Verified OK`; log ký có link Rekor transparency log.
Do Actions bị khóa billing, các tệp này chưa được sinh trên GitHub trong lần
chạy này; workflow đã được kiểm tra cú pháp bằng `actionlint`.

## 4. Bài 3 — SLSA Level 3 Provenance

Workflow `.github/workflows/slsa-provenance.yml` gồm 2 job:

- **build:** checkout, đóng gói `release.tar.gz`, tính
  `sha256sum | base64 -w0` và xuất qua `GITHUB_OUTPUT`, upload artifact.
- **provenance:** gọi reusable workflow chính thức
  `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0`
  với `base64-subjects` lấy từ job build.

Quyền được tách theo job:

```yaml
permissions: read-all
# build: contents: read
# provenance: actions: read, id-token: write, contents: write
```

Các action bên thứ ba được pin SHA:

| Action | Version | Commit SHA |
| --- | --- | --- |
| `actions/checkout` | v4.2.2 | `11bd71901bbe5b1630ceea73d27597364c9af683` |
| `actions/setup-python` | v5.6.0 | `a26af69be951a213d495a4c3e4e4022e16d87065` |
| `actions/upload-artifact` | v4.6.2 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| `anchore/sbom-action` | v0.15.10 | `ab5d7b5f48981941c4c5d6bf33aeb98fe3bae38c` |
| `anchore/scan-action` | v7 | `e1165082ffb1fe366ebaf02d8526e7c4989ea9d2` |
| `sigstore/cosign-installer` | v4.1.3 | `756fe2d284c7292c4e9b62c8a28f1e5629c59532` |

Riêng reusable workflow của SLSA được tham chiếu bằng tag `v2.0.0` theo đúng
khuyến nghị của SLSA (không pin SHA cho reusable workflow này).

**Kết quả mong đợi:** artifact `release-artifact` và attestation
`multiple.intoto.jsonl`; cấu trúc gồm `_type`,
`predicateType` (`https://slsa.dev/provenance/v1`), `subject` (tên + digest
SHA256 của `release.tar.gz`), `predicate.buildDefinition` (builder id, build
type, external parameters, resolved dependencies) và `predicate.runDetails`
(metadata, byproducts). Có thể xác minh bằng `slsa-verifier verify-artifact`.

## 5. Trạng thái chạy GitHub Actions

Repo đã được tạo và push thành công:

- <https://github.com/nv-hoai/lab-slsa-sbom>

Các run đã được trigger:

| Workflow | Run |
| --- | --- |
| Generate & Scan SBOM | <https://github.com/nv-hoai/lab-slsa-sbom/actions/runs/42585968586> |
| Keyless Artifact Signing with Cosign | <https://github.com/nv-hoai/lab-slsa-sbom/actions/runs/42585975552> |
| SLSA (push main) | <https://github.com/nv-hoai/lab-slsa-sbom/actions/runs/42585969059> |
| SLSA (push tag v1.0.0) | <https://github.com/nv-hoai/lab-slsa-sbom/actions/runs/42585975957> |

Cả 4 run dừng ngay ở bước khởi động job với annotation:

> The job was not started because your account is locked due to a billing
> issue.

Đây là lỗi phía tài khoản GitHub, không phải lỗi YAML hay mã nguồn. Bằng
chứng:

- `actionlint 1.7.12` chạy trên cả 3 workflow, không báo lỗi.
- Cùng mã nguồn, Syft và Grype chạy cục bộ thành công và sinh đầy đủ SBOM,
  báo cáo lỗ hổng trong thư mục `evidence/`.

Sau khi xử lý billing, có thể chạy lại bằng:

```bash
gh workflow run sbom.yml --repo nv-hoai/lab-slsa-sbom
gh workflow run cosign-sign.yml --repo nv-hoai/lab-slsa-sbom
gh workflow run slsa-provenance.yml --repo nv-hoai/lab-slsa-sbom
```

hoặc push tag mới `v1.1.0`.

## 6. Câu hỏi tổng hợp kiến thức

### Câu 1: SBOM CycloneDX đầy đủ đã đủ để khẳng định SLSA Level 3 chưa?

**Chưa đủ.** SBOM và SLSA trả lời hai câu hỏi khác nhau:

- **SBOM** là *danh mục thành phần*: ứng dụng gồm những thư viện nào, phiên
  bản nào, giấy phép gì, có lỗ hổng nào. SBOM có thể được sinh sau khi build,
  thậm chí sinh lại từ source hoặc từ một môi trường khác, và bản thân nó
  không được ràng buộc mật mã với artifact phát hành.
- **SLSA** là *nguồn gốc và tính toàn vẹn của quá trình build*: ai build, từ
  commit nào, bằng builder nào, với tham số nào, có bị sửa sau build không.
  SLSA Level 3 yêu cầu nền tảng build được quản lý, cách ly giữa các build,
  provenance không thể giả mạo, được ký bởi builder, và người dùng xác minh
  được bằng `slsa-verifier`.

Một SBOM CycloneDX đầy đủ vẫn có thể đi kèm một artifact bị chèn mã độc hoặc
được build từ source không đúng. SBOM không chứng minh được:
`artifact = build(source, builder, parameters)`. Vì vậy SBOM không thể thay
thế provenance. Ngược lại, provenance cũng không liệt kê đầy đủ dependency.
Muốn đạt SLSA L3 cần: source integrity, build trên nền tảng hosted, pin
dependency/action, quyền tối thiểu, sinh provenance bằng generator chuẩn,
ký và xác minh provenance; SBOM là lớp bổ sung để quản lý lỗ hổng.

### Câu 2: Vì sao keyless signing của Sigstore an toàn hơn PGP/GPG truyền thống?

PGP/GPG dựa trên **khóa riêng dài hạn**. Khóa này phải được tạo, sao lưu, phân
phối và bảo vệ trong nhiều năm. Nếu bị lộ, kẻ tấn công có thể ký mọi artifact
cho đến khi khóa bị thu hồi; việc thu hồi không đáng tin cậy vì phụ thuộc
keyserver/CRL và người dùng có thể không kiểm tra. Nhiều đội còn lưu khóa
không mã hóa trên laptop/CI, xoay vòng khóa rất khó, và chữ ký PGP không có
nhật ký công khai để phát hiện việc lạm dụng.

Keyless signing của Sigstore giải quyết các điểm này:

1. **Không có khóa riêng dài hạn.** Cosign tạo khóa tạm trong bộ nhớ, xin OIDC
   token ngắn hạn từ GitHub Actions, gửi public key + danh tính lên Fulcio để
   lấy chứng chỉ X.509 chỉ sống vài phút.
2. **Danh tính gắn với workload.** Chứng chỉ chứa repo, workflow, ref (ví dụ
   `https://github.com/owner/repo/.github/workflows/cosign-sign.yml@refs/tags/v1.0.0`),
   nên verifier kiểm tra *ai đã ký* thay vì chỉ kiểm tra *khóa nào*.
3. **Cửa sổ bị xâm phạm rất nhỏ.** Khóa riêng chỉ tồn tại trong thời gian ký;
   không có file `cosign.key` nằm trên máy hay trong secret của CI.
4. **Minh bạch và kiểm toán.** Chữ ký được ghi vào Rekor transparency log;
   mọi người có thể phát hiện một chữ ký bất thường, kể cả khi khóa đã hết hạn.
5. **Giảm gánh nặng vận hành.** Không cần phân phối public key, không cần
   CRL/keyserver, không cần quy trình rotate khóa thủ công.

Đánh đổi: phải tin tưởng OIDC provider, Fulcio và Rekor; phải cấu hình
`--certificate-identity` và `--certificate-oidc-issuer` chính xác; và phải
bảo vệ repo/workflow (branch protection, review) vì danh tính ký gắn với
workflow. PGP vẫn có thể an toàn nếu dùng HSM và khóa ngắn hạn, nhưng chi phí
vận hành cao hơn nhiều so với keyless.

### Câu 3: Vì sao `pull_request_target` nguy hiểm và cách phòng thủ?

`pull_request_target` chạy trong **ngữ cảnh của repo base**, không phải fork.
Vì vậy workflow có thể được cấp secret và `GITHUB_TOKEN` có quyền ghi, kể cả
khi PR đến từ fork. Nếu workflow checkout mã của PR (`github.event.pull_request.head.sha`)
rồi chạy script, cài dependency hoặc build, kẻ tấn công kiểm soát code sẽ chạy
được lệnh trong môi trường có quyền cao: đọc secret, đẩy commit, sửa release,
hoặc đầu độc cache/artifact. Đây là lỗi kinh điển dẫn đến lộ token.

Cách phòng thủ tối ưu:

- **Không dùng `pull_request_target` để chạy code không tin cậy.** Dùng
  `pull_request` cho build/test; sự kiện này không có secret và token chỉ
  read-only.
- **Tách workflow.** Workflow không đặc quyền build artifact từ PR; workflow
  đặc quyền dùng `workflow_run` chỉ để xử lý artifact đã được kiểm tra, và
  tuyệt đối không thực thi code từ artifact đó.
- **Quyền tối thiểu.** Khai báo `permissions: {}` hoặc `contents: read`, chỉ
  mở `id-token: write`/`contents: write` ở job thật sự cần; đặt
  `persist-credentials: false` khi checkout.
- **Không đưa secret vào môi trường của job chạy code PR.** Dùng OIDC và
  credential ngắn hạn thay vì secret dài hạn nếu buộc phải triển khai.
- **Kiểm soát nhánh và người chạy.** Branch protection, required review,
  environment protection/required reviewers, giới hạn người được approve
  workflow từ fork.
- **Pin action bằng SHA** và truyền dữ liệu từ PR qua `env` thay vì nội suy
  trực tiếp `${{ }}` vào shell để tránh expression injection.

Tóm lại, `pull_request_target` chỉ nên dùng cho tác vụ metadata (gắn nhãn,
comment) không checkout và không chạy code của PR.

## 7. Kết luận

Đã hoàn thành:

- Ứng dụng Python tối giản, dependency pin phiên bản.
- Workflow SBOM sinh cả SPDX và CycloneDX, quét Grype từ SBOM.
- Workflow Cosign keyless có sign + verify + upload artifact.
- Workflow SLSA L3 với build tách biệt, quyền tối thiểu và action pin SHA.
- Kiểm chứng cục bộ: SBOM hợp lệ, phát hiện 3 lỗ hổng, vá và quét lại sạch.
- Trả lời 3 câu hỏi tổng hợp.

Hạn chế duy nhất: các lần chạy GitHub Actions bị chặn bởi billing của tài
khoản. Khi billing được xử lý, chỉ cần chạy lại workflow/tag để lấy artifact
Cosign và SLSA thật.
