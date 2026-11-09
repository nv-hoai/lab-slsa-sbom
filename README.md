# Lab: Software Supply Chain Security (SLSA, SBOM, Cosign, Scorecard)

Repo thực hành an toàn chuỗi cung ứng phần mềm, gồm một ứng dụng Python nhỏ và
ba pipeline GitHub Actions:

| Workflow | Mục đích |
| --- | --- |
| `.github/workflows/sbom.yml` | Sinh SBOM SPDX + CycloneDX bằng Anchore Syft và quét lỗ hổng bằng Grype (`anchore/scan-action@v7`) |
| `.github/workflows/cosign-sign.yml` | Ký keyless tệp release bằng Sigstore Cosign (OIDC của GitHub Actions) và xác thực lại |
| `.github/workflows/slsa-provenance.yml` | Sinh chứng nhận SLSA Provenance Level 3 bằng SLSA GitHub Generator |

## Ứng dụng

```text
app.py            # Flask entry point: / và /health
main.py           # Hàm dùng chung + CLI
requirements.txt  # Flask, requests (pin phiên bản)
```

Chạy thử:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
python app.py     # http://127.0.0.1:5000
```

## Kích hoạt pipeline

- **SBOM:** tự chạy khi push/PR vào `main`, hoặc bấm *Run workflow*.
- **Cosign:** push tag (`git tag v1.0.0 && git push origin v1.0.0`) hoặc chạy tay.
- **SLSA:** tự chạy khi push vào `main`/tag, hoặc chạy tay.

## Bảo mật pipeline

- Mọi action bên thứ ba được pin bằng commit SHA 40 ký tự (trừ reusable
  workflow chính thức của SLSA, vốn phải tham chiếu theo tag `v2.0.0`).
- `permissions` được khai báo tối thiểu theo từng job.
- Cosign dùng `id-token: write` và keyless signing, không lưu khóa dài hạn.
- SBOM được quét bằng Grype trực tiếp từ tệp CycloneDX, không quét lại source.

## Tài liệu

- [`BAO_CAO_THUC_HANH.md`](BAO_CAO_THUC_HANH.md): báo cáo, kết quả chạy thật và
  trả lời 3 câu hỏi tổng hợp.
- [`Lab_SLSA_SBOM.docx`](Lab_SLSA_SBOM.docx): đề bài gốc.

## Giấy phép

MIT, xem [`LICENSE`](LICENSE).
