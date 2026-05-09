# security_study

하드웨어 보안 칩 및 신뢰 루트(Root of Trust) 기술 학습 저장소.

## 프로젝트

| 디렉토리 | 내용 |
|----------|------|
| [`caliptra_project/`](caliptra_project/) | CHIPS Alliance Caliptra 2.x SoC 통합 연구 |

## 환경 설정

### Rust (caliptra_comms 빌드용)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.85
source "$HOME/.cargo/env"
```

### 서브모듈 초기화

```bash
git submodule update --init
```
