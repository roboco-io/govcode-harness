# GovCode Harness 로컬 참조 실행 안내

코드 버전: v0.9.0. R1-C부터 R6까지의 소프트웨어를 합성 자료·합성 역할로 연결한 로컬 참조다.
기관 운영 승인·법령 적용 확정·원격 CI 배포·실데이터 파일럿을 완료했다는 뜻은 아니다.
기본 검사기는 유지하고 오철칙은 선택 기능으로 둔다.

## 1. 현재 작업 폴더에서 전체 실행

참조 의존성이 이미 설치된 이 프로젝트에서 다음을 실행한다.

```sh
.runtime/reference-venv/bin/python -m govcode_harness reference-demo --output .runtime/my-reference-demo
```

새 전용 폴더에만 자료를 만든다. 이미 있는 출력 폴더는 덮어쓰지 않는다.
다음 흐름을 실제로 수행한다.

1. 서로 다른 합성 작성자·승인자·운영자·감사 열람자의 키와 공개 신뢰 목록 생성.
2. 예시 정책 초안·검토·독립 승인·Ed25519 서명 묶음 발급.
3. 위험 commit 검사와 CI 예상 commit 게이트의 거부 확인.
4. 모의 모델의 수정 제안과 독립 서명 승인, 새 sandbox commit 생성·정적 재검사·실제 OS 격리 회귀 검증.
5. 별도 알려진 수정 commit의 검사·서명 정책 게이트 통과.
6. 원문 없는 포터블 서명 증적과 여러 부모 실행의 ID·digest 사슬 생성.
7. 보관·읽기·보존 잠금·백업·복구와 만료 후 삭제 검증.
8. 실제 loopback 관리 API의 역할·기관 경계·인증 거부 검증.

reference-result.json은 원문·개인 키·접속 토큰을 제외한 결과다.
model_checks.backend=fixture, real_model_executed=false를 명시한다. 실제 모델 추론이나 품질은 시험하지 않았다.
격리가 불가능하거나 필수 검사가 미완료면 exit 3이며 완료로 표시하지 않는다. 오류는 exit 4다.

## 2. 새 환경에서 설치

Python 3.12 이상과 uv가 필요하다. 원래 검사·기본 데모 경로는 표준 라이브러리를 유지한다.
서명·관리·보관 참조 기능에는 별도 참조 환경의 의존성이 필요하다.

```sh
python3 scripts/setup_reference.py --python /absolute/path/to/python3.12 --uv /absolute/path/to/uv
```

requirements-reference.lock과 빌드 도구 lock의 버전·배포 해시를 확인해 .runtime/reference-venv에 설치한다.
신뢰한 이 프로젝트를 일반 패키지로 설치하고 필요한 정책·UI 자원도 포함한다. CI의 -I 격리 모드는 이 설치본을 사용하며 검사 대상의 Python 모듈은 불러오지 않는다.
원본 프로젝트 경로에서 실행하는 오철칙 선택 PoC와 패키지 설치본의 기본/서명 CI 경로를 구분한다. 패키지 설치본에 외부 오철칙 실행 환경을 자동 복제하지 않는다.
기존 환경을 덮어쓰지 않는다. 이미 설치됐다면 그대로 사용하거나 --environment로 새 .runtime/ 하위 경로를 지정한다.
처음에는 패키지 다운로드를 위해 인터넷이 필요하다. 캐시가 준비된 환경은 --offline으로 설치할 수 있다.
프로젝트 밖 환경이나 경로 탈출·symlink는 거부하며 전역 Python·사용자 설정을 변경하지 않는다.
이번 실제 검증 환경은 macOS와 Python 3.12다. OS 격리 수정 검증은 macOS sandbox-exec를 사용한다.
다른 플랫폼이나 제한 실행기에서 격리를 사용할 수 없으면 undeterminable로 종료한다.

## 3. 관리 화면

```sh
.runtime/reference-venv/bin/python -m govcode_harness control --config .runtime/my-reference-demo/control-config.json --port 8766
```

표시된 127.0.0.1 주소를 브라우저에서 연다. 외부 인터페이스에는 바인딩하지 않는다.
control-bootstrap.json은 0600 권한의 합성 접속 토큰 파일이다. 필요한 역할의 토큰을 로컬에서 확인해 접속한다.
토큰 파일·개인 키·설정 파일을 공개하거나 보고서에 붙이지 않는다.

| 역할 | 화면에서 가능한 일 |
| --- | --- |
| author | 예시 정책 초안·검토 제출·등록된 실행에 대한 예외 요청 |
| approver | 다른 작성자의 정책·예외 검토와 승인 |
| operator | 승인 정책 묶음 발급·보관 잠금 관리 |
| auditor | 자기 기관·프로젝트의 실행·정책·증적 열람 |

화면의 승인은 합성 역할의 참조 승인이다. 실제 기관 사용자·OIDC·LDAP 연결이 아니다.
접속 정보는 브라우저 메모리에만 두고 로그아웃하면 지운다. 다른 기관·프로젝트나 역할은 서버에서 거부한다.
데모 종료 후 화면은 복구한 store를 사용하므로 보존 잠금된 실제 합성 증적을 열람할 수 있다.

[데스크톱 화면 예시](images/control-desk-desktop.png) · [모바일 화면 예시](images/control-desk-mobile.png)
화면 예시는 합성 감사 열람자로 확인한 UI이며 비밀값을 포함하지 않는다.

## 4. CI 게이트

```sh
.runtime/reference-venv/bin/python -m govcode_harness gate --help
```

게이트는 신뢰한 CI 문맥의 전체 expected commit, 실제 HEAD, 증적 commit, 검사 프로필과 receipt를 대조한다.
서명 정책을 사용하는 경우 bundle·trust·기관·프로젝트·최소 순번을 함께 지정한다.
예외는 commit·현재 도구·정책·탐지 의미 digest에 묶으며, 철회된 작성자·승인자·양쪽 서명 기록은 사용할 수 없다.
오류·검토 필요·미분석과 법적 의무를 예시 예외로 면제하지 않는다.

ci/reference-gate.sh는 기본 입력 게이트 예제이고 ci/reference-signed-gate.sh는 서명 정책·신뢰·범위·최소 순번이 필수인 예제다.
서명 wrapper의 보안 자료는 검사 checkout 밖의 신뢰한 CI 경로에서 제공한다. 필요하면 GOVCODE_REVOCATIONS를 전달한다.
승인 예외는 새 scan의 ID가 아니라 승인한 정확한 기록에 적용한다. GOVCODE_EXISTING_EVIDENCE와 GOVCODE_EXCEPTIONS로 같은 현재 commit의 기존 증적을 재검증하는 두 단계 흐름을 사용할 수 있다. 게이트가 오류·검토 필요를 완화하지 않는다.
이 wrapper와 제공자별 .example.yml은 비활성 예제다. 실제 원격 저장소나 보호 브랜치를 생성·수정하지 않았다.
CI가 제공하는 expected commit을 저장소 안의 사용자 파일에서 가져오면 안 된다.
[스냅샷 검사 범위](SNAPSHOT_COMMIT_MODE.md)를 함께 확인한다.

## 5. 과거 증적 확인

전체 데모의 archive 폴더를 다른 새 폴더로 복사한 뒤 다음과 같이 확인할 수 있다.

```sh
.runtime/reference-venv/bin/python scripts/verify_reference_archive.py --archive /absolute/path/to/copied-archive --trust .runtime/my-reference-demo/public-trust.json --tenant-id TENANT-REFERENCE --project-id PROJECT-REFERENCE
```

이 결과는 archive_integrity와 release_approval=false다. 소스 저장소·현재 검사 도구를 실행하지 않고 서명·내용 digest·부모 사슬만 확인한다.
현재 commit의 CI 통과 근거로 사용할 수 없다. 부모는 최대 16개의 원문 없는 투영 기록으로 연결한다.
생성자 원본은 unsigned이며, 서명은 검증된 원본에서 파생한 투영을 운영자가 확인했다는 참조 증명이다.

보관소의 권한·보존 잠금·만료 삭제·백업·복구는 EvidenceStore API와 전체 데모에서 확인한다.
완전한 오프라인 상태 복원에는 외부의 신뢰한 head digest/최소 순번이 필요하다.
로컬 OS 소유자의 전체 파일 대체까지 막는 WORM/KMS를 구현했다는 뜻은 아니다.

## 6. 평가와 시험

```sh
.runtime/reference-venv/bin/python -m unittest discover -s tests -p 'test_*.py' -q
.runtime/reference-venv/bin/python -m govcode_harness evaluate --dataset tests/fixtures/evaluation_confirmatory.json --output .runtime/my-confirmatory-result.json
```

평가기는 원문을 실행하지 않는다. 고정 표본의 ID·정답·판정·탐지 수·문제 코드와 분모를 기록한다.
최초 holdout은 과도한 예외 처리 검토 비율로 실패했고 진단용으로 전환했다.
수정 뒤 원래 표본 재실행과 새로 작성한 독립 확인 표본 40건을 따로 보관한다.
[corpus 설명](R2_CORPUS.md)과 최종 검증 기록을 따른다. 실제 기관 정확도나 보정된 확률을 뜻하지 않는다.

실제 HTTP·OS 격리 시험은 해당 기능이 허용되는 로컬 실행 환경에서 수행해야 한다.
격리 검증은 CPU·시간·출력·파일·프로세스를 제한하며 메모리는 RSS 감시 방식이다. 하드 메모리 상한으로 표현하지 않는다.
검증 가능한 AST 부분집합 외의 수정은 실행하지 않고 판단 불가로 남긴다.

## 7. 실제 운영으로 옮기기 전

[외부 운영 준비 조건](EXTERNAL_READINESS.md)을 확정해야 한다.
실제 법령 적용·기관 승인·보존 분류·신원·키 관리·원격 CI·실모델·실데이터 파일럿은 이번 합성 소프트웨어 검증과 구분한다.
