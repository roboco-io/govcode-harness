# R1-A R1-B 스냅샷과 명시적 commit 검사

기준일: 2026-10-28 KST / 코드: v0.4.0 / 범위: 독립 스냅샷 수집·명시적 commit 검사·구조화 결과
R1-C의 예상 commit CI 게이트와 실제 원격 브랜치 보호는 아직 구현하지 않았다.

## 두 검사 모드

| 항목 | 기본 strict_head | 명시적 commit_snapshot |
| --- | --- | --- |
| 선택 방법 | scan에 --commit 없음 | scan --commit에 정확한 SHA 지정 |
| 검사 입력 | 현재 HEAD의 커밋 원본 | 지정 commit의 커밋 원본 |
| 작업 트리·index·비추적 파일 | 엄격하게 확인 | 검사하지 않음 |
| 캐시·가상환경·ignore 파일 | 파일이 남아 있으면 기존 규칙에 따라 거부 | 지정 commit에 없으면 입력 대상 밖 |
| 과거 commit | 기본 검사 대상 아님 | 사용 가능 |
| 작업 코드 실행 | 하지 않음 | 하지 않음 |

명시적 모드는 작업 폴더의 수정·삭제·staged·미추적 파일을 검사했다고 표시하지 않는다.
commit에 포함된 모든 파일을 목록화하며, Python 입력·지원 문서·미지원 파일·인코딩 오류를 구분한다.
지원 문서나 설정의 내용을 코드 검사한 것으로 집계하지 않는다.

## 명시적 검사 실행

프로젝트 디렉터리에서 실행한다. 저장소와 새 증적 경로를 실제 경로로 바꾼다.

```sh
GOVCODE_REPO=/absolute/path/to/repository
GOVCODE_COMMIT="$(git -C "$GOVCODE_REPO" rev-parse HEAD)"
python3 -m govcode_harness scan --repo "$GOVCODE_REPO" --commit "$GOVCODE_COMMIT" --output /absolute/path/to/new-evidence --local-demo
```

--commit은 소문자 40자리 commit SHA만 받는다. HEAD·branch 이름·짧은 ID·tag 객체·blob·없는 객체는 거부한다.
과거 commit을 검사하려면 GOVCODE_COMMIT에 그 commit의 전체 SHA를 넣는다.
출력은 입력 저장소 밖의 새 디렉터리로 지정한다. 기존 출력 디렉터리를 덮어쓰지 않는다.

오철칙을 함께 사용하려면 기존 --with-iron-laws를 추가한다.
설치·프로필·적용 한계는 [오철칙 PoC](IRON_LAWS_POC.md)를 따른다. 기본 활성화하지 않는다.

## 결과 읽기

CLI JSON은 기존 판정·종료 코드 외에 다음 범위를 표시한다.

| 필드 | 의미 |
| --- | --- |
| input_mode | strict_head 또는 commit_snapshot |
| scope | all_tracked_files_at_commit |
| commit_sha | 실제 검사한 commit |
| worktree_checked | strict_head는 true, commit_snapshot은 false |
| head_matches_commit | 결과를 반환할 때 관측한 HEAD와 검사 commit의 일치 여부 |

commit_snapshot에서 exit 0은 **지정 commit의 검사·증적 검증 통과**다.
작업 폴더, 현재 PR 또는 CI의 병합 승인으로 해석하지 않는다.
과거 안전 commit의 결과를 현재 변경의 통과 근거로 사용해서는 안 된다. CI의 예상 commit 대조는 R1-C에서 구현한다.
종료 코드는 기존대로 0=allow, 2=deny, 3=review_required, 4=error다.

## 증적 재검증

기본 verify는 증적 commit이 현재 HEAD와 같은지 확인한다.
strict_head 증적은 작업 폴더도 엄격하게 확인한다.
commit_snapshot 증적은 작업 폴더를 확인하지 않으며 결과에 worktree_checked=false를 표시한다.

```sh
python3 -m govcode_harness verify --repo "$GOVCODE_REPO" --evidence /absolute/path/to/evidence --local-demo
```

과거 commit_snapshot 증적을 재검증하려면 같은 SHA를 다시 명시한다.

```sh
python3 -m govcode_harness verify --repo "$GOVCODE_REPO" --evidence /absolute/path/to/evidence --commit "$GOVCODE_COMMIT" --local-demo
```

다른 SHA나 strict_head 증적에 이 옵션을 사용하면 거부한다.
verify가 증적만 보고 과거 commit의 결과로 자동 통과하도록 변경하지 않았다.
선택적 외부 검사는 증적의 검사 프로필에 따라 자동 재실행한다.

## 스냅샷 기록과 입력 보호

snapshot.py가 Git 객체 읽기·commit 검증·파일 분류·자원 상한과 원문 없는 manifest를 담당한다.
모든 새 실행의 snapshot.json에 다음을 기록하고 manifest·receipt·의미 재검증에 포함한다.

- commit SHA와 전체 파일 목록의 digest.
- 파일별 상대 경로·내용 SHA-256·바이트 수·분류·이유 코드.
- 전체 크기·지원 Python 파일 수·수집 단계의 문제 코드.

원문 코드는 내부 분석용 sources에만 있고 snapshot.json에는 없다.
python_source는 분석 가능한 입력이라는 뜻이다. AST 분석 완료나 위험 없음 판정은 아니다.
지원하지 않는 코드나 인코딩 오류는 기존처럼 검토 필요·오류로 남는다.

Git 읽기는 저장소의 hook·fsmonitor·clean filter·외부 프로토콜을 사용하지 않도록 제한한다.
replace·graft 설정으로 조회 객체가 바뀌지 않도록 하고, 출력·시간·자체 프로세스 그룹을 제한한다.
입력 코드·저장소 스크립트는 실행하지 않는다. 파일 수 100개·파일당 256,000바이트·합계 2,000,000바이트의 기존 상한을 유지한다.
미지원·상한 초과를 조용히 제외해 allow로 만들지 않는다.

독립 스키마는 [snapshot.schema.json](../packages/contracts/snapshot.schema.json)이다.
Run·Finding·Decision·Evidence는 기존 catalog를 사용하며, 스냅샷은 별도 계약으로 검사한다.

## 호환성과 현재 경계

기본 HEAD 검사의 엄격한 동작과 기존 종료 코드는 유지한다.
입력 모드는 execution.json의 input_scope와 실행 지문에 연결한다.
스냅샷 삭제·수정, 모드 강등, 다른 입력 모드의 부모 연결을 거부한다.
새 증적에는 snapshot.json이 필요하다. v0.3 증적을 현재 도구의 통과 결과로 자동 승격하지 않는다.

현재도 local_demo 예시 정책과 unsigned 로컬 증적을 사용한다.
기관 승인·운영 서명·증적 이동성·원격 CI 연결은 후속 단계다.
과거 도구를 실행하지 않는 역사적 무결성 확인은 R4 범위이며 이번 명시적 commit 재검증과 다르다.
