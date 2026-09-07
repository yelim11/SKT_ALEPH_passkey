# Yerim Passkey Portfolio — 과제 8 최종 정리본

기존 공개 소개 페이지는 누구나 볼 수 있고, `PRIVATE` 영역만 WebAuthn 패스키로 보호합니다. 비밀번호 입력칸은 없습니다.

## 남겨 둔 파일

```text
yerim-passkey-clean/
├─ public/
│  ├─ index.html      # 공개 소개 + PRIVATE UI
│  └─ app.js          # 패스키 등록/로그인/로그아웃/검증 UI
├─ server.js          # challenge, 공개키 저장, 서명검증, 세션, 401/403
├─ package.json       # Node 실행 정보
├─ .env.example       # 로컬/배포 환경값 예시
├─ .gitignore         # data, .env 제외
├─ README.md          # 실행/배포 방법
└─ SUBMISSION.md      # 과제 제출문 + 체크리스트
```

중복 `index.html`, `frontend-single-file.html`, HTA/BAT 실행기, 임시 점검 보고서 등은 제거했습니다.

## 로컬 실행

Node.js 18 이상에서 별도 패키지 설치 없이 실행합니다.

```bash
node server.js
```

브라우저에서 `http://localhost:3000`을 엽니다.

## GitHub에 올릴 때

이 폴더의 파일을 그대로 하나의 저장소에 올리면 됩니다. `data/`와 `.env`는 `.gitignore`에 의해 제외됩니다.

GitHub Pages로 배포하면 안 됩니다. 이 과제는 `server.js`가 실행되어야 하므로 Node.js 서버를 지원하는 HTTPS 호스팅에 GitHub 저장소를 연결해야 합니다.

## HTTPS 배포 환경값

결과물 주소가 예를 들어 `https://yerim-passkey.example.com`이라면 호스팅 환경변수를 다음처럼 설정합니다.

```text
RP_ID=yerim-passkey.example.com
ORIGIN=https://yerim-passkey.example.com
HOST=0.0.0.0
```

호스팅 서비스가 `PORT`를 자동 제공하면 그 값을 사용합니다.

패스키 공개키와 등록 정보는 `DATA_DIR/db.json`에 저장됩니다. 서버 재시작/재배포 뒤에도 패스키를 유지해야 하므로 최종 제출 호스팅에서는 **영구 디스크/볼륨을 연결하고 `DATA_DIR`을 그 경로로 지정**하는 것이 안전합니다.

## 사용 순서

1. 결과물 HTTPS 주소를 엽니다.
2. `PRIVATE`에서 첫 패스키를 등록합니다.
3. 패스키로 로그인하면 서버가 비공개 자료 3개를 내려줍니다.
4. 로그인 상태에서 두 번째 패스키를 추가합니다.
5. 하나를 삭제하고 남은 패스키로 다시 로그인합니다.
6. 제출 증거가 필요할 때만 `과제 검증 도구 보기`를 펼칩니다.

공유 PC에서는 패스키를 그 PC 자체에 저장하지 말고, 가능하면 본인 휴대폰/개인 기기를 사용하세요.

## 비공개 자료 관리

패스키 로그인 후 PRIVATE 영역에서 다음 기능을 사용할 수 있습니다.

- `+ 자료 추가`: 과제용 가상 비공개 자료를 새로 추가
- 각 카드의 `수정`: 제목과 내용을 서버에 저장
- `기본 3개로 초기화`: 현재 계정의 비공개 자료를 과제 기본값 3개로 복원

비공개 자료 변경 API도 모두 로그인 세션을 요구하므로 인증 전에는 401로 거절됩니다. 실제 개인정보는 넣지 마세요.
