다음 단계로 git commit을 수행해줘:

1. `git status`와 `git diff --staged` (staged 없으면 `git diff`)를 실행해서 변경 사항 파악
2. 변경 내용을 분석해서 커밋 메시지 초안 작성:
   - 제목: 50자 이내, 명령형 영어 (Add / Fix / Update / Remove / Refactor 등)
   - 본문: 필요 시 변경 이유 간략히
   - 푸터: `Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>` 항상 포함
3. 스테이징되지 않은 파일이 있으면 어떤 파일을 포함할지 나에게 확인
4. 확인 후 `git add` + `git commit` 실행

$ARGUMENTS
