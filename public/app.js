(() => {
  const $ = (id) => document.getElementById(id);
  const evidence = [];
  let statusCache = null;
  let currentPrivate = null;

  function b64urlToBytes(value) {
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  }

  function bytesToB64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  function preview(value) {
    if (!value) return '';
    return value.length <= 18 ? value : `${value.slice(0, 9)}…${value.slice(-7)}`;
  }

  function log(text, kind = 'info') {
    const entry = `${new Date().toLocaleTimeString('ko-KR')} · ${text}`;
    evidence.unshift({ entry, kind });
    evidence.splice(80);
    renderEvidence();
  }

  function renderEvidence() {
    const list = $('evidence-list');
    if (!list) return;
    list.innerHTML = '';
    for (const item of evidence) {
      const li = document.createElement('li');
      li.dataset.kind = item.kind;
      li.textContent = item.entry;
      list.appendChild(li);
    }
    if (!evidence.length) {
      const li = document.createElement('li');
      li.textContent = '아직 기록이 없습니다. 패스키 등록/로그인 또는 확인 버튼을 실행하세요.';
      list.appendChild(li);
    }
  }

  function message(text, kind = 'info') {
    const el = $('private-message');
    el.hidden = false;
    el.dataset.kind = kind;
    el.textContent = text;
  }

  async function api(url, options = {}) {
    const response = await fetch(url, {
      credentials: 'same-origin',
      headers: options.body ? { 'Content-Type': 'application/json', ...(options.headers || {}) } : (options.headers || {}),
      ...options,
    });
    let body = null;
    try { body = await response.json(); } catch { body = {}; }
    return { response, body };
  }

  function creationOptions(json) {
    return {
      ...json,
      challenge: b64urlToBytes(json.challenge),
      user: { ...json.user, id: b64urlToBytes(json.user.id) },
      excludeCredentials: (json.excludeCredentials || []).map((c) => ({ ...c, id: b64urlToBytes(c.id) })),
    };
  }

  function requestOptions(json) {
    return {
      ...json,
      challenge: b64urlToBytes(json.challenge),
      allowCredentials: (json.allowCredentials || []).map((c) => ({ ...c, id: b64urlToBytes(c.id) })),
    };
  }

  function serializeRegistration(credential) {
    const r = credential.response;
    const out = {
      id: credential.id,
      rawId: bytesToB64url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: bytesToB64url(r.clientDataJSON),
        attestationObject: bytesToB64url(r.attestationObject),
        transports: typeof r.getTransports === 'function' ? r.getTransports() : [],
      },
      clientExtensionResults: credential.getClientExtensionResults(),
      authenticatorAttachment: credential.authenticatorAttachment || undefined,
    };
    return out;
  }

  function serializeAuthentication(credential) {
    const r = credential.response;
    return {
      id: credential.id,
      rawId: bytesToB64url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: bytesToB64url(r.clientDataJSON),
        authenticatorData: bytesToB64url(r.authenticatorData),
        signature: bytesToB64url(r.signature),
        userHandle: r.userHandle ? bytesToB64url(r.userHandle) : undefined,
      },
      clientExtensionResults: credential.getClientExtensionResults(),
      authenticatorAttachment: credential.authenticatorAttachment || undefined,
    };
  }

  async function refreshStatus() {
    try {
      const { response, body } = await api('/api/status');
      if (!response.ok) throw new Error('상태 확인 실패');
      statusCache = body;
      renderStatus();
      if (body.session) await loadPrivate();
      else renderLocked();
    } catch (error) {
      $('boundary-status').textContent = 'SERVER OFFLINE';
      $('runtime-info').textContent = '서버 연결이 필요합니다. 이 HTML 파일만 직접 열면 패스키 API는 동작하지 않습니다.';
      message('서버에 연결할 수 없습니다. 배포된 HTTPS 주소에서 열거나 로컬 프로젝트 폴더에서 node server.js로 실행하세요.', 'error');
    }
  }

  function renderStatus() {
    const s = statusCache;
    $('runtime-info').textContent = `RP ID: ${s.webauthn.rpID} · Origin: ${s.webauthn.origin}`;
    $('boundary-status').textContent = s.session ? `UNLOCKED · ${s.session.label}` : 'LOCKED · PASSKEY REQUIRED';
    $('bootstrap-box').hidden = s.ownerReady;
    $('login-box').hidden = !s.ownerReady;

    const select = $('login-account');
    if (select) {
      select.innerHTML = '';
      for (const a of s.accounts.filter((a) => a.passkeyCount > 0)) {
        const option = document.createElement('option');
        option.value = a.id;
        option.textContent = `${a.label} · 패스키 ${a.passkeyCount}개`;
        select.appendChild(option);
      }
    }
  }

  function renderLocked() {
    $('private-locked').hidden = false;
    $('private-unlocked').hidden = true;
    currentPrivate = null;
  }

  async function loadPrivate() {
    const { response, body } = await api('/api/private');
    if (!response.ok) {
      renderLocked();
      return;
    }
    currentPrivate = body;
    $('private-locked').hidden = true;
    $('private-unlocked').hidden = false;
    $('boundary-status').textContent = `UNLOCKED · ${body.user.label}`;
    $('logged-in-user').textContent = `🔓 ${body.user.label}`;

    const items = $('private-items');
    items.innerHTML = '';
    $('private-item-count').textContent = `${body.items.length}개`;
    body.items.forEach((item, index) => {
      const card = document.createElement('article');
      card.className = 'private-item';

      const no = document.createElement('span');
      no.textContent = `PRIVATE ${String(index + 1).padStart(2, '0')}`;

      const view = document.createElement('div');
      const h = document.createElement('h4');
      h.textContent = item.title;
      const text = document.createElement('p');
      text.textContent = item.body;
      const actions = document.createElement('div');
      actions.className = 'private-item-actions';
      const editButton = document.createElement('button');
      editButton.type = 'button';
      editButton.className = 'danger-outline';
      editButton.textContent = '수정';
      actions.appendChild(editButton);
      view.append(h, text, actions);

      const edit = document.createElement('div');
      edit.className = 'private-item-edit';
      edit.hidden = true;
      const titleLabel = document.createElement('label');
      titleLabel.textContent = '제목';
      const titleInput = document.createElement('input');
      titleInput.type = 'text';
      titleInput.maxLength = 60;
      titleInput.value = item.title;
      titleLabel.appendChild(titleInput);
      const bodyLabel = document.createElement('label');
      bodyLabel.textContent = '내용';
      const bodyInput = document.createElement('textarea');
      bodyInput.rows = 4;
      bodyInput.maxLength = 500;
      bodyInput.value = item.body;
      bodyLabel.appendChild(bodyInput);
      const editActions = document.createElement('div');
      editActions.className = 'private-item-actions';
      const save = document.createElement('button');
      save.type = 'button';
      save.className = 'passkey-button';
      save.textContent = '저장';
      const cancel = document.createElement('button');
      cancel.type = 'button';
      cancel.className = 'danger-outline';
      cancel.textContent = '취소';
      editActions.append(save, cancel);
      edit.append(titleLabel, bodyLabel, editActions);

      editButton.addEventListener('click', () => {
        view.hidden = true;
        edit.hidden = false;
        titleInput.focus();
      });
      cancel.addEventListener('click', () => {
        titleInput.value = item.title;
        bodyInput.value = item.body;
        edit.hidden = true;
        view.hidden = false;
      });
      save.addEventListener('click', () => updatePrivateItem(item.id, titleInput.value, bodyInput.value));

      card.append(no, view, edit);
      items.appendChild(card);
    });
    $('private-data-note').textContent = `${body.note} · 여기에서 추가/수정한 내용도 서버에 저장됩니다.`;
    await refreshPasskeys();
    renderTesterState();
  }

  async function addPrivateItem() {
    const title = $('private-new-title').value.trim();
    const bodyText = $('private-new-body').value.trim();
    if (!title || !bodyText) return message('자료 제목과 내용을 모두 입력하세요.', 'error');
    const result = await api('/api/private/items', {
      method: 'POST',
      body: JSON.stringify({ title, body: bodyText }),
    });
    if (!result.response.ok) return message(result.body.message || '자료 추가에 실패했습니다.', 'error');
    log(`비공개 자료 추가 · ${title} · 총 ${result.body.count}개`, 'success');
    $('private-new-title').value = '';
    $('private-new-body').value = '';
    $('private-add-form').hidden = true;
    message('비공개 자료를 추가했습니다.', 'success');
    await loadPrivate();
  }

  async function updatePrivateItem(itemId, titleValue, bodyValue) {
    const title = String(titleValue || '').trim();
    const bodyText = String(bodyValue || '').trim();
    if (!title || !bodyText) return message('자료 제목과 내용을 모두 입력하세요.', 'error');
    const result = await api(`/api/private/items/${encodeURIComponent(itemId)}`, {
      method: 'PATCH',
      body: JSON.stringify({ title, body: bodyText }),
    });
    if (!result.response.ok) return message(result.body.message || '자료 수정에 실패했습니다.', 'error');
    log(`비공개 자료 수정 · ${title}`, 'success');
    message('비공개 자료를 수정했습니다.', 'success');
    await loadPrivate();
  }

  async function resetPrivateItems() {
    if (!confirm('현재 비공개 자료를 지우고 과제용 기본 3개로 되돌릴까요?')) return;
    const result = await api('/api/private/reset', { method: 'POST' });
    if (!result.response.ok) return message(result.body.message || '자료 초기화에 실패했습니다.', 'error');
    log(`비공개 자료 초기화 · 기본 ${result.body.count}개 복원`, 'success');
    $('private-new-title').value = '';
    $('private-new-body').value = '';
    $('private-add-form').hidden = true;
    message('비공개 자료를 기본 3개로 초기화했습니다.', 'success');
    await loadPrivate();
  }

  function renderTesterState() {
    const tester = statusCache?.accounts?.find((a) => a.id === 'tester');
    if (!tester) return;
    $('tester-state').textContent = tester.passkeyCount
      ? `등록됨 · 패스키 ${tester.passkeyCount}개. 로그아웃 후 로그인 계정에서 테스트 계정을 선택할 수 있습니다.`
      : '아직 패스키가 없습니다. 소유자 계정 로그인 상태에서 하나 등록하세요.';
    $('tester-register-wrap').hidden = Boolean(tester.passkeyCount) || !statusCache?.session?.isOwner;
  }

  async function registerPasskey(account, name, storageType) {
    let challengeId = null;
    try {
      const start = await api('/api/register/options', { method: 'POST', body: JSON.stringify({ account }) });
      if (!start.response.ok) throw new Error(start.body.message || start.body.error || '등록 options 실패');
      challengeId = start.body.challengeId;
      log(`등록 challenge 발급 · ${account} · ${start.body.challengePreview}`);

      const publicKey = creationOptions(start.body.options);

      // The UI choice is not just a label: use WebAuthn Level 3 hints to
      // prefer the requested authenticator UI. Browsers may still ignore a
      // hint when that authenticator is unavailable or blocked by policy.
      if (storageType === 'Google 비밀번호 관리자') {
        publicKey.hints = ['hybrid'];
        // Do not force authenticatorAttachment here. Leaving it open lets a
        // supporting browser choose cross-device phone/QR authentication.
        if (publicKey.authenticatorSelection) {
          delete publicKey.authenticatorSelection.authenticatorAttachment;
        }
        log('등록 방식 요청 · 휴대폰/QR(hybrid) 우선');
      } else if (storageType === '기기 자체') {
        publicKey.hints = ['client-device'];
        publicKey.authenticatorSelection = {
          ...(publicKey.authenticatorSelection || {}),
          authenticatorAttachment: 'platform',
        };
        log('등록 방식 요청 · 현재 기기(client-device) 우선');
      } else if (storageType === '보안 키') {
        publicKey.hints = ['security-key'];
        publicKey.authenticatorSelection = {
          ...(publicKey.authenticatorSelection || {}),
          authenticatorAttachment: 'cross-platform',
        };
        log('등록 방식 요청 · USB/NFC 보안 키(security-key) 우선');
      } else {
        delete publicKey.hints;
        if (publicKey.authenticatorSelection) {
          delete publicKey.authenticatorSelection.authenticatorAttachment;
        }
        log('등록 방식 요청 · 브라우저 기본 선택');
      }

      const credential = await navigator.credentials.create({ publicKey });
      if (!credential) throw new Error('패스키 생성 결과가 없습니다.');
      const serialized = serializeRegistration(credential);
      log('등록 응답 전송 필드: id/rawId/clientDataJSON/attestationObject/transports · privateKey 필드 없음');

      const finish = await api('/api/register/verify', {
        method: 'POST',
        body: JSON.stringify({ account, challengeId, response: serialized, passkeyName: name, storageType }),
      });
      if (!finish.response.ok) throw new Error(finish.body.message || finish.body.error || '등록 검증 실패');
      log(`등록 성공 200 · 서버 공개키 저장 ${preview(finish.body.passkey.publicKey)} · 개인키 전송 없음`, 'success');
      message('패스키 등록에 성공했습니다. 서버에는 공개키만 저장했습니다.', 'success');
      await refreshStatus();
    } catch (error) {
      if (challengeId && (error?.name === 'NotAllowedError' || error?.name === 'AbortError')) {
        await api('/api/register/cancel', { method: 'POST', body: JSON.stringify({ account, challengeId }) });
        log('패스키 등록 취소 · challenge 폐기 · 새 passkey 저장 없음', 'error');
        message('등록을 취소했습니다. 서버에 새 패스키는 저장되지 않았습니다.', 'info');
        return;
      }
      log(`등록 실패 · ${error.message}`, 'error');
      message(`패스키 등록 실패: ${error.message}`, 'error');
    }
  }

  async function getAssertion(account) {
    const start = await api('/api/login/options', { method: 'POST', body: JSON.stringify({ account }) });
    if (!start.response.ok) throw new Error(start.body.message || start.body.error || '로그인 options 실패');
    log(`로그인 challenge 발급 · ${account} · ${start.body.challengePreview}`);
    const credential = await navigator.credentials.get({ publicKey: requestOptions(start.body.options) });
    if (!credential) throw new Error('패스키 인증 결과가 없습니다.');
    return { challengeId: start.body.challengeId, response: serializeAuthentication(credential) };
  }

  async function login(account) {
    try {
      const assertion = await getAssertion(account);
      const finish = await api('/api/login/verify', {
        method: 'POST',
        body: JSON.stringify({ account, ...assertion }),
      });
      if (!finish.response.ok) throw new Error(finish.body.message || finish.body.error || '로그인 검증 실패');
      sessionStorage.setItem('yerim-last-successful-auth', JSON.stringify({ account, ...assertion }));
      log(`로그인 성공 200 · ${finish.body.user.label} · 서버 세션 생성(값은 숨김)`, 'success');
      message('패스키 서명 검증에 성공했습니다.', 'success');
      await refreshStatus();
    } catch (error) {
      log(`로그인 실패 · ${error.message}`, 'error');
      message(`패스키 로그인 실패: ${error.message}`, 'error');
    }
  }

  async function refreshPasskeys() {
    const { response, body } = await api('/api/passkeys');
    if (!response.ok) return;
    $('passkey-count').textContent = `패스키 ${body.passkeys.length}개 등록됨`;
    const root = $('passkey-list');
    root.innerHTML = '';
    body.passkeys.forEach((p) => {
      const row = document.createElement('div');
      row.className = 'passkey-row';
      const info = document.createElement('div');
      const strong = document.createElement('strong');
      strong.textContent = p.name;
      const meta = document.createElement('span');
      meta.textContent = `${new Date(p.createdAt).toLocaleString('ko-KR')} · ${p.storageType} · ${p.deviceType || 'device type unknown'}`;
      const key = document.createElement('code');
      key.textContent = `publicKey(base64url): ${p.publicKey}`;
      info.append(strong, meta, key);
      const del = document.createElement('button');
      del.type = 'button';
      del.className = 'danger-outline';
      del.textContent = '삭제';
      del.disabled = body.passkeys.length <= 1;
      del.title = body.passkeys.length <= 1 ? '마지막 패스키는 삭제할 수 없습니다.' : '이 패스키를 서버 목록에서 삭제합니다.';
      del.addEventListener('click', async () => {
        const result = await api(`/api/passkeys/${encodeURIComponent(p.id)}`, { method: 'DELETE' });
        if (result.response.ok) {
          sessionStorage.setItem('yerim-last-deleted-passkey', JSON.stringify({ account: statusCache?.session?.userId, id: p.id, name: p.name }));
          log(`패스키 삭제 성공 · ${p.name} · 남은 패스키 ${result.body.remaining}개`, 'success');
          message('패스키를 삭제했습니다. 남은 패스키로 로그인을 확인하세요.', 'success');
          await refreshStatus();
        } else {
          log(`패스키 삭제 거절 ${result.response.status} · ${result.body.message || result.body.error}`, 'error');
          message(result.body.message || '삭제가 거절되었습니다.', 'error');
        }
      });
      row.append(info, del);
      root.appendChild(row);
    });
  }

  async function logout() {
    const result = await api('/api/logout', { method: 'POST' });
    log(`로그아웃 ${result.response.status} · 세션 폐기`, result.response.ok ? 'success' : 'error');
    const after = await api('/api/private');
    log(`로그아웃 직후 같은 GET /api/private → HTTP ${after.response.status} · ${after.body.error || ''}`, after.response.status === 401 ? 'success' : 'error');
    message(`로그아웃했습니다. 비공개 API 재요청 결과는 HTTP ${after.response.status}입니다.`, after.response.status === 401 ? 'success' : 'error');
    await refreshStatus();
  }

  async function testUnauth() {
    const response = await fetch('/api/private', { credentials: 'omit' });
    const body = await response.json().catch(() => ({}));
    log(`로그인 없이 GET /api/private → ${response.status} ${body.error || ''}`, response.status === 401 ? 'success' : 'error');
    message(`인증 없는 요청 결과: HTTP ${response.status}`, response.status === 401 ? 'success' : 'error');
  }

  async function testCrossAccount() {
    if (!statusCache?.session) return message('먼저 패스키로 로그인하세요.', 'error');
    const other = statusCache.session.userId === 'owner' ? 'tester' : 'owner';
    const result = await api(`/api/private/users/${other}`);
    log(`계정 ${statusCache.session.userId} → ${other} 비공개 자료 요청 → ${result.response.status} · 건수 ${result.body.countBefore ?? '?'}→${result.body.countAfter ?? '?'}`,
      result.response.status === 403 ? 'success' : 'error');
    message(`다른 계정 자료 요청 결과: HTTP ${result.response.status}`, result.response.status === 403 ? 'success' : 'error');
  }

  async function testIgnoredUser() {
    if (!statusCache?.session) return message('먼저 패스키로 로그인하세요.', 'error');
    const other = statusCache.session.userId === 'owner' ? 'tester' : 'owner';
    const result = await api(`/api/private?userId=${encodeURIComponent(other)}`);
    const returned = result.body?.user?.id;
    const ok = result.response.ok && returned === statusCache.session.userId;
    log(`다른 userId=${other}를 URL에 보냄 → HTTP ${result.response.status} · 실제 반환=${returned} · 세션 사용자만 반환`, ok ? 'success' : 'error');
    message(ok ? '다른 userId를 보내도 내 자료만 반환되었습니다.' : 'userId 무시 테스트가 예상과 다릅니다.', ok ? 'success' : 'error');
  }

  async function testBadSignature() {
    try {
      const account = statusCache?.session?.userId;
      if (!account) throw new Error('먼저 로그인하세요.');
      const assertion = await getAssertion(account);
      const signature = assertion.response.response.signature;
      assertion.response.response.signature = (signature[0] === 'A' ? 'B' : 'A') + signature.slice(1);
      const result = await api('/api/login/verify', { method: 'POST', body: JSON.stringify({ account, ...assertion }) });
      log(`서명 1글자 변조 후 로그인 검증 → HTTP ${result.response.status} · ${result.body.error || ''}`, result.response.status === 401 ? 'success' : 'error');
      message(`틀린 서명 결과: HTTP ${result.response.status}`, result.response.status === 401 ? 'success' : 'error');
    } catch (error) {
      log(`틀린 서명 테스트 중단 · ${error.message}`, 'error');
      message(error.message, 'error');
    }
  }

  async function testReplay() {
    const raw = sessionStorage.getItem('yerim-last-successful-auth');
    if (!raw) return message('이 브라우저 탭에서 먼저 정상 로그인 1회를 완료하세요.', 'error');
    const saved = JSON.parse(raw);
    const result = await api('/api/login/verify', { method: 'POST', body: JSON.stringify(saved) });
    log(`이미 성공에 사용한 로그인 응답 재전송 → HTTP ${result.response.status} · ${result.body.error || ''}`, result.response.status === 401 ? 'success' : 'error');
    message(`challenge 재사용 결과: HTTP ${result.response.status}`, result.response.status === 401 ? 'success' : 'error');
  }

  async function testDeletedPasskey() {
    const raw = sessionStorage.getItem('yerim-last-deleted-passkey');
    if (!raw) return message('먼저 패스키가 2개인 상태에서 하나를 삭제하세요.', 'error');
    const deleted = JSON.parse(raw);
    const account = statusCache?.session?.userId;
    if (!account || deleted.account !== account) return message('삭제를 수행한 같은 계정으로 로그인한 상태에서 확인하세요.', 'error');
    const start = await api('/api/login/options', { method: 'POST', body: JSON.stringify({ account }) });
    if (!start.response.ok) return message('삭제 credential 확인용 challenge 발급에 실패했습니다.', 'error');
    const result = await api('/api/login/verify', {
      method: 'POST',
      body: JSON.stringify({ account, challengeId: start.body.challengeId, response: { id: deleted.id } }),
    });
    log(`삭제한 credential ${preview(deleted.id)}로 로그인 요청 → HTTP ${result.response.status} · ${result.body.error || ''}`, result.response.status === 401 ? 'success' : 'error');
    message(`삭제한 패스키 서버 확인: HTTP ${result.response.status}`, result.response.status === 401 ? 'success' : 'error');
  }

  async function loadAudit() {
    const result = await api('/api/evidence/audit');
    if (!result.response.ok) {
      $('server-audit').textContent = `HTTP ${result.response.status} · 로그인 뒤 확인할 수 있습니다.`;
      return;
    }
    $('server-audit').textContent = JSON.stringify(result.body, null, 2);
    log(`서버 audit ${result.body.entries.length}건 불러옴 · 세션/토큰/challenge 원문 미표시`, 'success');
  }

  async function copyEvidence() {
    const text = evidence.map((e) => e.entry).join('\n');
    try {
      await navigator.clipboard.writeText(text);
      message('브라우저 확인 기록을 복사했습니다.', 'success');
    } catch {
      message('클립보드 권한이 없어 복사하지 못했습니다.', 'error');
    }
  }

  function bind() {
    document.querySelectorAll('.toggle').forEach((button) => {
      button.addEventListener('click', () => {
        const detail = document.getElementById(button.getAttribute('aria-controls'));
        if (!detail) return;
        const open = button.getAttribute('aria-expanded') === 'true';
        button.setAttribute('aria-expanded', String(!open));
        detail.hidden = open;
        if (button.firstChild) button.firstChild.textContent = open ? '자세히 보기 ' : '접기 ';
        const icon = button.querySelector('span');
        if (icon) icon.textContent = open ? '+' : '−';
      });
    });

    $('owner-register')?.addEventListener('click', () => registerPasskey('owner', $('owner-passkey-name').value.trim(), $('owner-storage-type').value));
    $('current-register')?.addEventListener('click', () => registerPasskey(statusCache?.session?.userId || 'owner', $('current-passkey-name').value.trim(), $('current-storage-type').value));
    $('tester-register')?.addEventListener('click', () => registerPasskey('tester', $('tester-passkey-name').value.trim(), $('tester-storage-type').value));
    $('login-passkey')?.addEventListener('click', () => login($('login-account')?.value || 'owner'));
    $('logout-passkey')?.addEventListener('click', logout);
    $('show-private-add')?.addEventListener('click', () => {
      $('private-add-form').hidden = false;
      $('private-new-title').focus();
    });
    $('cancel-private-add')?.addEventListener('click', () => {
      $('private-add-form').hidden = true;
      $('private-new-title').value = '';
      $('private-new-body').value = '';
    });
    $('save-private-item')?.addEventListener('click', addPrivateItem);
    $('reset-private-items')?.addEventListener('click', resetPrivateItems);
    $('test-unauth')?.addEventListener('click', testUnauth);
    $('test-cross-account')?.addEventListener('click', testCrossAccount);
    $('test-ignored-user')?.addEventListener('click', testIgnoredUser);
    $('test-bad-signature')?.addEventListener('click', testBadSignature);
    $('test-replay')?.addEventListener('click', testReplay);
    $('test-deleted-passkey')?.addEventListener('click', testDeletedPasskey);
    $('refresh-audit')?.addEventListener('click', loadAudit);
    $('copy-evidence')?.addEventListener('click', copyEvidence);
    $('clear-evidence')?.addEventListener('click', () => { evidence.length = 0; renderEvidence(); });
  }

  document.addEventListener('DOMContentLoaded', async () => {
    bind();
    renderEvidence();
    const supported = Boolean(window.PublicKeyCredential && navigator.credentials);
    const secureEnough = window.isSecureContext || location.hostname === 'localhost' || location.hostname === '127.0.0.1';
    $('webauthn-warning').hidden = supported && secureEnough;
    if (!supported) log('이 브라우저는 WebAuthn API를 지원하지 않습니다.', 'error');
    else if (!secureEnough) log('WebAuthn은 HTTPS 또는 localhost에서 실행해야 합니다.', 'error');
    await refreshStatus();
  });
})();
