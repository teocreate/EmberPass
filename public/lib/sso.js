/**
 * Single sign-on entry points shared by both apps. The provider redirects the whole
 * browser, so this is navigation, not fetch: the session cookie has to be set by the
 * callback before the app loads again.
 */

const SSO_ERRORS = {
  access_denied: 'вход отменён',
  expired: 'сессия входа истекла, попробуйте ещё раз',
  state_mismatch: 'сессия входа истекла, попробуйте ещё раз',
  email_conflict: 'этот email уже занят локальным аккаунтом — войдите по паролю',
  no_email: 'провайдер не передал email — проверьте настройки приложения',
  account_suspended: 'аккаунт заблокирован',
  provider_unreachable: 'сервер единого входа недоступен',
  provider_error: 'сервер единого входа отклонил запрос',
  invalid_signature: 'провайдер вернул токен с неверной подписью',
  invalid_token: 'провайдер вернул некорректный токен',
  issuer_mismatch: 'адрес провайдера не совпадает с настроенным',
  not_configured: 'единый вход не настроен',
};

/** Wires up the "sign in with ..." button, or hides it when the server has no provider. */
export function setupSso({ auth, next, elements }) {
  const { block, button, name, divider } = elements;
  const provider = auth?.oidc;

  if (!provider) {
    block.hidden = true;
    return;
  }
  name.textContent = provider.displayName;
  block.hidden = false;
  // With the password form switched off there is nothing to separate it from.
  divider.hidden = !auth.local;
  button.addEventListener('click', () => {
    window.location.href = `${provider.startUrl}?next=${encodeURIComponent(next)}`;
  });
}

/** Shows the reason a redirect back from the provider failed, then cleans the URL. */
export function showSsoError(errorNode) {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('sso_error');
  if (!code) return;
  errorNode.textContent = SSO_ERRORS[code] || `не удалось войти через единый вход (${code})`;
  errorNode.hidden = false;
  params.delete('sso_error');
  const query = params.toString();
  window.history.replaceState({}, '', window.location.pathname + (query ? `?${query}` : ''));
}

/** Follows the provider's logout URL when the server asks for it. */
export function finishLogout(result) {
  if (result?.redirectTo) {
    window.location.href = result.redirectTo;
    return true;
  }
  return false;
}
