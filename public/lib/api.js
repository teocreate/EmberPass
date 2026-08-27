/** Small fetch wrapper: JSON in, JSON out, errors as exceptions with a code. */
export class ApiError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.status = status;
    this.code = code;
  }
}

async function request(method, path, body) {
  let response;
  try {
    response = await fetch(path, {
      method,
      headers: body === undefined ? {} : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
    });
  } catch (error) {
    throw new ApiError(0, 'network_error', 'нет соединения с сервером');
  }
  const text = await response.text();
  const payload = text ? JSON.parse(text) : {};
  if (!response.ok) throw new ApiError(response.status, payload.error || 'error', payload.message || 'ошибка запроса');
  return payload;
}

export const api = {
  me: () => request('GET', '/api/auth/me'),
  login: (email, password) => request('POST', '/api/auth/login', { email, password }),
  register: (data) => request('POST', '/api/auth/register', data),
  logout: () => request('POST', '/api/auth/logout', {}),
  checkEmail: (email) => request('POST', '/api/auth/check-email', { email }),
  pass: () => request('GET', '/api/pass'),
  passToken: () => request('POST', '/api/pass/token', {}),
  history: () => request('GET', '/api/pass/history'),
  verifyKey: () => request('GET', '/api/verify/key'),
  verify: (token, gate, offline) => request('POST', '/api/staff/verify', { token, gate, offline }),
  recentScans: (limit = 50) => request('GET', `/api/staff/scans?limit=${limit}`),
};
