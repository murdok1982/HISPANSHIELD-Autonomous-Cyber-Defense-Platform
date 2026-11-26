/**
 * Typed fetch client for the HISPANSHIELD API.
 *
 * - Sends the active organization header on every request.
 * - Adds the double-submit CSRF header for cookie-authenticated mutations.
 * - Normalizes the API error envelope and emits a global unauthorized event.
 * - Never caches API responses (the server also sets Cache-Control: no-store).
 */

export interface ApiErrorDetail {
  field: string;
  message: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: ApiErrorDetail[];
  readonly requestId?: string;

  constructor(status: number, code: string, message: string, details: ApiErrorDetail[] = [], requestId?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
    this.requestId = requestId;
  }
}

export const ORG_STORAGE_KEY = "hs.activeOrg";

export function getCookie(name: string): string | null {
  const prefix = `${name}=`;
  for (const part of document.cookie.split(";")) {
    const value = part.trim();
    if (value.startsWith(prefix)) return decodeURIComponent(value.slice(prefix.length));
  }
  return null;
}

export function getActiveOrg(): string | null {
  try {
    return window.localStorage.getItem(ORG_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function setActiveOrg(orgId: string | null): void {
  try {
    if (orgId) window.localStorage.setItem(ORG_STORAGE_KEY, orgId);
    else window.localStorage.removeItem(ORG_STORAGE_KEY);
  } catch {
    /* storage can be unavailable in hardened browsers; session remains usable */
  }
}

type RequestOptions = {
  method?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
  body?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  timeoutMs?: number;
};

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

function buildHeaders(options: RequestOptions): Headers {
  const headers = new Headers(options.headers);
  headers.set("Accept", "application/json");
  const org = getActiveOrg();
  if (org) headers.set("X-Organization-Id", org);
  const method = options.method ?? "GET";
  if (!SAFE_METHODS.has(method)) {
    const csrf = getCookie("hs_csrf");
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  if (options.body !== undefined && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  return headers;
}

async function parseError(response: Response): Promise<ApiError> {
  let code = "http_error";
  let message = `Request failed with status ${response.status}`;
  let details: ApiErrorDetail[] = [];
  let requestId: string | undefined = response.headers.get("X-Request-ID") ?? undefined;
  try {
    const body = (await response.json()) as {
      error?: { code?: string; message?: string; details?: ApiErrorDetail[]; request_id?: string };
    };
    if (body.error) {
      code = body.error.code ?? code;
      message = body.error.message ?? message;
      details = body.error.details ?? [];
      requestId = body.error.request_id ?? requestId;
    }
  } catch {
    /* non-JSON error body: keep the status-derived message */
  }
  return new ApiError(response.status, code, message, details, requestId);
}

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), options.timeoutMs ?? 30_000);
  if (options.signal) {
    options.signal.addEventListener("abort", () => controller.abort(), { once: true });
  }
  let response: Response;
  try {
    response = await fetch(`/api/v1${path}`, {
      method: options.method ?? "GET",
      headers: buildHeaders(options),
      credentials: "same-origin",
      cache: "no-store",
      body:
        options.body === undefined
          ? undefined
          : options.body instanceof FormData
            ? options.body
            : JSON.stringify(options.body),
      signal: controller.signal,
    });
  } catch (error) {
    window.clearTimeout(timeout);
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new ApiError(0, "timeout", "The request exceeded the client timeout");
    }
    throw new ApiError(0, "network_error", "Unable to reach the HISPANSHIELD API");
  }
  window.clearTimeout(timeout);

  if (response.status === 401) {
    window.dispatchEvent(new CustomEvent("hs:unauthorized"));
    throw await parseError(response);
  }
  if (!response.ok) {
    throw await parseError(response);
  }
  if (response.status === 204) return undefined as T;
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    return (await response.text()) as unknown as T;
  }
  return (await response.json()) as T;
}

export type Query = Record<string, string | number | boolean | undefined | null>;

export function withQuery(path: string, query?: Query): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

export const api = {
  get: <T>(path: string, query?: Query, timeoutMs?: number) =>
    apiRequest<T>(withQuery(path, query), { timeoutMs }),
  post: <T>(path: string, body?: unknown) => apiRequest<T>(path, { method: "POST", body }),
  patch: <T>(path: string, body?: unknown) => apiRequest<T>(path, { method: "PATCH", body }),
  put: <T>(path: string, body?: unknown) => apiRequest<T>(path, { method: "PUT", body }),
  delete: <T>(path: string, body?: unknown) => apiRequest<T>(path, { method: "DELETE", body }),
  upload: <T>(path: string, form: FormData) => apiRequest<T>(path, { method: "POST", body: form, timeoutMs: 120_000 }),
};

export async function downloadFile(path: string, filename: string): Promise<void> {
  const response = await fetch(`/api/v1${path}`, {
    headers: buildHeaders({ method: "GET" }),
    credentials: "same-origin",
  });
  if (!response.ok) throw await parseError(response);
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export interface PageMeta {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  has_next: boolean;
}

export interface Page<T> {
  items: T[];
  meta: PageMeta;
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return "Unexpected error";
}
