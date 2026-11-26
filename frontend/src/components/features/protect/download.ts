import { getActiveOrg, getCookie } from "../../../lib/api";

/**
 * Download a binary response produced by a POST endpoint.
 *
 * `api.downloadFile` only issues GET requests, while the forensics case export
 * is a POST that mutates the audit chain (it records the export). This helper
 * mirrors the API client headers (organization + double-submit CSRF) without
 * duplicating the error envelope parsing.
 */
export async function downloadPostFile(path: string, filename: string): Promise<void> {
  const headers = new Headers({ Accept: "application/octet-stream" });
  const org = getActiveOrg();
  if (org) headers.set("X-Organization-Id", org);
  const csrf = getCookie("hs_csrf");
  if (csrf) headers.set("X-CSRF-Token", csrf);

  const response = await fetch(`/api/v1${path}`, {
    method: "POST",
    headers,
    credentials: "same-origin",
    cache: "no-store",
  });
  if (!response.ok) {
    let message = `Request failed with status ${response.status}`;
    try {
      const body = (await response.json()) as { error?: { message?: string } };
      if (body.error?.message) message = body.error.message;
    } catch {
      /* non-JSON body: keep the status-derived message */
    }
    throw new Error(message);
  }
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
