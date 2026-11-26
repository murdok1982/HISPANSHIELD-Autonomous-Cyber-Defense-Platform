/**
 * Shared building blocks for the detection & exposure pages
 * (Monitoring, Assets, Asset detail, Attack surface, Vulnerabilities, Threat intel).
 *
 * Only page-scoped helpers live here: no global navigation or design-token
 * mutations. Everything is built on the existing UI primitives.
 */
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Check, Copy } from "lucide-react";
import clsx from "clsx";
import { isApiError } from "../../../lib/api";
import { useI18n } from "../../../lib/i18n";
import { Badge, Button, Modal, useToast } from "../../ui";

/* -------------------------------------------------------------------- utils */

/** Debounce a rapidly changing value (search inputs) to protect the API. */
export function useDebouncedValue<T>(value: T, delay = 350): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delay);
    return () => window.clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}

/** Plain-text copy with a legacy fallback for non-secure contexts. */
export async function copyText(value: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return true;
    }
  } catch {
    /* fall back to the selection based copy below */
  }
  try {
    const area = document.createElement("textarea");
    area.value = value;
    area.setAttribute("readonly", "true");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    const copied = document.execCommand("copy");
    area.remove();
    return copied;
  } catch {
    return false;
  }
}

/** Split a comma/newline separated input into a de-duplicated list. */
export function parseCommaList(raw: string): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const token of raw.split(/[,\n]/)) {
    const value = token.trim();
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(value);
  }
  return result;
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPV6 = /^[0-9A-Fa-f:]+$/;

/** Permissive client-side IP check; the server remains authoritative. */
export function isIpAddress(value: string): boolean {
  const token = value.trim();
  if (!token || token.length > 64) return false;
  const v4 = IPV4.exec(token);
  if (v4) {
    return v4.slice(1).every((part) => Number(part) >= 0 && Number(part) <= 255);
  }
  if (!token.includes(":") || !IPV6.test(token)) return false;
  const doubleColon = token.split("::").length - 1;
  return doubleColon <= 1;
}

/** Map a normalized API error to `{field: message}` for inline form errors. */
export function fieldErrors(error: unknown): Record<string, string> {
  const map: Record<string, string> = {};
  if (!isApiError(error)) return map;
  for (const detail of error.details) {
    if (detail.field && !map[detail.field]) map[detail.field] = detail.message;
  }
  return map;
}

/** ISO date stamp used for exported file names. */
export function csvStamp(date = new Date()): string {
  return date.toISOString().slice(0, 10);
}

export const SEVERITY_LEVELS = [
  { id: 5, value: "critical" },
  { id: 4, value: "high" },
  { id: 3, value: "medium" },
  { id: 2, value: "low" },
  { id: 1, value: "info" },
] as const;

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export function severityFromId(id: number | null | undefined): string {
  const match = SEVERITY_LEVELS.find((level) => level.id === id);
  return match?.value ?? "info";
}

export function severityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "var(--critical)";
    case "high":
      return "var(--danger)";
    case "medium":
      return "var(--warning)";
    case "low":
      return "var(--accent)";
    default:
      return "var(--muted)";
  }
}

/** Set toggling helper for expandable rows and selection lists. */
export function useToggleSet(initial: string[] = []) {
  const [values, setValues] = useState<Set<string>>(() => new Set(initial));
  const toggle = useCallback((id: string) => {
    setValues((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);
  const clear = useCallback(() => setValues(new Set()), []);
  return { values, toggle, clear, has: (id: string) => values.has(id) };
}

/* ---------------------------------------------------------------- components */

export function FilterBar({ children, ariaLabel }: { children: ReactNode; ariaLabel: string }) {
  return (
    <div className="filters-bar" role="group" aria-label={ariaLabel}>
      {children}
    </div>
  );
}

export function CopyButton({ text, label }: { text: string; label?: string }) {
  const { t } = useI18n();
  const { push } = useToast();
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 1800);
    return () => window.clearTimeout(timer);
  }, [copied]);

  const ariaLabel = label ?? t("common.copy");
  return (
    <Button
      type="button"
      size="sm"
      variant="ghost"
      icon={copied ? Check : Copy}
      aria-label={ariaLabel}
      onClick={() => {
        void copyText(text).then((ok) => {
          if (ok) {
            setCopied(true);
          } else {
            push(t("errors.unexpected"), "error");
          }
        });
      }}
    >
      {copied ? t("common.copied") : ariaLabel}
    </Button>
  );
}

export function JsonBlock({ value, ariaLabel }: { value: unknown; ariaLabel?: string }) {
  return (
    <pre className="code-block" aria-label={ariaLabel}>
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

/** Five-segment criticality indicator (1-5) with an accessible label. */
export function CriticalityMeter({ value }: { value: number }) {
  const level = Math.max(0, Math.min(5, Math.round(value)));
  const color =
    level >= 5
      ? "var(--critical)"
      : level === 4
        ? "var(--danger)"
        : level === 3
          ? "var(--warning)"
          : level >= 1
            ? "var(--accent)"
            : "var(--dim)";
  return (
    <span className="row" style={{ gap: 2 }} role="img" aria-label={`${level}/5`} title={`${level}/5`}>
      {[1, 2, 3, 4, 5].map((segment) => (
        <span
          key={segment}
          aria-hidden="true"
          style={{
            width: 5,
            height: 12,
            borderRadius: 1,
            background: segment <= level ? color : "var(--border)",
          }}
        />
      ))}
    </span>
  );
}

export function DemoTag({ label }: { label?: string }) {
  const { t } = useI18n();
  return <Badge tone="amber">{label ?? t("common.demoData")}</Badge>;
}

export function MetaRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="metric-row">
      <span className="metric-label">{label}</span>
      <span className="metric-value" style={{ textAlign: "right", wordBreak: "break-word" }}>
        {children}
      </span>
    </div>
  );
}

export function TagList({ tags, emptyLabel }: { tags: string[]; emptyLabel: string }) {
  if (!tags.length) return <span className="dim" style={{ fontSize: 11.5 }}>{emptyLabel}</span>;
  return (
    <div className="chip-row">
      {tags.map((tag) => (
        <span className="tag" key={tag}>
          {tag}
        </span>
      ))}
    </div>
  );
}

/** Explicit confirmation dialog for destructive or high-blast-radius actions. */
export function ConfirmModal({
  open,
  title,
  description,
  confirmLabel,
  onConfirm,
  onClose,
  loading = false,
  danger = false,
  children,
}: {
  open: boolean;
  title: string;
  description?: string;
  confirmLabel: string;
  onConfirm: () => void;
  onClose: () => void;
  loading?: boolean;
  danger?: boolean;
  children?: ReactNode;
}) {
  const { t } = useI18n();
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={loading}>
            {t("common.cancel")}
          </Button>
          <Button variant={danger ? "danger" : "primary"} onClick={onConfirm} loading={loading} data-testid="confirm-action">
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="stack">
        {description ? <p style={{ fontSize: 12.5, color: "var(--muted)" }}>{description}</p> : null}
        {children}
      </div>
    </Modal>
  );
}

export function FieldGroup({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={clsx("form-grid", className)}>{children}</div>;
}

/** Render the first N server-side import errors without flooding the modal. */
export function ImportErrors({
  errors,
  emptyLabel,
}: {
  errors: { row?: number | null; field?: string | null; asset_key?: string | null; identifier?: string | null; message: string }[];
  emptyLabel: string;
}) {
  if (!errors.length) return <span className="dim" style={{ fontSize: 11.5 }}>{emptyLabel}</span>;
  return (
    <div className="table-wrap">
      <table className="data">
        <thead>
          <tr>
            <th style={{ width: 64 }}>#</th>
            <th>Ref</th>
            <th>Error</th>
          </tr>
        </thead>
        <tbody>
          {errors.slice(0, 25).map((error, index) => (
            <tr key={`${error.row ?? index}-${index}`}>
              <td className="mono">{error.row ?? index + 1}</td>
              <td className="mono" style={{ fontSize: 10.5 }}>
                {error.asset_key ?? error.identifier ?? error.field ?? "—"}
              </td>
              <td>{error.message}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
