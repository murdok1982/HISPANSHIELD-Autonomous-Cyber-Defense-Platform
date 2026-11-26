import { useEffect, useId, useState, type ReactNode } from "react";
import { AlertTriangle, Check, Copy, ShieldAlert } from "lucide-react";
import {
  Button,
  Field,
  Input,
  Modal,
  Textarea,
  useToast,
} from "../../ui";
import { isApiError } from "../../../lib/api";

/* -------------------------------------------------------------- clipboard */

export async function copyText(value: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return true;
    }
  } catch {
    /* fall through to the legacy path */
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

export function CopyButton({
  value,
  label,
  testId,
}: {
  value: string;
  label: string;
  testId?: string;
}) {
  const toast = useToast();
  const [copied, setCopied] = useState(false);
  return (
    <Button
      type="button"
      size="sm"
      variant="ghost"
      icon={copied ? Check : Copy}
      aria-label={label}
      data-testid={testId}
      onClick={() => {
        void copyText(value).then((ok) => {
          if (!ok) {
            toast.push("No se pudo copiar al portapapeles", "error");
            return;
          }
          setCopied(true);
          toast.push("Copiado al portapapeles", "success");
          window.setTimeout(() => setCopied(false), 1600);
        });
      }}
    />
  );
}

/* ----------------------------------------------------------- confirmation */

export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  description,
  warning,
  confirmLabel,
  cancelLabel,
  tone = "danger",
  busy = false,
  requireReason = false,
  reasonLabel,
  reasonHint,
  minReason = 3,
  testId,
  children,
}: {
  open: boolean;
  onClose: () => void;
  onConfirm: (reason: string) => void;
  title: string;
  description?: ReactNode;
  warning?: ReactNode;
  confirmLabel: string;
  cancelLabel: string;
  tone?: "danger" | "primary";
  busy?: boolean;
  requireReason?: boolean;
  reasonLabel?: string;
  reasonHint?: string;
  minReason?: number;
  testId?: string;
  children?: ReactNode;
}) {
  const [reason, setReason] = useState("");
  const reasonId = useId();

  useEffect(() => {
    if (open) setReason("");
  }, [open]);

  const reasonValid = !requireReason || reason.trim().length >= minReason;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      footer={
        <>
          <Button type="button" variant="ghost" onClick={onClose} disabled={busy}>
            {cancelLabel}
          </Button>
          <Button
            type="button"
            variant={tone === "danger" ? "danger" : "primary"}
            loading={busy}
            disabled={!reasonValid}
            onClick={() => onConfirm(reason.trim())}
            data-testid={testId ? `${testId}-confirm` : undefined}
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="stack">
        {description ? <div style={{ color: "var(--text-secondary)", fontSize: 12.5 }}>{description}</div> : null}
        {warning ? (
          <div className="notice notice-danger" role="alert">
            <ShieldAlert size={14} style={{ flex: "0 0 auto", marginTop: 1 }} />
            <span>{warning}</span>
          </div>
        ) : null}
        {children}
        {requireReason ? (
          <Field label={reasonLabel ?? "Motivo"} htmlFor={reasonId} hint={reasonHint} required>
            <Textarea
              id={reasonId}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              maxLength={1000}
              rows={3}
              aria-invalid={!reasonValid && reason.length > 0 ? true : undefined}
              data-testid={testId ? `${testId}-reason` : undefined}
            />
          </Field>
        ) : null}
      </div>
    </Modal>
  );
}

/* ----------------------------------------------------------------- secrets */

export function SecretOnce({
  label,
  value,
  warning,
  testId,
}: {
  label: string;
  value: string;
  warning: string;
  testId?: string;
}) {
  const id = useId();
  return (
    <div className="stack" data-testid={testId}>
      <div className="notice notice-warning">
        <AlertTriangle size={14} style={{ flex: "0 0 auto", marginTop: 1 }} />
        <span>{warning}</span>
      </div>
      <Field label={label} htmlFor={id}>
        <div className="row" style={{ gap: 6 }}>
          <Input id={id} readOnly value={value} className="mono" style={{ flex: 1 }} onFocus={(event) => event.currentTarget.select()} />
          <CopyButton value={value} label={`Copiar ${label.toLowerCase()}`} testId={testId ? `${testId}-copy` : undefined} />
        </div>
      </Field>
    </div>
  );
}

/* ------------------------------------------------------------------ JSON UI */

export type JsonRecordResult =
  | { ok: true; value: Record<string, unknown> }
  | { ok: false; error: string };

export function parseJsonRecord(text: string, emptyValue: Record<string, unknown> = {}): JsonRecordResult {
  const trimmed = text.trim();
  if (!trimmed) return { ok: true, value: emptyValue };
  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { ok: false, error: "Debe ser un objeto JSON" };
    }
    return { ok: true, value: parsed as Record<string, unknown> };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? `JSON inválido: ${error.message}` : "JSON inválido" };
  }
}

export function JsonEditor({
  id,
  label,
  value,
  onChange,
  hint,
  error,
  rows = 7,
  testId,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  hint?: string;
  error?: string;
  rows?: number;
  testId?: string;
}) {
  return (
    <Field label={label} htmlFor={id} hint={hint} error={error}>
      <Textarea
        id={id}
        className="mono"
        rows={rows}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        spellCheck={false}
        aria-invalid={error ? true : undefined}
        data-testid={testId}
      />
    </Field>
  );
}

/* -------------------------------------------------------------- metadata UI */

export function MetaRows({ items }: { items: { label: string; value: ReactNode }[] }) {
  return (
    <div className="metric-list">
      {items.map((item) => (
        <div className="metric-row" key={item.label}>
          <span className="metric-label">{item.label}</span>
          <span className="metric-value" style={{ textAlign: "right" }}>
            {item.value}
          </span>
        </div>
      ))}
    </div>
  );
}

export function PreBlock({ value, label }: { value: unknown; label?: string }) {
  return (
    <div>
      {label ? <div className="section-label">{label}</div> : null}
      <pre className="code-block">{JSON.stringify(value, null, 2)}</pre>
    </div>
  );
}

/* ---------------------------------------------------------------- helpers */

export function toIso(value: string): string | null {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

export function localDateTimeInput(date: Date): string {
  const pad = (part: number) => String(part).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function daysAgoInput(days: number): string {
  const date = new Date();
  date.setDate(date.getDate() - days);
  return localDateTimeInput(date);
}

export function slugify(value: string): string {
  return value
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}

export function hashPrefix(hash: string | null | undefined, length = 12): string {
  if (!hash) return "—";
  return hash.slice(0, length);
}

export function splitTags(value: string): string[] {
  return value
    .split(",")
    .map((tag) => tag.trim().toLowerCase())
    .filter((tag, index, list) => tag.length > 0 && list.indexOf(tag) === index);
}

export function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value.trim());
}

export function invocationId(id: string | null | undefined): string {
  return id ? id.slice(0, 8) : "—";
}

/**
 * Maps ApiError.details ({field,message}) to the `Field` error prop so server
 * validation is shown inline instead of only in a toast.
 */
export function apiFieldErrors(error: unknown): Record<string, string> {
  if (!isApiError(error)) return {};
  const result: Record<string, string> = {};
  for (const detail of error.details) {
    if (!detail.field) continue;
    result[detail.field] = result[detail.field] ? `${result[detail.field]} · ${detail.message}` : detail.message;
  }
  return result;
}

export function errorCode(error: unknown): string | null {
  return isApiError(error) ? error.code : null;
}
