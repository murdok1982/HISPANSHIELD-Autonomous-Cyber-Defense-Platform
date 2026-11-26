import {
  createContext,
  createElement,
  useCallback,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from "react";
import { createPortal } from "react-dom";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Inbox,
  Loader2,
  Search,
  ShieldAlert,
  X,
  type LucideIcon,
} from "lucide-react";
import clsx from "clsx";
import { Link } from "react-router-dom";
import { useI18n, severityKey } from "../../lib/i18n";
import { formatNumber, humanize } from "../../lib/format";

/* ------------------------------------------------------------------ buttons */

type ButtonVariant = "default" | "primary" | "ghost" | "danger";
type ButtonSize = "sm" | "md" | "lg";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  icon?: LucideIcon;
}

export function Button({
  variant = "default",
  size = "md",
  loading = false,
  icon: Icon,
  className,
  children,
  disabled,
  ...rest
}: ButtonProps) {
  return (
    <button
      className={clsx(
        "btn",
        variant === "primary" && "btn-primary",
        variant === "ghost" && "btn-ghost",
        variant === "danger" && "btn-danger",
        size === "sm" && "btn-sm",
        size === "lg" && "btn-lg",
        !children && "btn-icon",
        className,
      )}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      {...rest}
    >
      {loading ? <Loader2 size={14} className="spin" aria-hidden="true" /> : Icon ? <Icon size={14} aria-hidden="true" /> : null}
      {children}
    </button>
  );
}

export function LinkButton({
  to,
  variant = "default",
  size = "md",
  icon: Icon,
  children,
}: {
  to: string;
  variant?: ButtonVariant;
  size?: ButtonSize;
  icon?: LucideIcon;
  children: ReactNode;
}) {
  return (
    <Link
      to={to}
      className={clsx(
        "btn",
        variant === "primary" && "btn-primary",
        variant === "ghost" && "btn-ghost",
        variant === "danger" && "btn-danger",
        size === "sm" && "btn-sm",
        size === "lg" && "btn-lg",
      )}
    >
      {Icon ? <Icon size={14} aria-hidden="true" /> : null}
      {children}
    </Link>
  );
}

/* -------------------------------------------------------------------- badges */

type BadgeTone = "neutral" | "accent" | "success" | "warning" | "danger" | "critical" | "amber";

export function Badge({ tone = "neutral", children, className }: { tone?: BadgeTone; children: ReactNode; className?: string }) {
  return <span className={clsx("badge", `badge-${tone}`, className)}>{children}</span>;
}

const SEVERITY_TONE: Record<string, BadgeTone> = {
  critical: "critical",
  high: "danger",
  medium: "warning",
  low: "accent",
  info: "neutral",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const { t } = useI18n();
  const normalized = severity.toLowerCase();
  return <Badge tone={SEVERITY_TONE[normalized] ?? "neutral"}>{t(severityKey(normalized))}</Badge>;
}

const STATUS_TONE: Record<string, BadgeTone> = {
  new: "accent",
  triaged: "accent",
  investigating: "amber",
  contained: "warning",
  eradicated: "warning",
  recovered: "success",
  closed: "neutral",
  resolved: "success",
  open: "danger",
  success: "success",
  ok: "success",
  available: "success",
  failure: "danger",
  unavailable: "danger",
  pending: "warning",
  pending_approval: "amber",
  waiting_approval: "amber",
  approved: "success",
  rejected: "danger",
  executed: "success",
  failed: "danger",
  verified: "success",
  healthy: "success",
  degraded: "warning",
  unhealthy: "danger",
  unconfigured: "neutral",
  disabled: "neutral",
  active: "success",
  suspended: "warning",
  running: "accent",
  completed: "success",
  queued: "neutral",
  simulated: "accent",
  dry_run: "accent",
  mitigated: "success",
  accepted: "neutral",
  false_positive: "neutral",
  compliant: "success",
  partial: "warning",
  non_compliant: "danger",
  not_assessed: "neutral",
  not_applicable: "neutral",
};

export function StatusBadge({ status, label }: { status: string; label?: string }) {
  const { t } = useI18n();
  const key = `status.${status.toLowerCase()}`;
  const translated = t(key);
  const text = label ?? (translated === key ? humanize(status) : translated);
  return <Badge tone={STATUS_TONE[status.toLowerCase()] ?? "neutral"}>{text}</Badge>;
}

export function SeverityDot({ severity }: { severity: string }) {
  return <span className={clsx("sev", `sev-${severity.toLowerCase()}`)}>{severity}</span>;
}

/* --------------------------------------------------------------------- cards */

export function Card({
  title,
  subtitle,
  actions,
  children,
  className,
  bodyClassName,
  footer,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  footer?: ReactNode;
}) {
  return (
    <section className={clsx("card", className)}>
      {(title || actions) && (
        <header className="card-head">
          {title ? <h2>{title}</h2> : null}
          {subtitle ? <span className="card-sub">{subtitle}</span> : null}
          {actions ? <div className="card-head-actions">{actions}</div> : null}
        </header>
      )}
      <div className={clsx(bodyClassName ?? "card-body")}>{children}</div>
      {footer ? <footer className="card-footer">{footer}</footer> : null}
    </section>
  );
}

export function Kpi({
  label,
  value,
  suffix,
  icon: Icon,
  tone = "accent",
  footer,
}: {
  label: string;
  value: ReactNode;
  suffix?: string;
  icon: LucideIcon;
  tone?: "accent" | "danger" | "warning" | "success" | "neutral";
  footer?: ReactNode;
}) {
  return (
    <div className="card kpi animate-in">
      <div className="kpi-label">
        <Icon size={13} style={{ color: `var(--${tone === "neutral" ? "muted" : tone})` }} aria-hidden="true" />
        {label}
      </div>
      <div className={clsx("kpi-value", `kpi-${tone}`)}>
        {value}
        {suffix ? <small>{suffix}</small> : null}
      </div>
      {footer ? <div className="kpi-foot">{footer}</div> : null}
    </div>
  );
}

export function PageHeader({
  eyebrow,
  title,
  subtitle,
  actions,
}: {
  eyebrow?: string;
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="page-head">
      <div>
        {eyebrow ? <div className="eyebrow">{eyebrow}</div> : null}
        <h1>{title}</h1>
        {subtitle ? <p className="page-sub">{subtitle}</p> : null}
      </div>
      {actions ? <div className="page-head-actions">{actions}</div> : null}
    </div>
  );
}

/* -------------------------------------------------------------------- states */

export function Skeleton({ className, style }: { className?: string; style?: React.CSSProperties }) {
  return <div className={clsx("skeleton", className)} style={style} aria-hidden="true" />;
}

export function PageSkeleton() {
  return (
    <div aria-busy="true" aria-label="Loading">
      <Skeleton className="skeleton-title" style={{ width: "28%", height: 24, marginBottom: 20 }} />
      <div className="kpi-grid" style={{ marginBottom: 12 }}>
        {[0, 1, 2, 3].map((item) => (
          <Skeleton key={item} className="skeleton-card" />
        ))}
      </div>
      <div className="split-main">
        <div className="card card-pad">
          <Skeleton className="skeleton-chart" />
        </div>
        <div className="card card-pad">
          <Skeleton className="skeleton-row" />
          <Skeleton className="skeleton-row" />
          <Skeleton className="skeleton-row" />
          <Skeleton className="skeleton-row" />
        </div>
      </div>
    </div>
  );
}

export function TableSkeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div style={{ padding: 12 }} aria-busy="true">
      {Array.from({ length: rows }).map((_, index) => (
        <Skeleton key={index} className="skeleton-row" />
      ))}
    </div>
  );
}

export function EmptyState({
  icon: Icon = Inbox,
  title,
  description,
  action,
}: {
  icon?: LucideIcon;
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <div className="empty-icon">
        <Icon size={22} aria-hidden="true" />
      </div>
      <h3>{title}</h3>
      {description ? <p>{description}</p> : null}
      {action ? <div style={{ marginTop: 8 }}>{action}</div> : null}
    </div>
  );
}

export function ErrorBanner({
  title,
  message,
  onRetry,
  compact,
}: {
  title?: string;
  message: string;
  onRetry?: () => void;
  compact?: boolean;
}) {
  const { t } = useI18n();
  return (
    <div className="error-banner" role="alert" style={compact ? { padding: "8px 10px" } : undefined}>
      <AlertTriangle size={16} aria-hidden="true" style={{ flex: "0 0 auto", color: "var(--danger)", marginTop: 1 }} />
      <div>
        <strong>{title ?? t("errors.loadFailed")}</strong>
        <div style={{ marginTop: 2 }}>{message}</div>
      </div>
      {onRetry ? (
        <div className="error-actions">
          <Button size="sm" onClick={onRetry}>
            {t("common.retry")}
          </Button>
        </div>
      ) : null}
    </div>
  );
}

export function LoadingBlock({ label }: { label?: string }) {
  return (
    <div className="empty-state" aria-busy="true">
      <Loader2 size={20} className="spin" style={{ color: "var(--accent)" }} aria-hidden="true" />
      <p>{label ?? "Cargando…"}</p>
    </div>
  );
}

/* --------------------------------------------------------------------- forms */

export function Field({
  label,
  hint,
  error,
  required,
  children,
  htmlFor,
}: {
  label: string;
  hint?: string;
  error?: string;
  required?: boolean;
  children: ReactNode;
  htmlFor?: string;
}) {
  return (
    <div className="field">
      <label htmlFor={htmlFor}>
        {label}
        {required ? <span style={{ color: "var(--danger)", marginLeft: 3 }}>*</span> : null}
      </label>
      {children}
      {hint && !error ? <span className="hint">{hint}</span> : null}
      {error ? <span className="field-error" role="alert">{error}</span> : null}
    </div>
  );
}

export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={clsx("input", className)} {...rest} />;
}

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={clsx("select", className)} {...rest}>
      {children}
    </select>
  );
}

export function Textarea({ className, ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={clsx("textarea", className)} {...rest} />;
}

export function SearchInput({
  value,
  onChange,
  placeholder,
  ariaLabel,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  ariaLabel?: string;
}) {
  return (
    <div className="search-input">
      <Search size={14} aria-hidden="true" />
      <input
        className="input"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        aria-label={ariaLabel ?? placeholder ?? "Search"}
        type="search"
      />
    </div>
  );
}

/* ---------------------------------------------------------------------- tabs */

export function Tabs<T extends string>({
  items,
  value,
  onChange,
  ariaLabel,
}: {
  items: { key: T; label: string; count?: number }[];
  value: T;
  onChange: (value: T) => void;
  ariaLabel?: string;
}) {
  return (
    <div className="tabs" role="tablist" aria-label={ariaLabel}>
      {items.map((item) => (
        <button
          key={item.key}
          type="button"
          role="tab"
          aria-selected={value === item.key}
          className={clsx("tab", value === item.key && "active")}
          onClick={() => onChange(item.key)}
        >
          {item.label}
          {item.count !== undefined ? <span className="mono" style={{ marginLeft: 6, color: "var(--dim)" }}>{formatNumber(item.count)}</span> : null}
        </button>
      ))}
    </div>
  );
}

/* -------------------------------------------------------------------- modal */

export function Modal({
  open,
  onClose,
  title,
  children,
  footer,
  size = "md",
  labelledBy,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  footer?: ReactNode;
  size?: "md" | "lg";
  labelledBy?: string;
}) {
  const titleId = useId();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
      if (event.key === "Tab" && ref.current) {
        const focusable = ref.current.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        );
        if (!focusable.length) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    const previous = document.activeElement as HTMLElement | null;
    window.setTimeout(() => ref.current?.querySelector<HTMLElement>("input, button, select, textarea")?.focus(), 30);
    return () => {
      document.removeEventListener("keydown", onKey);
      previous?.focus();
    };
  }, [open, onClose]);

  if (!open) return null;
  return createPortal(
    <div className="overlay" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <div
        className={clsx("modal", size === "lg" && "modal-lg")}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy ?? titleId}
        ref={ref}
      >
        <div className="modal-head">
          <h2 id={titleId}>{title}</h2>
          <button type="button" className="icon-btn" style={{ marginLeft: "auto" }} onClick={onClose} aria-label="Close">
            <X size={16} />
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer ? <div className="modal-foot">{footer}</div> : null}
      </div>
    </div>,
    document.body,
  );
}

/* -------------------------------------------------------------------- tables */

export interface Column<T> {
  key: string;
  header: ReactNode;
  render: (row: T) => ReactNode;
  width?: string;
  align?: "left" | "right" | "center";
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  loading,
  empty,
  error,
}: {
  columns: Column<T>[];
  rows: T[] | undefined;
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  loading?: boolean;
  empty?: ReactNode;
  error?: ReactNode;
}) {
  if (loading) return <TableSkeleton />;
  if (error) return <div style={{ padding: 16 }}>{error}</div>;
  if (!rows || rows.length === 0) return <div className="table-empty">{empty ?? <EmptyState title="Sin datos" />}</div>;
  return (
    <div className="table-wrap">
      <table className={clsx("data", onRowClick && "table-clickable")}>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key} style={{ width: column.width, textAlign: column.align ?? "left" }}>
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={rowKey(row)}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              tabIndex={onRowClick ? 0 : undefined}
              onKeyDown={
                onRowClick
                  ? (event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        onRowClick(row);
                      }
                    }
                  : undefined
              }
            >
              {columns.map((column) => (
                <td key={column.key} style={{ textAlign: column.align ?? "left" }}>
                  {column.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Pagination({
  meta,
  onPage,
}: {
  meta: { page: number; pages: number; total: number; page_size: number } | undefined;
  onPage: (page: number) => void;
}) {
  const { t } = useI18n();
  if (!meta) return null;
  const from = meta.total === 0 ? 0 : (meta.page - 1) * meta.page_size + 1;
  const to = Math.min(meta.total, meta.page * meta.page_size);
  return (
    <div className="pagination">
      <span>{t("common.showing", { from, to, total: formatNumber(meta.total) })}</span>
      <Button size="sm" variant="ghost" icon={ChevronLeft} disabled={meta.page <= 1} onClick={() => onPage(meta.page - 1)} aria-label={t("common.previous")} />
      <span className="mono">{t("common.page", { page: meta.page, pages: Math.max(1, meta.pages) })}</span>
      <Button
        size="sm"
        variant="ghost"
        icon={ChevronRight}
        disabled={meta.page >= meta.pages}
        onClick={() => onPage(meta.page + 1)}
        aria-label={t("common.next")}
      />
    </div>
  );
}

/* -------------------------------------------------------------------- toasts */

interface Toast {
  id: number;
  tone: "info" | "success" | "error";
  message: string;
}

interface ToastContextValue {
  push: (message: string, tone?: Toast["tone"]) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((message: string, tone: Toast["tone"] = "info") => {
    const id = Date.now() + Math.random();
    setToasts((current) => [...current, { id, tone, message }]);
    window.setTimeout(() => setToasts((current) => current.filter((toast) => toast.id !== id)), 4800);
  }, []);
  const value = useMemo(() => ({ push }), [push]);
  return createElement(
    ToastContext.Provider,
    { value },
    children,
    createPortal(
      <div className="toast-stack" role="status" aria-live="polite">
        {toasts.map((toast) => (
          <div key={toast.id} className={clsx("toast", toast.tone)}>
            <div className="row" style={{ gap: 8 }}>
              {toast.tone === "success" ? <CheckCircle2 size={14} style={{ color: "var(--success)" }} /> : null}
              {toast.tone === "error" ? <ShieldAlert size={14} style={{ color: "var(--danger)" }} /> : null}
              <span>{toast.message}</span>
            </div>
          </div>
        ))}
      </div>,
      document.body,
    ),
  );
}

export function useToast(): ToastContextValue {
  const context = useContext(ToastContext);
  if (!context) throw new Error("useToast must be used inside ToastProvider");
  return context;
}

/* -------------------------------------------------------------------- charts */

export function ScoreRing({
  score,
  size = 132,
  label,
  tone,
}: {
  score: number;
  size?: number;
  label?: string;
  tone?: string;
}) {
  const radius = (size - 16) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, score));
  const color = tone ?? (clamped >= 75 ? "var(--critical)" : clamped >= 50 ? "var(--danger)" : clamped >= 25 ? "var(--warning)" : "var(--success)");
  return (
    <div style={{ position: "relative", width: size, height: size, flex: "0 0 auto" }}>
      <svg width={size} height={size} role="img" aria-label={`${label ?? "Score"}: ${clamped}`}>
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="var(--border)" strokeWidth={8} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={8}
          strokeLinecap="round"
          strokeDasharray={`${(clamped / 100) * circumference} ${circumference}`}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: "stroke-dasharray 700ms ease" }}
        />
      </svg>
      <div
        style={{
          position: "absolute",
          inset: 0,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <span style={{ fontFamily: "var(--font-display)", fontSize: size / 4.2, fontWeight: 600 }}>{Math.round(clamped)}</span>
        {label ? <span style={{ fontSize: 9, letterSpacing: "0.12em", textTransform: "uppercase", color: "var(--muted)", maxWidth: size * 0.82, lineHeight: 1.3 }}>{label}</span> : null}
      </div>
    </div>
  );
}

export interface SeriesPoint {
  timestamp: string;
  value: number;
}

export function AreaChart({ data, height = 180, color = "var(--accent)" }: { data: SeriesPoint[]; height?: number; color?: string }) {
  const width = 640;
  const pad = 22;
  if (!data.length) return <div className="empty-state" style={{ padding: 24, fontSize: 12 }}>Sin datos</div>;
  const max = Math.max(...data.map((point) => point.value), 1);
  const step = data.length > 1 ? (width - pad * 2) / (data.length - 1) : 0;
  const points = data.map((point, index) => {
    const x = pad + index * step;
    const y = height - pad - (point.value / max) * (height - pad * 2);
    return [x, y] as const;
  });
  const line = points.map(([x, y], index) => `${index === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const area = `${line} L${points[points.length - 1][0].toFixed(1)},${height - pad} L${points[0][0].toFixed(1)},${height - pad} Z`;
  return (
    <div className="chart-wrap" style={{ height }}>
      <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" className="chart-svg" style={{ height }} role="img" aria-label="Time series chart">
        <defs>
          <linearGradient id="areaGradient" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.28" />
            <stop offset="100%" stopColor={color} stopOpacity="0" />
          </linearGradient>
        </defs>
        <g className="chart-grid">
          {[0.25, 0.5, 0.75, 1].map((fraction) => (
            <line key={fraction} x1={pad} x2={width - pad} y1={height - pad - fraction * (height - pad * 2)} y2={height - pad - fraction * (height - pad * 2)} />
          ))}
        </g>
        <path d={area} fill="url(#areaGradient)" />
        <path d={line} fill="none" stroke={color} strokeWidth={1.8} strokeLinejoin="round" strokeLinecap="round" />
      </svg>
    </div>
  );
}

export function Sparkline({ values, width = 96, height = 26, color = "var(--accent)" }: { values: number[]; width?: number; height?: number; color?: string }) {
  if (!values.length) return null;
  const max = Math.max(...values, 1);
  const step = values.length > 1 ? width / (values.length - 1) : width;
  const points = values.map((value, index) => `${index * step},${height - (value / max) * (height - 4) - 2}`).join(" ");
  return (
    <svg width={width} height={height} aria-hidden="true" style={{ overflow: "visible" }}>
      <polyline points={points} fill="none" stroke={color} strokeWidth={1.4} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

export function SeverityBars({ data }: { data: { label: string; value: number; color: string }[] }) {
  const max = Math.max(...data.map((item) => item.value), 1);
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {data.map((item) => (
        <div key={item.label}>
          <div className="row-between" style={{ fontSize: 11.5, marginBottom: 4 }}>
            <span className="muted">{item.label}</span>
            <span className="mono">{formatNumber(item.value)}</span>
          </div>
          <div className="progress" style={{ height: 4 }}>
            <span style={{ width: `${(item.value / max) * 100}%`, background: item.color }} />
          </div>
        </div>
      ))}
    </div>
  );
}

export function ProgressBar({ value, max = 100, tone }: { value: number; max?: number; tone?: string }) {
  const pct = max <= 0 ? 0 : Math.max(0, Math.min(100, (value / max) * 100));
  return (
    <div className="progress">
      <span style={{ width: `${pct}%`, ...(tone ? { background: tone } : {}) }} />
    </div>
  );
}

export function StatusDot({ status }: { status: string }) {
  const color =
    status === "healthy" || status === "active" || status === "success"
      ? "var(--success)"
      : status === "degraded" || status === "warning"
        ? "var(--warning)"
        : status === "unhealthy" || status === "failed"
          ? "var(--danger)"
          : "var(--dim)";
  return <span style={{ display: "inline-block", width: 7, height: 7, borderRadius: "50%", background: color, flex: "0 0 auto" }} aria-label={status} />;
}
