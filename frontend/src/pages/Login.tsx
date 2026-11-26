import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Eye, EyeOff, KeyRound, ShieldCheck } from "lucide-react";
import { useAuth } from "../lib/auth";
import { useI18n } from "../lib/i18n";
import { errorMessage } from "../lib/api";
import { Button, ErrorBanner, Field, Input } from "../components/ui";
import { BrandMark } from "../components/layout/AppShell";

export function LoginPage() {
  const { t, lang, setLang } = useI18n();
  const { login, verifyMfa, session, status } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [challenge, setChallenge] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  const target = (location.state as { from?: string } | null)?.from ?? "/";

  useEffect(() => {
    if (status === "authenticated" && session) navigate(target, { replace: true });
  }, [status, session, navigate, target]);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    const errors: Record<string, string> = {};
    if (!email.trim()) errors.email = t("common.required");
    if (!password) errors.password = t("common.required");
    setFieldErrors(errors);
    if (Object.keys(errors).length) return;
    setBusy(true);
    try {
      const result = await login(email.trim(), password);
      if (result.mfaRequired && result.challengeToken) {
        setChallenge(result.challengeToken);
        setCode("");
      } else {
        navigate(target, { replace: true });
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleMfa(event: React.FormEvent) {
    event.preventDefault();
    if (!challenge) return;
    setError(null);
    if (!/^\d{6,8}$/.test(code)) {
      setFieldErrors({ code: t("auth.invalidCode") });
      return;
    }
    setFieldErrors({});
    setBusy(true);
    try {
      await verifyMfa(challenge, code);
      navigate(target, { replace: true });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const languageToggle = (
    <div className="row" style={{ position: "absolute", top: 20, right: 24, gap: 4 }}>
      <button
        type="button"
        className={`icon-btn ${lang === "es" ? "active-lang" : ""}`}
        onClick={() => setLang("es")}
        aria-label="Español"
        style={lang === "es" ? { color: "var(--accent)", borderColor: "var(--border-accent)" } : undefined}
      >
        ES
      </button>
      <button
        type="button"
        className="icon-btn"
        onClick={() => setLang("en")}
        aria-label="English"
        style={lang === "en" ? { color: "var(--accent)", borderColor: "var(--border-accent)" } : undefined}
      >
        EN
      </button>
    </div>
  );

  return (
    <div className="login-shell">
      {languageToggle}
      <section className="login-panel">
        <div className="login-brand">
          <BrandMark className="brand-mark" />
          <div>
            <strong>HISPANSHIELD</strong>
            <span>Autonomous Cyber Defence</span>
          </div>
        </div>

        <div className="eyebrow">{t("auth.restricted")}</div>
        <h1>{challenge ? t("auth.mfaTitle") : t("auth.title")}</h1>
        <p className="login-sub">{challenge ? t("auth.mfaSubtitle") : t("auth.subtitle")}</p>

        {error ? <div style={{ marginBottom: 14 }}><ErrorBanner message={error} compact /></div> : null}

        {challenge ? (
          <form className="login-form" onSubmit={handleMfa}>
            <Field label={t("auth.mfaCode")} htmlFor="totp" error={fieldErrors.code} hint="TOTP · 30 s">
              <Input
                id="totp"
                name="totp"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]{6,8}"
                maxLength={8}
                value={code}
                onChange={(event) => setCode(event.target.value.replace(/\D/g, ""))}
                className="input-lg mono"
                style={{ letterSpacing: "0.4em", fontSize: 18, textAlign: "center" }}
                autoFocus
                aria-invalid={Boolean(fieldErrors.code)}
              />
            </Field>
            <Button type="submit" variant="primary" size="lg" loading={busy} icon={ShieldCheck} aria-busy={busy}>
              {t("auth.verify")}
            </Button>
            <Button type="button" variant="ghost" onClick={() => { setChallenge(null); setError(null); }}>
              {t("auth.back")}
            </Button>
          </form>
        ) : (
          <form className="login-form" onSubmit={handleSubmit}>
            <Field label={t("auth.email")} htmlFor="email" error={fieldErrors.email}>
              <Input
                id="email"
                name="email"
                type="email"
                autoComplete="username"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                className="input-lg"
                placeholder="operator@organization.eu"
                aria-invalid={Boolean(fieldErrors.email)}
                required
              />
            </Field>
            <Field label={t("auth.password")} htmlFor="password" error={fieldErrors.password}>
              <div style={{ position: "relative" }}>
                <Input
                  id="password"
                  name="password"
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  className="input-lg"
                  style={{ paddingRight: 40 }}
                  aria-invalid={Boolean(fieldErrors.password)}
                  required
                />
                <button
                  type="button"
                  className="icon-btn"
                  onClick={() => setShowPassword((value) => !value)}
                  aria-label={showPassword ? "Ocultar contraseña" : "Mostrar contraseña"}
                  style={{ position: "absolute", right: 4, top: 4 }}
                >
                  {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </Field>
            <Button type="submit" variant="primary" size="lg" loading={busy} icon={KeyRound} aria-busy={busy}>
              {busy ? t("auth.signingIn") : t("auth.signIn")}
            </Button>
          </form>
        )}

        <div className="login-meta">
          <ShieldCheck size={12} style={{ display: "inline", marginRight: 5, color: "var(--success)" }} />
          {t("auth.euHosting")}
          <br />
          {t("auth.securityNotice")}
        </div>
      </section>

      <aside className="login-visual" aria-hidden="true">
        <div className="visual-metrics">
          <span className="visual-metric"><b>ZERO TRUST</b> · mTLS</span>
          <span className="visual-metric"><b>LOCAL AI</b> · offline-ready</span>
          <span className="visual-metric"><b>NIS2</b> · ENS · GDPR</span>
        </div>
        <div className="radar">
          <div className="radar-core">
            <BrandMark className="shield" />
            <span className="tagline">Defence in depth</span>
          </div>
        </div>
        <div className="visual-caption">
          <span>EU · SOVEREIGN DEFENCE GRID</span>
          <span>{new Date().getFullYear()} · RESTRICTED</span>
        </div>
      </aside>
    </div>
  );
}
