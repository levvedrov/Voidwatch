import { AnimateIn } from '@/components/AnimateIn'
import Link from 'next/link'
import {
  ArrowRight, Download, ShieldCheck, Brain, Users, Eye, Lock, Cpu,
  CheckCircle2, XCircle, ArrowDownToLine, FileText,
} from 'lucide-react'

/* ── Hero ─────────────────────────────────────────────────── */
function Hero() {
  return (
    <section className="relative min-h-screen bg-grid flex flex-col items-center justify-center text-center px-6 overflow-hidden pt-24">
      <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
        <div className="h-[500px] w-[700px] rounded-full bg-white/[0.03] blur-[120px]" />
      </div>

      <div className="relative z-10 max-w-3xl mx-auto">
        <AnimateIn>
          <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.04] px-4 py-1.5 text-[11px] font-semibold tracking-[0.2em] uppercase text-[#787882]">
            <span className="h-1.5 w-1.5 rounded-full bg-white/40 animate-pulse" />
            Private Beta · Windows
          </div>
        </AnimateIn>

        <AnimateIn delay={0.08}>
          <h1 className="text-4xl sm:text-5xl md:text-6xl font-bold tracking-tight text-white leading-[1.1] mb-6">
            An AI assistant that watches<br className="hidden sm:block" /> your endpoints.
          </h1>
        </AnimateIn>

        <AnimateIn delay={0.15}>
          <p className="text-base sm:text-lg text-[#787882] leading-relaxed max-w-xl mx-auto mb-10">
            Voidwatch runs quietly on Windows, learns what normal looks like on your machine, and
            tells you when something is wrong — what it is, why it matters, and how suspicious it is.
            No enterprise complexity. No alert fatigue.
          </p>
        </AnimateIn>

        <AnimateIn delay={0.22}>
          <div className="flex flex-wrap items-center justify-center gap-4">
            <Link
              href="/download"
              className="inline-flex items-center gap-2 rounded-md bg-white hover:bg-white/90 px-6 py-2.5 text-sm font-bold tracking-wide text-black transition-colors"
            >
              <Download size={16} /> Download Beta
            </Link>
            <Link
              href="/beta"
              className="inline-flex items-center gap-2 rounded-md border border-white/10 bg-white/5 px-6 py-2.5 text-sm font-semibold tracking-wide text-white hover:bg-white/10 transition-colors"
            >
              Join Beta Program <ArrowRight size={15} />
            </Link>
            <Link
              href="/privacy"
              className="text-sm text-[#787882] hover:text-white transition-colors underline underline-offset-4"
            >
              Read Privacy Policy
            </Link>
          </div>
        </AnimateIn>

        {/* dashboard preview */}
        <AnimateIn delay={0.3}>
          <div className="mt-16 mx-auto max-w-4xl rounded-xl overflow-hidden border border-white/[0.08] shadow-2xl shadow-black/60">
            <div className="flex items-center gap-1.5 bg-[#0d0d0f] px-4 py-3 border-b border-white/[0.06]">
              <span className="h-2.5 w-2.5 rounded-full bg-white/10" />
              <span className="h-2.5 w-2.5 rounded-full bg-white/10" />
              <span className="h-2.5 w-2.5 rounded-full bg-white/10" />
              <span className="ml-3 text-[10px] text-[#424250] tracking-wide">Voidwatch Dashboard</span>
            </div>
            <img src="/images/dashboard.png" alt="Voidwatch Dashboard" className="w-full" />
          </div>
        </AnimateIn>
      </div>

      <div className="pointer-events-none absolute bottom-0 inset-x-0 h-32 bg-gradient-to-t from-[#080809] to-transparent" />
    </section>
  )
}

/* ── Features ─────────────────────────────────────────────── */
const FEATURES = [
  {
    icon: Cpu,
    title: 'It watches everything',
    desc: 'Every process that runs on your machine — its name, path, parent, command line, network connections, and whether it is signed — is observed and recorded.',
  },
  {
    icon: Brain,
    title: 'It tells you what is suspicious',
    desc: 'A trained ML classifier scores every process from 0 to 100%. High scores surface as alerts. You see the risk, not a raw list of events to dig through yourself.',
  },
  {
    icon: ShieldCheck,
    title: 'It explains its reasoning',
    desc: 'Each alert shows which rules fired and what behavior triggered the score — so you can decide whether to act, not just know that something happened.',
  },
  {
    icon: Users,
    title: 'It learns from your corrections',
    desc: 'Mark a process as benign or malicious in the dashboard. Those labels feed back into the next training session, making the assistant smarter on your data.',
  },
  {
    icon: Eye,
    title: 'It only looks at what matters',
    desc: 'Voidwatch sees process behavior, not your content. It never reads files, captures your screen, records keystrokes, or touches passwords or messages.',
  },
  {
    icon: Lock,
    title: 'It runs quietly in the background',
    desc: 'A lightweight Windows agent collects telemetry silently. No performance impact, no popups. The dashboard is there when you want it, invisible when you do not.',
  },
]

function Features() {
  return (
    <section className="py-28 px-6 bg-[#0a0a0c]">
      <div className="mx-auto max-w-6xl">
        <AnimateIn>
          <div className="mb-3 text-[11px] font-semibold tracking-[0.25em] uppercase text-[#424250]">What Voidwatch does</div>
          <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">Your security analyst, running 24/7</h2>
          <p className="text-[#787882] mb-16 max-w-xl">Voidwatch acts like a security analyst sitting next to you — observing, scoring, explaining, and learning — without needing your attention until something is actually wrong.</p>
        </AnimateIn>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {FEATURES.map((f, i) => (
            <AnimateIn key={f.title} delay={i * 0.06}>
              <div className="glass rounded-xl p-6 h-full hover:border-white/[0.13] transition-all duration-300">
                <f.icon size={22} className="text-white/50 mb-4" strokeWidth={1.5} />
                <div className="text-sm font-semibold text-white mb-2">{f.title}</div>
                <p className="text-xs text-[#787882] leading-relaxed">{f.desc}</p>
              </div>
            </AnimateIn>
          ))}
        </div>
      </div>
    </section>
  )
}

/* ── Screenshots ──────────────────────────────────────────── */
function Screenshots() {
  return (
    <section className="py-28 px-6">
      <div className="mx-auto max-w-5xl">
        <AnimateIn>
          <div className="mb-3 text-[11px] font-semibold tracking-[0.25em] uppercase text-[#424250]">Alerts</div>
          <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">Every threat, explained</h2>
          <p className="text-[#787882] mb-16 max-w-xl">
            The Alerts view shows a live timeline of flagged activity and a full breakdown of each
            detection — process path, parent, network connections, and exactly why the score fired.
          </p>
        </AnimateIn>

        <AnimateIn>
          <div className="rounded-xl overflow-hidden border border-white/[0.08] shadow-2xl shadow-black/60">
            <div className="flex items-center gap-1.5 bg-[#0d0d0f] px-4 py-3 border-b border-white/[0.06]">
              <span className="h-2.5 w-2.5 rounded-full bg-white/10" />
              <span className="h-2.5 w-2.5 rounded-full bg-white/10" />
              <span className="h-2.5 w-2.5 rounded-full bg-white/10" />
              <span className="ml-3 text-[10px] text-[#424250] tracking-wide">Alerts — Threat Timeline</span>
            </div>
            <img src="/images/alerts.png" alt="Voidwatch Alerts" className="w-full" />
          </div>
        </AnimateIn>
      </div>
    </section>
  )
}

/* ── Detection Engine ─────────────────────────────────────── */
function DetectionEngine() {
  return (
    <section className="py-28 px-6">
      <div className="mx-auto max-w-5xl">
        <AnimateIn>
          <div className="mb-3 text-[11px] font-semibold tracking-[0.25em] uppercase text-[#424250]">Detection Engine</div>
          <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">How the assistant thinks</h2>
          <p className="text-[#787882] mb-16 max-w-xl">
            Voidwatch does not guess. Every risk score is the result of two independent reasoning
            layers — one that applies known rules, and one that learned from real attack data.
          </p>
        </AnimateIn>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-10">
          <AnimateIn>
            <div className="glass rounded-2xl p-7 h-full hover:border-white/[0.13] transition-all duration-300">
              <div className="text-[10px] font-bold tracking-[0.2em] uppercase text-[#424250] mb-3">Layer 1</div>
              <h3 className="text-base font-bold text-white mb-3">Rule-Based Engine</h3>
              <p className="text-xs text-[#787882] leading-relaxed mb-5">
                A deterministic rule set maps process behavior to known attack patterns from the
                MITRE ATT&amp;CK framework. Rules fire instantly — no model inference latency —
                and produce explainable, auditable detections.
              </p>
              <ul className="flex flex-col gap-2">
                {['MITRE ATT&CK tactic mapping', 'Parent-child chain analysis', 'Suspicious path and signature checks', 'Network destination flagging'].map(item => (
                  <li key={item} className="flex items-center gap-2 text-xs text-[#787882]">
                    <span className="h-1 w-1 rounded-full bg-white/20 shrink-0" />{item}
                  </li>
                ))}
              </ul>
            </div>
          </AnimateIn>

          <AnimateIn delay={0.08}>
            <div className="glass rounded-2xl p-7 h-full hover:border-white/[0.13] transition-all duration-300">
              <div className="text-[10px] font-bold tracking-[0.2em] uppercase text-[#424250] mb-3">Layer 2</div>
              <h3 className="text-base font-bold text-white mb-3">ML Classifier</h3>
              <p className="text-xs text-[#787882] leading-relaxed mb-5">
                A gradient boosting classifier trained on labeled Windows process telemetry from
                real-world attack and benign datasets. Calibrated with isotonic regression to
                produce accurate probability scores rather than raw model outputs.
              </p>
              <ul className="flex flex-col gap-2">
                {['HistGradientBoosting classifier', 'Isotonic calibration for accurate probabilities', 'Trained on OTRF Security Datasets', 'Human-reviewed beta labels feed retraining'].map(item => (
                  <li key={item} className="flex items-center gap-2 text-xs text-[#787882]">
                    <span className="h-1 w-1 rounded-full bg-white/20 shrink-0" />{item}
                  </li>
                ))}
              </ul>
            </div>
          </AnimateIn>
        </div>

        <AnimateIn delay={0.1}>
          <div className="glass rounded-xl px-6 py-5 flex flex-wrap justify-around gap-6 text-center">
            {[
              { label: 'AUC-ROC',    value: '0.943', sub: 'Model discrimination' },
              { label: 'AUC-PR',     value: '0.859', sub: 'Precision-recall area' },
              { label: 'Recall',     value: '90%',   sub: 'Threat detection rate'  },
              { label: 'Training',   value: 'OTRF',  sub: 'Attack dataset source'  },
              { label: 'Retrained',  value: 'Live',  sub: 'Per beta session'        },
            ].map(s => (
              <div key={s.label}>
                <div className="text-lg font-bold text-white font-mono">{s.value}</div>
                <div className="text-[10px] font-semibold tracking-widest uppercase text-[#424250] mt-0.5">{s.label}</div>
                <div className="text-[10px] text-[#424250] mt-0.5">{s.sub}</div>
              </div>
            ))}
          </div>
        </AnimateIn>
      </div>
    </section>
  )
}

/* ── Privacy ──────────────────────────────────────────────── */
const COLLECTED     = ['Process name', 'Process path', 'Parent process', 'Command line', 'Network destination IP and port', 'Digital signature information', 'Timestamp', 'Risk score']
const NOT_COLLECTED = ['Passwords', 'Private messages', 'Files and documents', 'Screenshots', 'Browser history', 'Cookies', 'Document contents', 'Keystrokes']

function Privacy() {
  return (
    <section className="py-28 px-6 bg-[#0a0a0c]">
      <div className="mx-auto max-w-4xl">
        <AnimateIn>
          <div className="mb-3 text-[11px] font-semibold tracking-[0.25em] uppercase text-[#424250]">Privacy & Trust</div>
          <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">It watches processes, not people</h2>
          <p className="text-[#787882] mb-12 max-w-xl">
            Voidwatch is an assistant that understands system behavior — not one that reads your
            content. Here is exactly what it sees and what it never touches.
          </p>
        </AnimateIn>

        <AnimateIn>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-8">
            <div className="glass rounded-xl p-6">
              <div className="flex items-center gap-2 text-sm font-semibold text-emerald-400 mb-4">
                <CheckCircle2 size={16} /> Collected
              </div>
              <ul className="flex flex-col gap-2.5">
                {COLLECTED.map(item => (
                  <li key={item} className="flex items-center gap-2 text-xs text-[#787882]">
                    <span className="h-1 w-1 rounded-full bg-emerald-500/60 shrink-0" />
                    {item}
                  </li>
                ))}
              </ul>
            </div>

            <div className="glass rounded-xl p-6">
              <div className="flex items-center gap-2 text-sm font-semibold text-red-400 mb-4">
                <XCircle size={16} /> Never collected
              </div>
              <ul className="flex flex-col gap-2.5">
                {NOT_COLLECTED.map(item => (
                  <li key={item} className="flex items-center gap-2 text-xs text-[#787882]">
                    <span className="h-1 w-1 rounded-full bg-red-500/60 shrink-0" />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <div className="text-center">
            <Link
              href="/privacy"
              className="inline-flex items-center gap-2 text-sm text-[#787882] hover:text-white transition-colors border border-white/10 rounded-md px-5 py-2.5"
            >
              <FileText size={14} /> Read Full Data Collection Policy
            </Link>
          </div>
        </AnimateIn>
      </div>
    </section>
  )
}

/* ── Architecture ─────────────────────────────────────────── */
const ARCH_STEPS = [
  { label: 'Voidwatch\nClient',     sub: 'Windows process & network telemetry'   },
  { label: 'Telemetry\nAPI',        sub: 'Secure ingestion endpoint'              },
  { label: 'Risk\nEngine',          sub: 'Rule-based + ML scoring'               },
  { label: 'Admin\nDashboard',      sub: 'Human review & labeling'               },
  { label: 'Reviewed\nDataset',     sub: 'Labeled training data'                  },
  { label: 'Improved\nModel',       sub: 'Retrained classifier'                   },
]

function Architecture() {
  return (
    <section className="py-28 px-6">
      <div className="mx-auto max-w-5xl">
        <AnimateIn>
          <div className="mb-3 text-[11px] font-semibold tracking-[0.25em] uppercase text-[#424250]">Architecture</div>
          <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">How it works</h2>
          <p className="text-[#787882] mb-16 max-w-xl">
            A client-server architecture where telemetry flows from endpoint to dashboard and
            human-reviewed labels feed back into model improvement.
          </p>
        </AnimateIn>

        <AnimateIn>
          <div className="flex flex-wrap items-start justify-center gap-0">
            {ARCH_STEPS.map((step, i) => (
              <div key={step.label} className="flex items-center">
                <div className="flex flex-col items-center text-center w-28 sm:w-32">
                  <div className="glass rounded-lg px-3 py-3 w-full mb-2 hover:border-white/[0.14] transition-all">
                    <div className="text-xs font-semibold text-white whitespace-pre-line leading-tight">{step.label}</div>
                  </div>
                  <div className="text-[9px] text-[#424250] leading-tight px-1">{step.sub}</div>
                </div>
                {i < ARCH_STEPS.length - 1 && (
                  <div className="mx-1 sm:mx-2 text-[#2d2d35] text-lg mt-[-20px] shrink-0">→</div>
                )}
              </div>
            ))}
          </div>
        </AnimateIn>
      </div>
    </section>
  )
}

/* ── Download CTA ─────────────────────────────────────────── */
function DownloadCTA() {
  return (
    <section className="py-28 px-6 bg-[#0a0a0c]">
      <div className="mx-auto max-w-3xl text-center">
        <AnimateIn>
          <div className="relative overflow-hidden glass rounded-2xl p-12">
            <div className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-white/20 to-transparent" />
            <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
              <div className="h-48 w-80 rounded-full bg-white/[0.03] blur-[60px]" />
            </div>

            <div className="relative z-10">
              <div className="mb-3 text-[11px] font-semibold tracking-[0.25em] uppercase text-[#424250]">Download</div>
              <h2 className="text-2xl sm:text-3xl font-bold text-white mb-4">Get your AI security assistant</h2>
              <p className="text-[#787882] mb-2 text-sm leading-relaxed max-w-lg mx-auto">
                Voidwatch Beta is available now for Windows. Install it, activate your license key,
                and it starts watching immediately — no configuration, no rules to write.
              </p>
              <p className="text-xs text-[#424250] mb-8 italic">
                Voidwatch is a beta assistant, not a replacement for antivirus or enterprise EDR software.
              </p>

              <div className="flex flex-wrap items-center justify-center gap-4">
                <Link
                  href="/download"
                  className="inline-flex items-center gap-2 rounded-md bg-white hover:bg-white/90 px-6 py-2.5 text-sm font-bold tracking-wide text-black transition-colors"
                >
                  <ArrowDownToLine size={16} /> Download Beta Client
                </Link>
                <Link
                  href="/beta"
                  className="inline-flex items-center gap-2 rounded-md border border-white/10 bg-white/5 px-6 py-2.5 text-sm font-semibold text-white hover:bg-white/10 transition-colors"
                >
                  Join Beta Program <ArrowRight size={15} />
                </Link>
              </div>
            </div>
          </div>
        </AnimateIn>
      </div>
    </section>
  )
}

/* ── Page ─────────────────────────────────────────────────── */
export default function Home() {
  return (
    <>
      <Hero />
      <Features />
      <Screenshots />
      <DetectionEngine />
      <Privacy />
      <Architecture />
      <DownloadCTA />
    </>
  )
}
