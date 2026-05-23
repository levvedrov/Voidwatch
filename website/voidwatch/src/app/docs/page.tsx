import { AnimateIn } from '@/components/AnimateIn'
import Link from 'next/link'
import { ArrowRight } from 'lucide-react'

function Section({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    <div id={id} className="mb-12 scroll-mt-24">
      <h2 className="text-lg font-bold text-white mb-4 pb-3 border-b border-white/[0.07]">{title}</h2>
      <div className="flex flex-col gap-3 text-sm text-[#787882] leading-relaxed">{children}</div>
    </div>
  )
}

function Code({ children }: { children: React.ReactNode }) {
  return (
    <code className="font-mono text-xs bg-white/[0.06] border border-white/[0.08] rounded px-2 py-0.5 text-[#c0c0c8]">
      {children}
    </code>
  )
}

function Block({ children }: { children: React.ReactNode }) {
  return (
    <pre className="glass rounded-lg p-4 text-xs font-mono text-[#c0c0c8] overflow-x-auto leading-relaxed">
      {children}
    </pre>
  )
}

const TOC = [
  { id: 'overview',      label: 'Overview'            },
  { id: 'requirements',  label: 'System Requirements' },
  { id: 'installation',  label: 'Installation'         },
  { id: 'first-launch',  label: 'First Launch'         },
  { id: 'dashboard',     label: 'Dashboard Overview'   },
  { id: 'risk-scores',   label: 'Risk Scores'          },
  { id: 'faq',           label: 'FAQ'                  },
]

export default function DocsPage() {
  return (
    <div className="pt-24 px-6 pb-20">
      <div className="mx-auto max-w-5xl flex flex-col lg:flex-row gap-10">

        <aside className="lg:w-48 shrink-0">
          <div className="lg:sticky lg:top-28">
            <div className="text-[10px] font-semibold tracking-widest uppercase text-[#424250] mb-3">Contents</div>
            <nav className="flex flex-col gap-1">
              {TOC.map(t => (
                <a key={t.id} href={`#${t.id}`} className="text-xs text-[#424250] hover:text-white transition-colors py-0.5">
                  {t.label}
                </a>
              ))}
            </nav>
          </div>
        </aside>

        <div className="flex-1 min-w-0">
          <AnimateIn>
            <div className="mb-3 text-[11px] font-semibold tracking-[0.25em] uppercase text-[#424250]">Documentation</div>
            <h1 className="text-3xl sm:text-4xl font-bold text-white mb-4">Voidwatch Beta Docs</h1>
            <p className="text-[#787882] mb-12 max-w-xl leading-relaxed">
              Getting started guide and reference for the Voidwatch Beta client and admin dashboard.
            </p>
          </AnimateIn>

          <Section id="overview" title="Overview">
            <p>Voidwatch is a lightweight Windows endpoint monitoring system. It collects process and
            network telemetry from the host machine, sends it to the Voidwatch backend, and provides
            a risk-ranked view of all running process activity through the admin dashboard.</p>
            <p>The system uses a combination of rule-based detection and a machine learning classifier
            to assign behavioral risk scores (0–100%) to every observed process. High-scoring
            processes are surfaced as alerts for admin review.</p>
          </Section>

          <Section id="requirements" title="System Requirements">
            <ul className="flex flex-col gap-2">
              {[
                ['OS',      'Windows 10 or Windows 11 (64-bit)'],
                ['RAM',     '4 GB minimum (8 GB recommended)'],
                ['Storage', '100 MB free disk space'],
                ['Network', 'Outbound HTTPS access to api.voidwatch.eranoid.com'],
                ['License', 'Valid Voidwatch Beta license key (provided on approval)'],
              ].map(([k, v]) => (
                <li key={k} className="flex gap-3">
                  <span className="w-20 shrink-0 font-semibold text-white text-xs">{k}</span>
                  <span className="text-xs">{v}</span>
                </li>
              ))}
            </ul>
          </Section>

          <Section id="installation" title="Installation">
            <p>1. Download <Code>VoidwatchSetup.exe</Code> from the <Link href="/download" className="text-white/60 hover:text-white transition-colors underline underline-offset-2">download page</Link>.</p>
            <p>2. Run the installer. Accept the UAC prompt when asked.</p>
            <p>3. The installer will place the Voidwatch agent (<Code>voidwatch_agent.exe</Code>) and dashboard on your machine.</p>
            <p>4. A shortcut will be created on your Desktop and in the Start menu.</p>
            <p>5. Voidwatch is configured to launch automatically on Windows startup via the registry run key.</p>
            <p>To uninstall, use <strong className="text-white">Add or Remove Programs</strong> in Windows Settings and search for Voidwatch.</p>
          </Section>

          <Section id="first-launch" title="First Launch">
            <p>On first launch, you will see the Voidwatch activation screen. Paste your beta license key and click <strong className="text-white">Activate License</strong>.</p>
            <p>The dashboard will then connect to the server, wait for the agent to check in, and begin displaying telemetry. The startup loading screen shows progress through four stages:</p>
            <ul className="flex flex-col gap-1.5 ml-4">
              {['Connecting to server', 'Waiting for agent', 'Collecting telemetry', 'Analysing threat intelligence'].map(s => (
                <li key={s} className="text-xs">• {s}</li>
              ))}
            </ul>
            <p>First telemetry usually appears within 60 seconds of launch.</p>
          </Section>

          <Section id="dashboard" title="Dashboard Overview">
            <p>The dashboard has five main sections accessible from the top navigation:</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 not-prose">
              {[
                { tab: 'Dashboard',    desc: 'Overview: alerts today, active alerts, average risk score, last check time, and the ML score distribution chart.' },
                { tab: 'Processes',    desc: 'Full process list for the current telemetry batch with risk scores, parent process, network connections, and signature status.' },
                { tab: 'MITRE ATT&CK', desc: 'Process activity mapped to MITRE ATT&CK tactics and techniques based on rule detections.' },
                { tab: 'Alerts',       desc: 'All high-risk alerts (ML score ≥ 80%) with timeline, process details, and feedback controls.' },
                { tab: 'Settings',     desc: 'Data retention periods, license management, and database statistics.' },
              ].map(item => (
                <div key={item.tab} className="glass rounded-lg p-4">
                  <div className="text-xs font-semibold text-white mb-1">{item.tab}</div>
                  <p className="text-xs leading-relaxed">{item.desc}</p>
                </div>
              ))}
            </div>
          </Section>

          <Section id="risk-scores" title="Risk Scores">
            <p>Every process is assigned a risk score from 0–100% based on two components:</p>
            <div className="glass rounded-xl overflow-hidden not-prose">
              {[
                { label: '0–39%',   color: 'text-emerald-400', level: 'LOW / Benign',    desc: 'Normal system activity. No action required.' },
                { label: '40–79%',  color: 'text-yellow-400',  level: 'MEDIUM',           desc: 'Unusual but not necessarily malicious. Worth reviewing.' },
                { label: '80–100%', color: 'text-red-400',     level: 'CRITICAL / Alert', desc: 'High probability of malicious behavior. Review immediately.' },
              ].map((r, i) => (
                <div key={r.label} className={`flex items-start gap-4 px-5 py-3.5 text-xs ${i !== 2 ? 'border-b border-white/[0.06]' : ''}`}>
                  <span className={`font-mono font-bold w-16 shrink-0 ${r.color}`}>{r.label}</span>
                  <span className="font-semibold text-white w-32 shrink-0">{r.level}</span>
                  <span className="text-[#787882]">{r.desc}</span>
                </div>
              ))}
            </div>
            <p>Scores are computed by two independent layers:</p>
            <ul className="flex flex-col gap-2 ml-3">
              <li><strong className="text-white">Rule engine</strong> — deterministic pattern matching against MITRE ATT&CK tactics (parent-child chains, path anomalies, unsigned executables, suspicious network destinations). Always explainable.</li>
              <li><strong className="text-white">ML classifier</strong> — a <Code>HistGradientBoosting</Code> model trained on labeled Windows process telemetry from the OTRF Security Datasets. Calibrated with isotonic regression so the output is a true probability, not a raw model score. Current beta model: AUC-ROC 0.943 · Recall 90% · AUC-PR 0.859.</li>
            </ul>
            <p>The two signals are combined and calibrated into the final 0–100% score displayed in the dashboard.</p>
          </Section>

          <Section id="faq" title="FAQ">
            <div className="flex flex-col gap-4 not-prose">
              {[
                {
                  q: 'Does Voidwatch read my files or messages?',
                  a: 'No. Voidwatch only collects process metadata (name, path, parent, command line, network destinations, signature). It does not read files, capture screenshots, record keystrokes, or access any personal data.',
                },
                {
                  q: 'Why is a legitimate process flagged as high risk?',
                  a: 'False positives occur, especially in the beta phase. Common causes: processes with unusual parent-child chains, unsigned executables, or tools that behave similarly to known attack patterns. Use the "Mark as Benign" action in the Alerts tab to label it — this feedback improves future training.',
                },
                {
                  q: 'What happens if the server is unreachable?',
                  a: 'The agent will retry the connection automatically. The dashboard will show "Server: Offline" in the status bar. Telemetry is not cached locally — missed intervals are not recovered.',
                },
                {
                  q: 'How do I update Voidwatch?',
                  a: 'During beta, updates are distributed via new installer releases. Download the latest setup from the download page and run it — it will replace the existing installation.',
                },
                {
                  q: 'Can I run Voidwatch without a license key?',
                  a: 'The free tier allows you to continue without activating. Detection quality is reduced on the free tier. Beta license keys are provided to approved applicants at no cost.',
                },
              ].map(item => (
                <div key={item.q} className="glass rounded-xl p-5">
                  <div className="text-xs font-semibold text-white mb-2">{item.q}</div>
                  <p className="text-xs text-[#787882] leading-relaxed">{item.a}</p>
                </div>
              ))}
            </div>
          </Section>

          <AnimateIn>
            <div className="glass rounded-xl p-5 text-center mt-4">
              <div className="text-sm font-semibold text-white mb-2">Something missing?</div>
              <p className="text-xs text-[#787882] mb-3">Reach out and we'll help directly.</p>
              <a href="mailto:contact@eranoid.com" className="inline-flex items-center gap-1 text-sm text-white/60 hover:text-white transition-colors">
                contact@eranoid.com <ArrowRight size={13} />
              </a>
            </div>
          </AnimateIn>
        </div>
      </div>
    </div>
  )
}
