import { AnimateIn } from '@/components/AnimateIn'
import { CheckCircle2, XCircle, Shield } from 'lucide-react'

const COLLECTED = [
  { item: 'Process name',                    note: 'Name of the running executable (e.g., chrome.exe)' },
  { item: 'Process path',                    note: 'Full file system path of the executable' },
  { item: 'Parent process name and ID',      note: 'What launched the process' },
  { item: 'Command-line arguments',          note: 'Arguments passed to the process at launch' },
  { item: 'Network destination IP and port', note: 'Remote address the process is communicating with' },
  { item: 'Digital signature information',   note: 'Whether the executable is signed and by whom' },
  { item: 'Timestamp',                       note: 'When the telemetry snapshot was collected' },
  { item: 'Risk score',                      note: 'ML-computed behavioral risk rating (0–100%)' },
]

const NOT_COLLECTED = [
  'Passwords or credentials of any kind',
  'Private messages, emails, or chat content',
  'File contents or document data',
  'Screenshots or screen recordings',
  'Browser history or cookies',
  'Keystrokes or clipboard content',
  'Personal files or user data',
  'Location data',
]

export default function PrivacyPage() {
  return (
    <div className="pt-24 px-6 pb-20">
      <div className="mx-auto max-w-3xl">

        <AnimateIn>
          <div className="mb-3 text-[11px] font-semibold tracking-[0.25em] uppercase text-[#424250]">Privacy</div>
          <h1 className="text-3xl sm:text-4xl font-bold text-white mb-4">Data Collection Policy</h1>
          <p className="text-[#787882] mb-12 max-w-xl leading-relaxed">
            Voidwatch is a privacy-aware product. This page describes exactly what telemetry the
            beta client collects, how it is used, and what we explicitly do not collect.
          </p>
        </AnimateIn>

        <AnimateIn>
          <div className="flex gap-3 glass rounded-xl p-5 mb-12">
            <Shield size={18} className="text-white/40 shrink-0 mt-0.5" />
            <div>
              <div className="text-sm font-semibold text-white mb-1">Security-first, privacy-aware</div>
              <p className="text-xs text-[#787882] leading-relaxed">
                Voidwatch collects only behavioral process metadata needed for risk analysis. It
                does not read your files, capture your screen, record your keystrokes, or access any
                personal data. All collected telemetry is used exclusively for endpoint risk scoring
                and product improvement during the beta.
              </p>
            </div>
          </div>
        </AnimateIn>

        <AnimateIn>
          <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
            <CheckCircle2 size={17} className="text-emerald-400" /> What we collect
          </h2>
          <div className="glass rounded-xl overflow-hidden mb-8">
            {COLLECTED.map((c, i) => (
              <div key={c.item} className={`flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-4 px-5 py-3.5 ${i !== COLLECTED.length - 1 ? 'border-b border-white/[0.06]' : ''}`}>
                <div className="text-xs font-medium text-white w-52 shrink-0">{c.item}</div>
                <div className="text-xs text-[#787882]">{c.note}</div>
              </div>
            ))}
          </div>
        </AnimateIn>

        <AnimateIn>
          <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
            <XCircle size={17} className="text-red-400" /> What we never collect
          </h2>
          <div className="glass rounded-xl p-6 mb-12">
            <ul className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {NOT_COLLECTED.map(item => (
                <li key={item} className="flex items-center gap-2.5 text-xs text-[#787882]">
                  <XCircle size={13} className="text-red-500/60 shrink-0" />
                  {item}
                </li>
              ))}
            </ul>
          </div>
        </AnimateIn>

        <AnimateIn>
          <h2 className="text-lg font-bold text-white mb-4">How collected data is used</h2>
          <div className="flex flex-col gap-3 mb-12">
            {[
              { title: 'Risk scoring',        desc: 'Telemetry is analyzed by the rule engine and ML classifier to assign a behavioral risk score to each process.' },
              { title: 'Admin review',         desc: 'Risk-ranked events are displayed in the Voidwatch admin dashboard for manual review and labeling.' },
              { title: 'Model improvement',   desc: 'Admin-reviewed labels can be exported and used to improve future training datasets and classifier accuracy.' },
              { title: 'Product development', desc: 'Aggregated behavioral patterns (no personal data) help us improve detection quality during the beta phase.' },
            ].map(item => (
              <div key={item.title} className="glass rounded-xl p-5">
                <div className="text-xs font-semibold text-white mb-1">{item.title}</div>
                <p className="text-xs text-[#787882] leading-relaxed">{item.desc}</p>
              </div>
            ))}
          </div>
        </AnimateIn>

        <AnimateIn>
          <h2 className="text-lg font-bold text-white mb-4">Data storage and retention</h2>
          <div className="glass rounded-xl p-6 mb-12">
            <div className="flex flex-col gap-3 text-xs text-[#787882] leading-relaxed">
              <p>Telemetry is stored on the Voidwatch server hosted at <span className="text-white font-mono">api.voidwatch.eranoid.com</span>. Process records are retained for 7 days by default. Alert records are retained for 30 days. Both retention periods are configurable by the server administrator.</p>
              <p>No telemetry data is sold, shared with third parties, or used for any purpose outside of Voidwatch product development and your own endpoint monitoring review.</p>
              <p>During the beta, participating users consent to the collection of the telemetry described above. Beta participation can be ended at any time by uninstalling the client.</p>
            </div>
          </div>
        </AnimateIn>

        <AnimateIn>
          <div className="glass rounded-xl p-5 text-center">
            <div className="text-sm font-semibold text-white mb-2">Questions about privacy?</div>
            <p className="text-xs text-[#787882] mb-3">Contact us directly for any data or privacy questions.</p>
            <a href="mailto:contact@eranoid.com" className="text-sm text-white hover:text-white/70 transition-colors">contact@eranoid.com</a>
          </div>
        </AnimateIn>

        <div className="text-[11px] text-[#424250] mt-8">Last updated: May 2026</div>
      </div>
    </div>
  )
}
