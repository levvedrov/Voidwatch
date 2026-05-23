import { AnimateIn } from '@/components/AnimateIn'
import Link from 'next/link'
import { Download, Terminal, Settings, Monitor, AlertTriangle, CheckCircle2, ArrowRight } from 'lucide-react'

const STEPS = [
  {
    icon: Download,
    step: '01',
    title: 'Download the installer',
    desc: 'Download the Voidwatch Beta setup file from the link above. The installer is a standard Windows executable (~8 MB).',
  },
  {
    icon: Settings,
    step: '02',
    title: 'Run the installer',
    desc: 'Run VoidwatchSetup.exe. The installer will place the agent and dashboard on your machine.',
  },
  {
    icon: Monitor,
    step: '03',
    title: 'Launch Voidwatch',
    desc: 'Open Voidwatch from the Start menu or desktop shortcut. The dashboard will start the agent and display live endpoint telemetry.',
  },
  {
    icon: Terminal,
    step: '04',
    title: 'Review and label events',
    desc: 'Use the dashboard to review flagged processes, adjust risk thresholds, and label activity to improve future detection.',
  },
]

export default function DownloadPage() {
  return (
    <div className="pt-24 px-6 pb-20">
      <div className="mx-auto max-w-4xl">

        <AnimateIn>
          <div className="mb-3 text-[11px] font-semibold tracking-[0.25em] uppercase text-[#424250]">Download</div>
          <h1 className="text-3xl sm:text-4xl font-bold text-white mb-4">Download Voidwatch Beta</h1>
          <p className="text-[#787882] mb-10 max-w-xl leading-relaxed">
            Voidwatch is currently available as a private beta for Windows systems. The beta client
            sends technical process and network telemetry to the Voidwatch server for risk scoring
            and admin review.
          </p>
        </AnimateIn>

        <AnimateIn>
          <div className="flex gap-3 glass rounded-xl p-4 mb-10" style={{borderColor:'rgba(234,179,8,0.15)',background:'rgba(234,179,8,0.04)'}}>
            <AlertTriangle size={16} className="text-yellow-500/80 shrink-0 mt-0.5" />
            <p className="text-xs text-[#787882] leading-relaxed">
              Voidwatch Beta is not a replacement for antivirus or enterprise EDR software. It is an
              early beta version intended for testing, telemetry review, and product development feedback.
            </p>
          </div>
        </AnimateIn>

        <AnimateIn>
          <div className="relative overflow-hidden glass rounded-2xl p-8 mb-16">
            <div className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-white/20 to-transparent" />
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6">
              <div>
                <div className="text-lg font-bold text-white mb-1">VoidwatchSetup.exe</div>
                <div className="text-xs text-[#424250]">Windows 10 / 11 · 64-bit · ~8 MB</div>
                <div className="flex items-center gap-2 mt-2">
                  <CheckCircle2 size={13} className="text-emerald-400" />
                  <span className="text-xs text-emerald-400">Beta license required</span>
                </div>
              </div>
              <a
                href="https://api.voidwatch.eranoid.com/download/VoidwatchSetup.exe"
                download="VoidwatchSetup.exe"
                className="shrink-0 inline-flex items-center gap-2 rounded-md bg-white hover:bg-white/90 px-6 py-3 text-sm font-bold tracking-wide text-black transition-colors"
              >
                <Download size={16} /> Download Beta Client
              </a>
            </div>
          </div>
        </AnimateIn>

        <AnimateIn>
          <h2 className="text-xl font-bold text-white mb-8">Setup Guide</h2>
        </AnimateIn>

        <div className="flex flex-col gap-4 mb-16">
          {STEPS.map((s, i) => (
            <AnimateIn key={s.step} delay={i * 0.07}>
              <div className="glass rounded-xl p-6 flex gap-5">
                <div className="shrink-0 font-mono text-2xl font-bold text-[#2d2d35]">{s.step}</div>
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <s.icon size={15} className="text-white/40" strokeWidth={1.5} />
                    <span className="text-sm font-semibold text-white">{s.title}</span>
                  </div>
                  <p className="text-xs text-[#787882] leading-relaxed">{s.desc}</p>
                </div>
              </div>
            </AnimateIn>
          ))}
        </div>

        <AnimateIn>
          <div className="flex flex-wrap gap-4">
            <Link href="/docs"    className="inline-flex items-center gap-2 text-sm text-[#787882] hover:text-white transition-colors border border-white/10 rounded-md px-4 py-2">
              View Documentation <ArrowRight size={13} />
            </Link>
            <Link href="/privacy" className="inline-flex items-center gap-2 text-sm text-[#787882] hover:text-white transition-colors border border-white/10 rounded-md px-4 py-2">
              Read Privacy Policy <ArrowRight size={13} />
            </Link>
            <Link href="/beta"    className="inline-flex items-center gap-2 text-sm text-[#787882] hover:text-white transition-colors border border-white/10 rounded-md px-4 py-2">
              Join Beta Program <ArrowRight size={13} />
            </Link>
          </div>
        </AnimateIn>

      </div>
    </div>
  )
}
