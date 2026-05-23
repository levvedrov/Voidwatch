import { AnimateIn } from '@/components/AnimateIn'
import { ArrowRight, Users, Brain, Shield, CheckCircle2 } from 'lucide-react'

const PERKS = [
  { icon: Shield,       title: 'Early access',      desc: 'Get Voidwatch before public release and shape the product from the ground up.' },
  { icon: Brain,        title: 'Improve detection',  desc: 'Your labeled feedback directly improves the ML classifier\'s accuracy and reduces false positives.' },
  { icon: Users,        title: 'Direct access',      desc: 'Communicate directly with the development team. Your issues and requests are heard immediately.' },
  { icon: CheckCircle2, title: 'Free beta license',  desc: 'Beta participants receive a free license key for the duration of the beta program.' },
]

export default function BetaPage() {
  return (
    <div className="pt-24 px-6 pb-20">
      <div className="mx-auto max-w-3xl">

        <AnimateIn>
          <div className="mb-3 text-[11px] font-semibold tracking-[0.25em] uppercase text-[#424250]">Beta Program</div>
          <h1 className="text-3xl sm:text-4xl font-bold text-white mb-4">Join the Voidwatch Beta</h1>
          <p className="text-[#787882] mb-12 max-w-xl leading-relaxed">
            We are currently testing Voidwatch with selected Windows users, developers, and
            cybersecurity students. Beta participants help us improve detection quality, reduce
            false positives, and validate the product in real environments.
          </p>
        </AnimateIn>

        <AnimateIn>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-12">
            {PERKS.map((p) => (
              <div key={p.title} className="glass rounded-xl p-5">
                <p.icon size={18} className="text-white/40 mb-3" strokeWidth={1.5} />
                <div className="text-sm font-semibold text-white mb-1">{p.title}</div>
                <p className="text-xs text-[#787882] leading-relaxed">{p.desc}</p>
              </div>
            ))}
          </div>
        </AnimateIn>

        <AnimateIn>
          <h2 className="text-lg font-bold text-white mb-4">Who we're looking for</h2>
          <div className="glass rounded-xl p-6 mb-12">
            <ul className="flex flex-col gap-2.5">
              {[
                'Windows 10 or 11 users (64-bit)',
                'Developers, sysadmins, or IT professionals',
                'Cybersecurity students or researchers',
                'Small teams looking for endpoint visibility',
                'Anyone interested in AI-assisted threat detection',
              ].map(item => (
                <li key={item} className="flex items-center gap-2.5 text-xs text-[#787882]">
                  <span className="h-1 w-1 rounded-full bg-white/20 shrink-0" />
                  {item}
                </li>
              ))}
            </ul>
          </div>
        </AnimateIn>

        <AnimateIn>
          <div className="relative overflow-hidden glass rounded-2xl p-10 text-center">
            <div className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-white/20 to-transparent" />
            <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
              <div className="h-40 w-60 rounded-full bg-white/[0.03] blur-[60px]" />
            </div>

            <div className="relative z-10">
              <h2 className="text-xl font-bold text-white mb-3">Apply for Beta Access</h2>
              <p className="text-sm text-[#787882] mb-8 max-w-sm mx-auto leading-relaxed">
                Fill in the application form. We review applications and send license keys to approved participants within 48 hours.
              </p>
              <a
                href="https://forms.gle/REPLACE_WITH_GOOGLE_FORM_ID"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 rounded-md bg-white hover:bg-white/90 px-8 py-3 text-sm font-bold tracking-wide text-black transition-colors"
              >
                Apply for Beta Access <ArrowRight size={15} />
              </a>
              <div className="mt-4 text-xs text-[#424250]">No account required · Free during beta</div>
            </div>
          </div>
        </AnimateIn>

        <AnimateIn>
          <div className="mt-8 text-center">
            <p className="text-sm text-[#787882]">
              Already have a license key?{' '}
              <a href="/download" className="text-white hover:text-white/70 transition-colors underline underline-offset-4">
                Download the client →
              </a>
            </p>
          </div>
        </AnimateIn>

      </div>
    </div>
  )
}
