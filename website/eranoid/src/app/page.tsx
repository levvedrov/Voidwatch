import { Nav } from '@/components/Nav'
import { Footer } from '@/components/Footer'
import { AnimateIn } from '@/components/AnimateIn'
import {
  Brain, FlaskConical, Database, Layers,
  Eye, Lock, Globe,
  Github, Linkedin, Mail, ArrowRight, Cpu, Users,
} from 'lucide-react'

/* ── Hero ─────────────────────────────────────────────────── */
function Hero() {
  return (
    <section className="relative min-h-screen bg-grid flex flex-col items-center justify-center text-center px-6 overflow-hidden">
      <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
        <div className="h-[600px] w-[700px] rounded-full bg-white/[0.03] blur-[120px]" />
      </div>

      <div className="relative z-10 max-w-3xl mx-auto">
        <AnimateIn delay={0.08}>
          <h1 className="text-4xl sm:text-5xl md:text-6xl font-bold tracking-tight text-white leading-[1.1] mb-6">
            Building intelligent systems<br className="hidden sm:block" />
            {' '}for a safer digital future.
          </h1>
        </AnimateIn>

        <AnimateIn delay={0.15}>
          <p className="text-base sm:text-lg text-[#787882] leading-relaxed max-w-xl mx-auto mb-10">
            Eranoid develops intelligent software systems at the frontier of research and practical
            deployment — tools that help people understand complex environments and make better decisions.
          </p>
        </AnimateIn>

        <AnimateIn delay={0.22}>
          <div className="flex flex-wrap items-center justify-center gap-4">
            <a
              href="#contact"
              className="inline-flex items-center gap-2 rounded-md bg-white text-black px-6 py-2.5 text-sm font-bold tracking-wide hover:bg-white/90 transition-colors"
            >
              Contact Us <ArrowRight size={15} />
            </a>
            <a
              href="#about"
              className="inline-flex items-center gap-2 rounded-md border border-white/10 bg-white/5 px-6 py-2.5 text-sm font-semibold tracking-wide text-white hover:bg-white/10 transition-colors"
            >
              Learn More
            </a>
          </div>
        </AnimateIn>
      </div>

      <div className="pointer-events-none absolute bottom-0 inset-x-0 h-32 bg-gradient-to-t from-[#080809] to-transparent" />
    </section>
  )
}

/* ── About ────────────────────────────────────────────────── */
const ABOUT_CARDS = [
  { icon: Brain,        title: 'Intelligent Systems',      desc: 'Models and pipelines that learn from real-world data and produce decisions people can understand and verify.' },
  { icon: Layers,       title: 'Applied Research',         desc: 'We take ideas from research and ship them as practical products — closing the gap between academic progress and real-world use.' },
  { icon: Database,     title: 'Open Data Contribution',   desc: 'We build and share labeled datasets with the broader research community to raise the quality of publicly available training data.' },
  { icon: FlaskConical, title: 'Long-horizon Engineering', desc: 'Products designed to remain correct, maintainable, and explainable as they grow — not just fast to ship.' },
]

function About() {
  return (
    <section id="about" className="py-28 px-6">
      <div className="mx-auto max-w-6xl">
        <AnimateIn>
          <div className="mb-3 text-[11px] font-semibold tracking-[0.25em] uppercase text-[#424250]">About</div>
          <h2 className="text-3xl sm:text-4xl font-bold text-white mb-6 max-w-2xl">
            General intelligence software, starting with security
          </h2>
          <p className="text-[#787882] leading-relaxed max-w-2xl mb-16 text-base">
            Eranoid is a software company building intelligent systems across multiple domains.
            We focus on problems where good software — carefully reasoned, privacy-respecting, and
            grounded in data — can make a meaningful difference. Our first product, Voidwatch, applies
            that approach to endpoint security.
          </p>
        </AnimateIn>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {ABOUT_CARDS.map((c, i) => (
            <AnimateIn key={c.title} delay={i * 0.07}>
              <div className="glass rounded-xl p-6 h-full transition-all duration-300 hover:border-white/[0.13]">
                <c.icon size={22} className="text-white/40 mb-4" strokeWidth={1.5} />
                <div className="text-sm font-semibold text-white mb-2">{c.title}</div>
                <p className="text-xs text-[#787882] leading-relaxed">{c.desc}</p>
              </div>
            </AnimateIn>
          ))}
        </div>
      </div>
    </section>
  )
}

/* ── Vision ───────────────────────────────────────────────── */
const VISION_PILLARS = [
  { icon: Brain,    label: 'Explainable systems',         desc: 'Every output should come with a reason. Black-box decisions are a liability — in security, in science, and in products people depend on.' },
  { icon: Lock,     label: 'Security-first design',       desc: 'Security is not a feature — it is an architectural constraint. We embed it from the start, not as an afterthought.' },
  { icon: Database, label: 'Open datasets for better AI', desc: 'The quality of global AI is bounded by the quality of available data. We contribute labeled behavioral datasets to the research community to raise that floor.' },
  { icon: Zap,      label: 'Practical over impressive',   desc: 'A tool that runs reliably on modest hardware and does one thing well is more valuable than a complex system that fails in production.' },
  { icon: Eye,      label: 'Privacy-aware by default',    desc: 'We collect what is necessary and nothing more. Data collection should be proportional, transparent, and easy to audit.' },
]

function Zap({ size, className, strokeWidth }: { size: number; className?: string; strokeWidth?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={strokeWidth ?? 2} strokeLinecap="round" strokeLinejoin="round" className={className}>
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
    </svg>
  )
}

function Vision() {
  return (
    <section id="vision" className="py-28 px-6 bg-[#0a0a0c]">
      <div className="mx-auto max-w-6xl">
        <AnimateIn>
          <div className="mb-3 text-[11px] font-semibold tracking-[0.25em] uppercase text-[#424250]">Vision</div>
          <h2 className="text-3xl sm:text-4xl font-bold text-white mb-6 max-w-2xl">
            Software that earns trust through transparency.
          </h2>
          <p className="text-[#787882] leading-relaxed max-w-2xl mb-16 text-base">
            We believe intelligent software should be explainable, privacy-respecting, and grounded
            in openly shared knowledge. These are not ideals — they are engineering requirements.
          </p>
        </AnimateIn>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {VISION_PILLARS.map((p, i) => (
            <AnimateIn key={p.label} delay={i * 0.06}>
              <div className="glass rounded-xl p-6 transition-all duration-300 hover:border-white/[0.13]">
                <p.icon size={20} className="text-white/40 mb-3" strokeWidth={1.5} />
                <div className="text-sm font-semibold text-white mb-2">{p.label}</div>
                <p className="text-xs text-[#787882] leading-relaxed">{p.desc}</p>
              </div>
            </AnimateIn>
          ))}
        </div>
      </div>
    </section>
  )
}

/* ── Team ─────────────────────────────────────────────────── */
function Team() {
  return (
    <section id="team" className="py-28 px-6">
      <div className="mx-auto max-w-6xl">
        <AnimateIn>
          <div className="mb-3 text-[11px] font-semibold tracking-[0.25em] uppercase text-[#424250]">Team</div>
          <h2 className="text-3xl sm:text-4xl font-bold text-white mb-16">The people building Eranoid</h2>
        </AnimateIn>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
          <AnimateIn>
            <div className="glass rounded-2xl p-6 text-center transition-all duration-300 hover:border-white/[0.13]">
              <div className="mx-auto mb-4 h-20 w-20 rounded-full overflow-hidden bg-white/5 border border-white/10">
                <img src="/images/team/lev.jpg" alt="Lev Vedrov" className="h-full w-full object-cover" />
              </div>
              <div className="text-sm font-semibold text-white mb-1">Lev Vedrov</div>
              <div className="text-[11px] font-medium tracking-widest uppercase text-[#424250] mb-3">Founder & Engineer</div>
              <p className="text-xs text-[#787882] leading-relaxed mb-4">
                Building intelligent software systems at the intersection of machine learning,
                systems engineering, and security research.
              </p>
              <div className="flex items-center justify-center gap-3">
                <a href="https://github.com" target="_blank" rel="noopener noreferrer" className="text-[#424250] hover:text-white transition-colors">
                  <Github size={15} />
                </a>
                <a href="https://linkedin.com" target="_blank" rel="noopener noreferrer" className="text-[#424250] hover:text-white transition-colors">
                  <Linkedin size={15} />
                </a>
              </div>
            </div>
          </AnimateIn>

          <AnimateIn delay={0.07}>
            <div className="glass rounded-2xl p-6 text-center border-dashed flex flex-col items-center justify-center min-h-[240px]">
              <div className="h-20 w-20 rounded-full bg-white/5 border border-dashed border-white/10 flex items-center justify-center mb-4">
                <Users size={22} className="text-[#2d2d35]" />
              </div>
              <div className="text-xs text-[#424250] tracking-wide">Research & Advisors</div>
              <div className="text-[11px] mt-1 text-[#2d2d35]">Coming soon</div>
            </div>
          </AnimateIn>

          <AnimateIn delay={0.14}>
            <div className="glass rounded-2xl p-6 text-center border-dashed flex flex-col items-center justify-center min-h-[240px]">
              <div className="h-20 w-20 rounded-full bg-white/5 border border-dashed border-white/10 flex items-center justify-center mb-4">
                <Cpu size={22} className="text-[#2d2d35]" />
              </div>
              <div className="text-xs text-[#424250] tracking-wide">Engineering</div>
              <div className="text-[11px] mt-1 text-[#2d2d35]">Open positions</div>
            </div>
          </AnimateIn>
        </div>
      </div>
    </section>
  )
}

/* ── Contact ──────────────────────────────────────────────── */
function Contact() {
  return (
    <section id="contact" className="py-28 px-6 bg-[#0a0a0c]">
      <div className="mx-auto max-w-4xl">
        <AnimateIn>
          <div className="mb-3 text-[11px] font-semibold tracking-[0.25em] uppercase text-[#424250]">Contact</div>
          <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">Get in touch</h2>
          <p className="text-[#787882] mb-12 max-w-lg">
            Product inquiries, beta testing, investment, partnerships, and collaboration — we read everything.
          </p>
        </AnimateIn>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">
          <AnimateIn>
            <form
              action="https://formspree.io/f/REPLACE_FORM_ID"
              method="POST"
              className="flex flex-col gap-4"
            >
              <input type="hidden" name="_subject" value="Eranoid contact form" />

              <div className="grid grid-cols-2 gap-4">
                <div className="flex flex-col gap-1.5">
                  <label className="text-[11px] text-[#424250] tracking-wide uppercase">Name</label>
                  <input name="name" required
                    className="rounded-md border border-white/[0.07] bg-white/[0.03] px-3 py-2.5 text-sm text-white placeholder-white/20 outline-none focus:border-white/20 transition-colors"
                    placeholder="Your name" />
                </div>
                <div className="flex flex-col gap-1.5">
                  <label className="text-[11px] text-[#424250] tracking-wide uppercase">Email</label>
                  <input name="email" type="email" required
                    className="rounded-md border border-white/[0.07] bg-white/[0.03] px-3 py-2.5 text-sm text-white placeholder-white/20 outline-none focus:border-white/20 transition-colors"
                    placeholder="you@company.com" />
                </div>
              </div>

              <div className="flex flex-col gap-1.5">
                <label className="text-[11px] text-[#424250] tracking-wide uppercase">Company / Organization</label>
                <input name="company"
                  className="rounded-md border border-white/[0.07] bg-white/[0.03] px-3 py-2.5 text-sm text-white placeholder-white/20 outline-none focus:border-white/20 transition-colors"
                  placeholder="Optional" />
              </div>

              <div className="flex flex-col gap-1.5">
                <label className="text-[11px] text-[#424250] tracking-wide uppercase">Inquiry type</label>
                <select name="inquiry"
                  className="rounded-md border border-white/[0.07] bg-[#0d0d0f] px-3 py-2.5 text-sm text-[#787882] outline-none focus:border-white/20 transition-colors">
                  <option>General</option>
                  <option>Beta testing</option>
                  <option>Investment</option>
                  <option>Partnership</option>
                  <option>Collaboration</option>
                </select>
              </div>

              <div className="flex flex-col gap-1.5">
                <label className="text-[11px] text-[#424250] tracking-wide uppercase">Message</label>
                <textarea name="message" required rows={4}
                  className="rounded-md border border-white/[0.07] bg-white/[0.03] px-3 py-2.5 text-sm text-white placeholder-white/20 outline-none focus:border-white/20 transition-colors resize-none"
                  placeholder="Tell us about your inquiry…" />
              </div>

              <button type="submit"
                className="mt-2 rounded-md bg-white text-black px-6 py-2.5 text-sm font-bold tracking-wide hover:bg-white/90 transition-colors">
                Send Message
              </button>
            </form>
          </AnimateIn>

          <AnimateIn delay={0.1}>
            <div className="flex flex-col gap-6 pt-2">
              <div>
                <div className="text-[11px] font-semibold tracking-[0.2em] uppercase text-[#424250] mb-3">Direct contact</div>
                <div className="flex flex-col gap-3">
                  <a href="mailto:contact@eranoid.com" className="flex items-center gap-3 text-sm text-[#787882] hover:text-white transition-colors">
                    <Mail size={15} className="text-white/30" /> contact@eranoid.com
                  </a>
                  <a href="https://linkedin.com/company/eranoid" target="_blank" rel="noopener noreferrer" className="flex items-center gap-3 text-sm text-[#787882] hover:text-white transition-colors">
                    <Linkedin size={15} className="text-white/30" /> linkedin.com/company/eranoid
                  </a>
                  <a href="https://github.com/eranoid" target="_blank" rel="noopener noreferrer" className="flex items-center gap-3 text-sm text-[#787882] hover:text-white transition-colors">
                    <Github size={15} className="text-white/30" /> github.com/eranoid
                  </a>
                </div>
              </div>

              <div>
                <div className="text-[11px] font-semibold tracking-[0.2em] uppercase text-[#424250] mb-3">Location</div>
                <div className="flex items-center gap-2 text-sm text-[#787882]">
                  <Globe size={15} className="text-white/30" /> Seoul, South Korea · Global
                </div>
              </div>

              <div className="glass rounded-xl p-5">
                <div className="text-xs font-semibold text-white mb-2">Voidwatch Beta</div>
                <p className="text-xs text-[#787882] leading-relaxed mb-3">
                  Our first product — endpoint behavior monitoring for Windows. Apply for beta access.
                </p>
                <a href="https://voidwatch.eranoid.com/beta"
                  className="text-xs font-semibold text-white/60 hover:text-white transition-colors inline-flex items-center gap-1">
                  Apply for Beta <ArrowRight size={12} />
                </a>
              </div>
            </div>
          </AnimateIn>
        </div>
      </div>
    </section>
  )
}

/* ── Page ─────────────────────────────────────────────────── */
export default function Home() {
  return (
    <>
      <Nav />
      <main>
        <Hero />
        <About />
        <Vision />
        <Team />
        <Contact />
      </main>
      <Footer />
    </>
  )
}
