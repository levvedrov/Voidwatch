import Link from 'next/link'
import { Github, Linkedin, Mail } from 'lucide-react'

export function Footer() {
  return (
    <footer className="border-t border-white/[0.07] bg-[#080809] px-6 py-12 mt-20">
      <div className="mx-auto max-w-6xl flex flex-col md:flex-row items-start justify-between gap-8">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="text-sm font-bold tracking-[0.3em] uppercase text-white">Voidwatch</span>
            <span className="rounded-full border border-white/10 bg-white/5 px-2 py-0.5 text-[9px] font-bold tracking-widest uppercase text-[#787882]">Beta</span>
          </div>
          <div className="text-xs text-[#424250] mb-1">by <a href="https://eranoid.com" className="hover:text-white transition-colors">Eranoid</a></div>
          <div className="text-xs text-[#424250] max-w-xs mt-2 leading-relaxed">
            AI-assisted endpoint behavior monitoring for Windows.
          </div>
        </div>

        <div className="flex flex-col gap-2">
          <div className="text-[10px] tracking-widest uppercase text-[#424250] mb-1">Pages</div>
          {[
            ['/','Overview'], ['/download','Download'], ['/privacy','Privacy'],
            ['/beta','Beta Program'], ['/docs','Documentation'],
          ].map(([href, label]) => (
            <Link key={href} href={href} className="text-xs text-[#424250] hover:text-white transition-colors">{label}</Link>
          ))}
        </div>

        <div className="flex flex-col gap-3">
          <div className="text-[10px] tracking-widest uppercase text-[#424250] mb-1">Contact</div>
          <a href="mailto:contact@eranoid.com" className="flex items-center gap-2 text-xs text-[#424250] hover:text-white transition-colors">
            <Mail size={13} /> contact@eranoid.com
          </a>
          <a href="https://github.com/eranoid" target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 text-xs text-[#424250] hover:text-white transition-colors">
            <Github size={13} /> github.com/eranoid
          </a>
          <a href="https://linkedin.com/company/eranoid" target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 text-xs text-[#424250] hover:text-white transition-colors">
            <Linkedin size={13} /> Eranoid on LinkedIn
          </a>
        </div>
      </div>

      <div className="mx-auto max-w-6xl border-t border-white/[0.05] mt-8 pt-6 flex flex-col sm:flex-row items-center justify-between gap-2">
        <div className="text-[11px] text-[#424250]">© {new Date().getFullYear()} Eranoid. All rights reserved.</div>
        <div className="flex items-center gap-4">
          <Link href="/privacy" className="text-[11px] text-[#424250] hover:text-white transition-colors">Privacy</Link>
          <Link href="/docs"    className="text-[11px] text-[#424250] hover:text-white transition-colors">Docs</Link>
        </div>
      </div>
    </footer>
  )
}
