import Link from 'next/link'
import { Github, Linkedin, Mail } from 'lucide-react'

export function Footer() {
  return (
    <footer className="border-t border-white/[0.07] bg-[#07070a] px-6 py-12">
      <div className="mx-auto max-w-6xl flex flex-col md:flex-row items-center justify-between gap-6">
        <div>
          <div className="text-sm font-bold tracking-[0.3em] uppercase text-white mb-1">Eranoid</div>
          <div className="text-xs text-[#5c5c6e] tracking-wide">Building intelligent systems for a safer digital future.</div>
        </div>

        <div className="flex items-center gap-6">
          <a href="https://github.com/eranoid" target="_blank" rel="noopener noreferrer" className="text-[#5c5c6e] hover:text-white transition-colors">
            <Github size={16} />
          </a>
          <a href="https://linkedin.com/company/eranoid" target="_blank" rel="noopener noreferrer" className="text-[#5c5c6e] hover:text-white transition-colors">
            <Linkedin size={16} />
          </a>
          <a href="mailto:contact@eranoid.com" className="text-[#5c5c6e] hover:text-white transition-colors">
            <Mail size={16} />
          </a>
        </div>

        <div className="text-[11px] text-[#3c3c4e] tracking-wide">
          © {new Date().getFullYear()} Eranoid. All rights reserved.
        </div>
      </div>
    </footer>
  )
}
