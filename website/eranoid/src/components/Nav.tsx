'use client'
import { useState, useEffect, useRef } from 'react'
import Link from 'next/link'
import { Menu, X, ChevronDown, ArrowRight } from 'lucide-react'

const links = [
  { label: 'About',   href: '#about'   },
  { label: 'Vision',  href: '#vision'  },
  { label: 'Team',    href: '#team'    },
  { label: 'Contact', href: '#contact' },
]

function ProductsDropdown({ onClose }: { onClose: () => void }) {
  return (
    <div className="absolute right-0 top-full mt-2 w-72 rounded-xl border border-white/[0.09] bg-[#0d0d0f]/95 backdrop-blur-xl shadow-2xl shadow-black/60 overflow-hidden z-50">
      <div className="px-4 py-3 border-b border-white/[0.06]">
        <div className="text-[10px] font-semibold tracking-[0.2em] uppercase text-[#424250]">Our Products</div>
      </div>

      <a
        href="https://voidwatch.eranoid.com"
        onClick={onClose}
        className="flex items-start gap-3 px-4 py-4 hover:bg-white/[0.04] transition-colors group"
      >
        <div className="mt-0.5 h-8 w-8 rounded-lg bg-white/[0.05] border border-white/10 flex items-center justify-center shrink-0">
          <span className="text-[10px] font-bold text-white/50">VW</span>
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-sm font-semibold text-white">Voidwatch</span>
            <span className="rounded-full border border-white/10 bg-white/5 px-1.5 py-0.5 text-[9px] font-bold tracking-widest uppercase text-[#787882]">Beta</span>
          </div>
          <div className="text-xs text-[#787882] leading-relaxed">Endpoint behavior monitoring for Windows — process telemetry, risk scoring, admin review.</div>
        </div>
        <ArrowRight size={13} className="text-[#424250] group-hover:text-white transition-colors shrink-0 mt-1" />
      </a>

      <div className="flex items-center gap-3 px-4 py-3 border-t border-white/[0.05]">
        <div className="h-8 w-8 rounded-lg bg-white/[0.03] border border-dashed border-white/10 flex items-center justify-center shrink-0">
          <span className="text-[#2d2d35] text-lg">+</span>
        </div>
        <div className="text-xs text-[#424250]">More products in development</div>
      </div>
    </div>
  )
}

export function Nav() {
  const [scrolled,     setScrolled]     = useState(false)
  const [mobileOpen,   setMobileOpen]   = useState(false)
  const [productsOpen, setProductsOpen] = useState(false)
  const dropRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const fn = () => setScrolled(window.scrollY > 40)
    window.addEventListener('scroll', fn)
    return () => window.removeEventListener('scroll', fn)
  }, [])

  useEffect(() => {
    const fn = (e: MouseEvent) => {
      if (dropRef.current && !dropRef.current.contains(e.target as Node))
        setProductsOpen(false)
    }
    document.addEventListener('mousedown', fn)
    return () => document.removeEventListener('mousedown', fn)
  }, [])

  return (
    <header className={`fixed inset-x-0 top-0 z-50 transition-all duration-300 ${
      scrolled ? 'border-b border-white/[0.07] bg-[#080809]/90 backdrop-blur-xl' : ''
    }`}>
      <nav className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
        <Link href="/" className="text-sm font-bold tracking-[0.3em] text-white uppercase">
          Eranoid
        </Link>

        <div className="hidden md:flex items-center gap-7">
          {links.map(l => (
            <a key={l.href} href={l.href}
              className="text-xs tracking-widest uppercase text-[#787882] hover:text-white transition-colors duration-200">
              {l.label}
            </a>
          ))}
        </div>

        <div ref={dropRef} className="hidden md:block relative">
          <button
            onClick={() => setProductsOpen(o => !o)}
            className="inline-flex items-center gap-2 rounded-md border border-white/10 bg-white/5 px-4 py-2 text-xs font-semibold tracking-widest uppercase text-white hover:bg-white/10 transition-colors duration-200"
          >
            Explore Products
            <ChevronDown size={13} className={`transition-transform duration-200 ${productsOpen ? 'rotate-180' : ''}`} />
          </button>
          {productsOpen && <ProductsDropdown onClose={() => setProductsOpen(false)} />}
        </div>

        <button className="md:hidden text-white/60" onClick={() => setMobileOpen(o => !o)}>
          {mobileOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </nav>

      {mobileOpen && (
        <div className="md:hidden border-t border-white/[0.07] bg-[#080809]/95 backdrop-blur-xl px-6 py-4 flex flex-col gap-4">
          {links.map(l => (
            <a key={l.href} href={l.href}
              className="text-xs tracking-widest uppercase text-[#787882] hover:text-white transition-colors"
              onClick={() => setMobileOpen(false)}>
              {l.label}
            </a>
          ))}
          <a href="https://voidwatch.eranoid.com"
            className="mt-2 text-center rounded-md border border-white/10 bg-white/5 px-4 py-2 text-xs font-semibold tracking-widest uppercase text-white"
            onClick={() => setMobileOpen(false)}>
            Voidwatch Beta →
          </a>
        </div>
      )}
    </header>
  )
}
