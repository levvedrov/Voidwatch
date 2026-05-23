'use client'
import { useState, useEffect } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { Menu, X } from 'lucide-react'

const links = [
  { label: 'Overview', href: '/'          },
  { label: 'Download', href: '/download'  },
  { label: 'Privacy',  href: '/privacy'   },
  { label: 'Beta',     href: '/beta'      },
  { label: 'Docs',     href: '/docs'      },
]

export function Nav() {
  const pathname = usePathname()
  const [scrolled, setScrolled] = useState(false)
  const [open, setOpen]         = useState(false)

  useEffect(() => {
    const fn = () => setScrolled(window.scrollY > 40)
    window.addEventListener('scroll', fn)
    return () => window.removeEventListener('scroll', fn)
  }, [])

  return (
    <header className={`fixed inset-x-0 top-0 z-50 transition-all duration-300 ${
      scrolled ? 'border-b border-white/[0.07] bg-[#080809]/90 backdrop-blur-xl' : ''
    }`}>
      <nav className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
        <Link href="/" className="flex items-center gap-3">
          <span className="text-sm font-bold tracking-[0.3em] text-white uppercase">Voidwatch</span>
          <span className="rounded-full border border-white/10 bg-white/5 px-2 py-0.5 text-[9px] font-bold tracking-widest uppercase text-[#787882]">Beta</span>
        </Link>

        <div className="hidden md:flex items-center gap-7">
          {links.map(l => (
            <Link
              key={l.href}
              href={l.href}
              className={`text-xs tracking-widest uppercase transition-colors duration-200 ${
                pathname === l.href ? 'text-white' : 'text-[#787882] hover:text-white'
              }`}
            >
              {l.label}
            </Link>
          ))}
        </div>

        <Link
          href="/download"
          className="hidden md:inline-flex items-center gap-2 rounded-md border border-white/20 bg-white/5 hover:bg-white/10 px-4 py-2 text-xs font-bold tracking-widest uppercase text-white transition-colors"
        >
          Download Beta
        </Link>

        <button className="md:hidden text-white/60" onClick={() => setOpen(o => !o)}>
          {open ? <X size={20} /> : <Menu size={20} />}
        </button>
      </nav>

      {open && (
        <div className="md:hidden border-t border-white/[0.07] bg-[#080809]/95 backdrop-blur-xl px-6 py-4 flex flex-col gap-4">
          {links.map(l => (
            <Link key={l.href} href={l.href}
              className="text-xs tracking-widest uppercase text-[#787882] hover:text-white transition-colors"
              onClick={() => setOpen(false)}
            >
              {l.label}
            </Link>
          ))}
          <Link href="/download"
            className="mt-2 text-center rounded-md border border-white/20 bg-white/5 px-4 py-2 text-xs font-bold tracking-widest uppercase text-white"
            onClick={() => setOpen(false)}
          >
            Download Beta
          </Link>
        </div>
      )}
    </header>
  )
}
