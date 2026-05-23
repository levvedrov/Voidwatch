import type { Metadata } from 'next'
import { Inter, JetBrains_Mono } from 'next/font/google'
import './globals.css'
import { Nav } from '@/components/Nav'
import { Footer } from '@/components/Footer'

const inter = Inter({ subsets: ['latin'], variable: '--font-inter' })
const mono  = JetBrains_Mono({ subsets: ['latin'], variable: '--font-mono', weight: ['400','500','700'] })

export const metadata: Metadata = {
  title: 'Voidwatch — Your AI security assistant for Windows',
  description: 'Voidwatch watches your Windows endpoints, scores every process with AI, and tells you what is suspicious — so you know when something is actually wrong.',
  keywords: ['endpoint monitoring', 'cybersecurity', 'AI', 'Windows', 'EDR', 'Voidwatch'],
  openGraph: {
    title: 'Voidwatch Beta',
    description: 'Your AI security assistant for Windows endpoints.',
    url: 'https://voidwatch.eranoid.com',
    siteName: 'Voidwatch',
    images: [{ url: '/images/og.png', width: 1200, height: 630 }],
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Voidwatch Beta',
    description: 'Your AI security assistant for Windows endpoints.',
    images: ['/images/og.png'],
  },
  icons: { icon: '/favicon.ico' },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${mono.variable}`}>
      <body className="font-sans bg-void text-[#e2e2ec] min-h-screen">
        <Nav />
        <main>{children}</main>
        <Footer />
      </body>
    </html>
  )
}
