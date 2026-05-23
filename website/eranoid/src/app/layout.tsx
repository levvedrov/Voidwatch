import type { Metadata } from 'next'
import { Inter, JetBrains_Mono } from 'next/font/google'
import './globals.css'

const inter = Inter({ subsets: ['latin'], variable: '--font-inter' })
const mono  = JetBrains_Mono({ subsets: ['latin'], variable: '--font-mono', weight: ['400','500','700'] })

export const metadata: Metadata = {
  title: 'Eranoid — Building intelligent systems for a safer digital future',
  description: 'Eranoid develops AI-powered software for cybersecurity, automation, and intelligent digital infrastructure.',
  keywords: ['AI', 'cybersecurity', 'endpoint monitoring', 'automation', 'Eranoid'],
  authors: [{ name: 'Eranoid' }],
  openGraph: {
    title: 'Eranoid',
    description: 'Building intelligent systems for a safer digital future.',
    url: 'https://eranoid.com',
    siteName: 'Eranoid',
    images: [{ url: '/images/og.png', width: 1200, height: 630 }],
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Eranoid',
    description: 'Building intelligent systems for a safer digital future.',
    images: ['/images/og.png'],
  },
  icons: { icon: '/favicon.ico' },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${mono.variable}`}>
      <body className="font-sans bg-void text-[#e2e2ec] min-h-screen">
        {children}
      </body>
    </html>
  )
}
