import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'CyberSentinel AI — Agentic Multi-Tool Security Platform',
  description: '43 security tools, provider-agnostic AI, Docker-powered.',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
