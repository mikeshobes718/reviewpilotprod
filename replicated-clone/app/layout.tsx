import './globals.css'
import { ReactNode } from 'react'

export const metadata = {
  title: 'Replicated Clone',
  description: 'Frontend-only clone scaffold',
}

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className="bg-surface text-white">
      <body className="min-h-screen antialiased">
        {children}
      </body>
    </html>
  )
}


