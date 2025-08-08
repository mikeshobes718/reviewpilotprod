"use client";
import { useState } from 'react';

const nav = [
  { label: 'Product', items: ['Kubernetes installers', 'License management', 'Air-gapped', 'Integrations'] },
  { label: 'Solutions', items: ['Enterprise', 'Hybrid', 'On‑prem'] },
  { label: 'Resources', items: ['Docs', 'Blog', 'Customer stories'] },
  { label: 'Pricing', href: '/pricing' },
];

export default function Header() {
  const [open, setOpen] = useState<number | null>(null);
  return (
    <header className="sticky top-0 z-50 bg-transparent">
      <div className="container-1100 flex items-center justify-between py-4">
        <div className="flex items-center gap-2 font-extrabold">
          <div className="w-8 h-8 rounded-lg grid place-items-center border" style={{borderColor:'var(--colors-border-primary)'}}>R</div>
          Replicated
        </div>
        <nav className="hidden md:flex items-center gap-2">
          {nav.map((n, i) => (
            <div key={i} className="relative">
              <button
                className="btn"
                onMouseEnter={() => setOpen(i)}
                onMouseLeave={() => setOpen(null)}
              >
                {n.label}
              </button>
              {'items' in n && open === i && (
                <div className="absolute left-0 mt-2 w-64 rounded-xl border p-2" style={{borderColor:'var(--colors-border-primary)', background:'var(--colors-background-card)', boxShadow:'var(--shadow-card)'}} onMouseEnter={() => setOpen(i)} onMouseLeave={() => setOpen(null)}>
                  {(n as any).items.map((it: string) => (
                    <a key={it} href="#" className="block px-3 py-2 rounded-lg hover:bg-black/5" style={{color:'var(--colors-text-primary)'}}>{it}</a>
                  ))}
                </div>
              )}
            </div>
          ))}
          <a href="#" className="btn">Log in</a>
          <a href="#" className="btn btn-primary">Get started</a>
        </nav>
        <button className="md:hidden btn" onClick={() => setOpen(open === -1 ? null : -1)}>
          Menu
        </button>
      </div>
      {open === -1 && (
        <div className="md:hidden border-t" style={{borderColor:'var(--colors-border-primary)', background:'var(--colors-background-card)'}}>
          <div className="container-1100 py-2 grid gap-1">
            {nav.map((n, i) => (
              <details key={i} className="border rounded-lg" style={{borderColor:'var(--colors-border-primary)'}}>
                <summary className="px-3 py-2 cursor-pointer select-none">{n.label}</summary>
                {'items' in n && (
                  <div className="px-3 pb-2">
                    {(n as any).items.map((it: string) => (
                      <a key={it} href="#" className="block px-2 py-1 rounded hover:bg-black/5">{it}</a>
                    ))}
                  </div>
                )}
              </details>
            ))}
            <div className="flex gap-2">
              <a href="#" className="btn flex-1">Log in</a>
              <a href="#" className="btn btn-primary flex-1">Get started</a>
            </div>
          </div>
        </div>
      )}
    </header>
  );
}


