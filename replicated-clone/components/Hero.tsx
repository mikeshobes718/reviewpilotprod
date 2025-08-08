export default function Hero() {
  return (
    <section className="relative mt-6">
      <div className="container-1100 grid md:grid-cols-2 gap-10 items-center">
        <div>
          <div className="eyebrow mb-3">Platform</div>
          <h1 className="hero-heading">Ship enterprise-ready software to any environment</h1>
          <p className="body-text mt-3 text-[var(--colors-text-secondary)]">Installers, license management, entitlement, and observability so you can deliver secure, scalable software to customer clusters.</p>
          <div className="mt-6 flex gap-2">
            <a className="btn btn-primary" href="#">Start free</a>
            <a className="btn" href="#">See pricing</a>
          </div>
        </div>
        <div className="card p-3">
          <div className="rounded-xl overflow-hidden aspect-[16/9]">
            <iframe className="w-full h-full" src="https://www.youtube-nocookie.com/embed/3BturV25BsE?rel=0&modestbranding=1" title="Explainer" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowFullScreen />
          </div>
        </div>
      </div>
    </section>
  );
}


