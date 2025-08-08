type Feature = { title: string; body: string };
const FEATURES: Feature[] = [
  { title: 'K8s installers', body: 'Create reliable installers for customer clusters across clouds and air-gapped.' },
  { title: 'License & entitlement', body: 'Gate features, plans, and usage with powerful licensing APIs.' },
  { title: 'Observability', body: 'Gather customer environment signals to support upgrades with confidence.' },
];

export default function FeatureGrid() {
  return (
    <section className="container-1100 mt-10 grid md:grid-cols-3 gap-4">
      {FEATURES.map((f) => (
        <div key={f.title} className="card p-5">
          <h3 className="card-title mb-2">{f.title}</h3>
          <p className="text-[var(--colors-text-secondary)] body-text text-[16px] leading-6">{f.body}</p>
        </div>
      ))}
    </section>
  );
}


