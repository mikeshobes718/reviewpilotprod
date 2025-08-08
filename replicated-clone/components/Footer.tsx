export default function Footer() {
  return (
    <footer className="mt-16 border-t border-white/10">
      <div className="container-1100 py-8 text-center text-white/70">
        © {new Date().getFullYear()} Replicated Clone • <a className="underline" href="#">Privacy</a>
      </div>
    </footer>
  );
}


