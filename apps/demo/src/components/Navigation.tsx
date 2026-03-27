import Link from "next/link";

export function Navigation() {
  return (
    <nav className="main-nav">
      <div className="nav-container">
        <Link href="/" className="nav-logo">
          🔐 Capsule
        </Link>
        <div className="nav-links">
          <Link href="/spec">Specification</Link>
          <Link href="/glossary">Glossary</Link>
          <Link href="/client">Client</Link>
          <Link href="/server">Server</Link>
          <Link href="/demo">Demo</Link>
          <Link href="/changelog">Changelog</Link>
          <Link href="/roadmap">Roadmap</Link>
        </div>
      </div>
    </nav>
  );
}
