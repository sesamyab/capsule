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
          <Link href="/client">Client</Link>
          <Link href="/servers">Servers</Link>
          <Link href="/demo">Demo</Link>
        </div>
      </div>
    </nav>
  );
}
