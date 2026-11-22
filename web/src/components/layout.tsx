import { Link, Outlet } from "@tanstack/react-router";
import { Moon, Sun } from "lucide-react";
import { useEffect, useState } from "react";
import { Toaster } from "sonner";
import { Button } from "@/components/ui/button";

type Theme = "light" | "dark";

function initialTheme(): Theme {
  try {
    const saved = localStorage.getItem("cassandra-theme");
    if (saved === "light" || saved === "dark") return saved;
  } catch {
    // Storage may be unavailable; fall back to the OS preference.
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function AppLayout() {
  const [theme, setTheme] = useState<Theme>(initialTheme);
  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    try {
      localStorage.setItem("cassandra-theme", theme);
    } catch {
      // Not persisting the theme is harmless.
    }
  }, [theme]);

  return (
    <div className="flex h-dvh flex-col">
      <header className="flex h-14 shrink-0 items-center gap-6 border-b bg-card px-4 sm:px-6">
        <Link to="/" className="flex items-center gap-2 font-semibold">
          <img src="/favicon.svg" alt="" className="size-7" />
          Cassandra
        </Link>
        <nav className="flex items-center gap-1 text-sm">
          <Link to="/" className="rounded-md px-3 py-1.5 text-muted-foreground hover:text-foreground [&.active]:bg-muted [&.active]:text-foreground" activeOptions={{ exact: true }}>
            스캔
          </Link>
          <Link to="/remediations" className="rounded-md px-3 py-1.5 text-muted-foreground hover:text-foreground [&.active]:bg-muted [&.active]:text-foreground">
            조치
          </Link>
        </nav>
        <div className="ml-auto">
          <Button variant="ghost" size="icon" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label="테마 전환">
            {theme === "dark" ? <Sun /> : <Moon />}
          </Button>
        </div>
      </header>
      <main className="min-h-0 flex-1 overflow-auto">
        <Outlet />
      </main>
      <Toaster theme={theme} richColors position="bottom-right" />
    </div>
  );
}
