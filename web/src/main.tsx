import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { AppLayout } from "@/components/layout";
import { HomePage } from "@/pages/home";
import { RemediationPage, RemediationsPage } from "@/pages/remediation";
import { ScanPage } from "@/pages/scan";
import "./index.css";

const rootRoute = createRootRoute({ component: AppLayout });

const homeRoute = createRoute({ getParentRoute: () => rootRoute, path: "/", component: HomePage });

const scanRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/scans/$name",
  component: function ScanRoute() {
    const { name } = scanRoute.useParams();
    return <ScanPage name={name} />;
  },
});

const remediationsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/remediations", component: RemediationsPage });

const remediationRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/remediations/$name",
  component: function RemediationRoute() {
    const { name } = remediationRoute.useParams();
    return <RemediationPage name={name} />;
  },
});

const router = createRouter({
  routeTree: rootRoute.addChildren([homeRoute, scanRoute, remediationsRoute, remediationRoute]),
  defaultPreload: "intent",
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 10_000, retry: 1, refetchOnWindowFocus: false } },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);
