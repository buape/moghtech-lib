import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Notifications } from "@mantine/notifications";
import { setAuthUrl, ThemeProvider } from "mogh_ui";
import { Router } from "@/router";

import "@mantine/core/styles.css";
// ‼️ import notifications styles after core package styles
import "@mantine/notifications/styles.css";
// Import local css after to avoid mantine default body color flash.
import "./index.scss";
import "mogh_ui/index.scss";

export const EXAMPLE_BASE_URL =
  import.meta.env.VITE_EXAMPLE_HOST || location.origin;

const client = new QueryClient({
  defaultOptions: { queries: { retry: false } },
});

// mogh_ui talks to the auth api on its own, it only needs the url.
setAuthUrl(EXAMPLE_BASE_URL + "/auth");

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <QueryClientProvider client={client}>
      <ThemeProvider>
        <Router />
        <Notifications />
      </ThemeProvider>
    </QueryClientProvider>
  </React.StrictMode>,
);
