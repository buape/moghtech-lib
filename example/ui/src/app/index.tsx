import {
  AppShell,
  Button,
  Group,
  NavLink,
  Text,
  Title,
} from "@mantine/core";
import { LoadingScreen, ThemeToggle } from "mogh_ui";
import {
  Home,
  LogOut,
  NotebookText,
  Settings,
  User,
  Wrench,
} from "lucide-react";
import { Suspense } from "react";
import { Link, Outlet, useLocation } from "react-router-dom";
import { loginTokens, useUser, useUserInvalidate } from "@/lib/hooks";

const PAGES = [
  { to: "/", label: "Home", icon: Home, admin: false },
  { to: "/notes", label: "Notes", icon: NotebookText, admin: false },
  { to: "/tools", label: "Tools", icon: Wrench, admin: false },
  { to: "/profile", label: "Profile", icon: User, admin: false },
  { to: "/settings", label: "Settings", icon: Settings, admin: true },
];

export default function App() {
  const user = useUser().data;
  const userInvalidate = useUserInvalidate();
  const { pathname } = useLocation();
  return (
    <AppShell header={{ height: 62 }} navbar={{ width: 220, breakpoint: 0 }} padding="lg">
      <AppShell.Header>
        <Group h="100%" px="lg" justify="space-between">
          <Title order={3}>Mogh Example</Title>
          <Group>
            <Text data-testid="current-user">{user?.username}</Text>
            <ThemeToggle />
            <Button
              variant="default"
              leftSection={<LogOut size="1rem" />}
              onClick={() => {
                const tokens = loginTokens();
                if (user) tokens.remove(user.id);
                userInvalidate();
                location.replace("/login");
              }}
            >
              Log Out
            </Button>
          </Group>
        </Group>
      </AppShell.Header>
      <AppShell.Navbar p="sm">
        {PAGES.filter((page) => !page.admin || user?.admin).map((page) => (
          <NavLink
            key={page.to}
            component={Link}
            to={page.to}
            label={page.label}
            leftSection={<page.icon size="1rem" />}
            active={pathname === page.to}
          />
        ))}
      </AppShell.Navbar>
      <AppShell.Main>
        <Suspense fallback={<LoadingScreen />}>
          <Outlet />
        </Suspense>
      </AppShell.Main>
    </AppShell>
  );
}
