import {
  Center,
  DefaultMantineColor,
  Group,
  Tabs,
  TabsProps,
  Text,
} from "@mantine/core";
import { useLocalStorage } from "@mantine/hooks";
import { FC, useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { Page } from "./page";
import { CircleQuestionMark } from "lucide-react";

export type TabbedPageItem<Tab extends string> = {
  tab: Tab;
  icon?: FC<{ size?: string | number }>;
  content?: FC;
};

export interface TabbedPageProps<Tab extends string> extends TabsProps {
  /** Store current tab on localStorage */
  storageKey: string;
  /**
   * Sync the selected tab with this url query param, so links
   * can target a specific tab, eg. `/settings?tab=secret-providers`.
   * Tabs are matched by slug (lowercased, spaces to '-').
   * The query takes priority over localStorage.
   * Default: "tab". Pass false to disable.
   */
  queryKey?: string | false;
  tabs: TabbedPageItem<Tab>[];
}

/** "Secret Providers" => "secret-providers" */
export function tabSlug(tab: string) {
  return tab.toLowerCase().replace(/\s+/g, "-");
}

export function TabbedPage<Tab extends string>({
  storageKey,
  queryKey = "tab",
  tabs,
  ...tabsProps
}: TabbedPageProps<Tab>) {
  const defaultTab = tabs[0]?.tab;
  const [storedTab, setStoredTab] = useLocalStorage<Tab>({
    key: storageKey,
    defaultValue: defaultTab,
  });

  const [searchParams, setSearchParams] = useSearchParams();
  const querySlug = queryKey ? searchParams.get(queryKey) : null;
  const queryTab = querySlug
    ? tabs.find(({ tab }) => tabSlug(tab) === querySlug)?.tab
    : undefined;

  const selectedTab = queryTab ?? storedTab;
  const setSelectedTab = useCallback(
    (tab: Tab) => {
      setStoredTab(tab);
      if (queryKey) {
        setSearchParams(
          (params) => {
            params.set(queryKey, tabSlug(tab));
            return params;
          },
          { replace: true },
        );
      }
    },
    [queryKey, setStoredTab, setSearchParams],
  );

  const Content =
    tabs.find((tab) => tab.tab === selectedTab)?.content ??
    (() => (
      <Center>
        <CircleQuestionMark size={22} />
      </Center>
    ));
  return (
    <Tabs
      value={selectedTab}
      onChange={(tab) => setSelectedTab((tab as Tab) ?? defaultTab)}
      {...tabsProps}
    >
      <Page
        customTitle={
          <Tabs.List>
            {tabs.map(({ tab, icon }) => {
              const Icon = icon ?? CircleQuestionMark;
              return (
                <Tabs.Tab key={tab} value={tab}>
                  <Group opacity={tab === selectedTab ? 1 : 0.6}>
                    <Icon size={20} />
                    <Text fz="h3">{tab}</Text>
                  </Group>
                </Tabs.Tab>
              );
            })}
          </Tabs.List>
        }
      >
        <Content />
      </Page>
    </Tabs>
  );
}
