import { Breadcrumbs, BreadcrumbsProps, Text, TextProps } from "@mantine/core";
import { ReactNode } from "react";
import { Link } from "react-router-dom";

export interface Crumb extends TextProps {
  label: ReactNode;
  to?: string;
}

export interface PageBreadcrumbsProps extends Omit<
  BreadcrumbsProps,
  "children"
> {
  items: Crumb[];
}

export function PageBreadcrumbs({
  items,
  ...breadcrumbsProps
}: PageBreadcrumbsProps) {
  return (
    <Breadcrumbs separatorMargin="xs" visibleFrom="sm" {...breadcrumbsProps}>
      {items.map(({ label, to, ...textProps }, i) =>
        to ? (
          <Text
            key={i}
            className="hover-underline"
            c="dimmed"
            fz="sm"
            maw={200}
            truncate
            renderRoot={(props) => <Link to={to} {...props} />}
            {...textProps}
          >
            {label}
          </Text>
        ) : (
          <Text key={i} fz="sm" maw={200} truncate {...textProps}>
            {label}
          </Text>
        ),
      )}
    </Breadcrumbs>
  );
}
