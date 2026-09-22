import { Group, GroupProps } from "@mantine/core";
import { ReactNode } from "react";
import { Link, LinkProps } from "react-router-dom";

export interface ItemLinkProps extends Omit<GroupProps, "children"> {
  icon?: ReactNode;
  name: ReactNode;
  to: LinkProps["to"];
  link?: LinkProps;
}

export function ItemLink({
  icon,
  name,
  to,
  link,
  ...groupProps
}: ItemLinkProps) {
  return (
    <Group
      renderRoot={(props) => <Link to={to} {...link} {...props} />}
      gap="0.35rem"
      wrap="nowrap"
      w="fit-content"
      className="hover-underline"
      onClick={(e) => e.stopPropagation()}
      tt="none"
      {...groupProps}
    >
      {icon}
      {name}
    </Group>
  );
}
