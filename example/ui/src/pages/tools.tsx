import {
  Button,
  Code,
  Group,
  Select,
  Stack,
  Text,
  Textarea,
  TextInput,
} from "@mantine/core";
import { Page, Section } from "mogh_ui";
import { Types } from "example_client";
import { Wrench } from "lucide-react";
import { useState } from "react";
import { useExecute } from "@/lib/hooks";

export default function Tools() {
  return (
    <Page
      title="Tools"
      icon={Wrench}
      description="The /execute api, one action per crate."
    >
      <KeyPair />
      <Seal />
      <Validate />
    </Page>
  );
}

function KeyPair() {
  const { mutate, data, isPending } = useExecute("GenerateKeyPair");
  return (
    <Section title="Key Pair" titleFz="h3" description="mogh_pki" withBorder>
      <Group>
        <Button variant="default" loading={isPending} onClick={() => mutate({})}>
          Generate Key Pair
        </Button>
      </Group>
      {data && (
        <Stack gap="xs">
          <Text size="sm">
            Public: <Code data-testid="generated-public-key">{data.public_key}</Code>
          </Text>
          <Text size="sm">
            Private: <Code>{data.private_key}</Code>
          </Text>
        </Stack>
      )}
    </Section>
  );
}

function Seal() {
  const [text, setText] = useState("");
  const [sealed, setSealed] = useState("");
  const [opened, setOpened] = useState<string>();
  const { mutate: seal } = useExecute("SealText", {
    onSuccess: ({ sealed }) => setSealed(sealed),
  });
  const { mutate: open } = useExecute("OpenText", {
    onSuccess: ({ text }) => setOpened(text),
  });
  return (
    <Section
      title="Seal Text"
      titleFz="h3"
      description="mogh_encryption: encrypted with the server key, bound to your user."
      withBorder
    >
      <Group align="end">
        <TextInput
          label="Text"
          value={text}
          onChange={(e) => setText(e.target.value)}
          w={300}
        />
        <Button variant="default" onClick={() => seal({ text })}>
          Seal
        </Button>
      </Group>
      <Textarea
        label="Sealed"
        value={sealed}
        onChange={(e) => setSealed(e.target.value)}
        autosize
        minRows={2}
      />
      <Group>
        <Button
          variant="default"
          disabled={!sealed}
          onClick={() => {
            setOpened(undefined);
            open({ sealed });
          }}
        >
          Open
        </Button>
        {opened !== undefined && (
          <Text>
            Opened: <Code data-testid="opened-text">{opened}</Code>
          </Text>
        )}
      </Group>
    </Section>
  );
}

const KINDS = Object.values(Types.ValidateStringKind);

function Validate() {
  const [kind, setKind] = useState<Types.ValidateStringKind>(
    Types.ValidateStringKind.Username,
  );
  const [input, setInput] = useState("");
  const { mutate, data } = useExecute("ValidateString");
  return (
    <Section
      title="Validate"
      titleFz="h3"
      description="mogh_validations"
      withBorder
    >
      <Group align="end">
        <Select
          label="As"
          data={KINDS}
          value={kind}
          allowDeselect={false}
          onChange={(kind) => kind && setKind(kind as Types.ValidateStringKind)}
        />
        <TextInput
          label="Input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          w={300}
        />
        <Button variant="default" onClick={() => mutate({ kind, input })}>
          Validate
        </Button>
      </Group>
      {data && (
        <Text data-testid="validation-result" c={data.valid ? "green" : "red"}>
          {data.valid ? "Valid" : data.error}
        </Text>
      )}
    </Section>
  );
}
