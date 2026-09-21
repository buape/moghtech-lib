import {
  ActionIcon,
  Button,
  Group,
  Modal,
  Stack,
  Table,
  Text,
  Textarea,
  TextInput,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { notifications } from "@mantine/notifications";
import { Page, SearchInput, Section } from "mogh_ui";
import { NotebookText, Pencil, Plus, Trash } from "lucide-react";
import { useEffect, useState } from "react";
import { useInvalidate, useRead, useWrite } from "@/lib/hooks";

export default function Notes() {
  const [query, setQuery] = useState("");
  // `undefined`: closed, `""`: new note, else the id of the note to edit.
  const [editing, setEditing] = useState<string>();
  const notes = useRead("ListNotes", { query });
  const invalidate = useInvalidate();
  const { mutate: deleteNote } = useWrite("DeleteNote", {
    onSuccess: () => {
      invalidate(["ListNotes"], ["GetStats"]);
      notifications.show({ message: "Note deleted.", color: "green" });
    },
  });
  return (
    <Page
      title="Notes"
      icon={NotebookText}
      description="Stored encrypted (mogh_encryption), validated with mogh_validations."
      actions={
        <Group>
          <SearchInput value={query} onSearch={setQuery} />
          <Button
            leftSection={<Plus size="1rem" />}
            onClick={() => setEditing("")}
          >
            New Note
          </Button>
        </Group>
      }
    >
      <Section
        withBorder
        isPending={notes.isPending}
        error={notes.error ? "Failed to load notes" : false}
      >
        {notes.data?.length === 0 && <Text c="dimmed">No notes yet.</Text>}
        <Table>
          <Table.Tbody>
            {notes.data?.map((note) => (
              <Table.Tr key={note.id} data-testid="note-row">
                <Table.Td>
                  <Text fw="bold">{note.title}</Text>
                </Table.Td>
                <Table.Td>
                  <Text size="sm" c="dimmed">
                    {new Date(note.updated_at).toLocaleString()}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Group justify="end" gap="xs">
                    <ActionIcon
                      variant="default"
                      aria-label={`Edit ${note.title}`}
                      onClick={() => setEditing(note.id)}
                    >
                      <Pencil size="1rem" />
                    </ActionIcon>
                    <ActionIcon
                      color="red"
                      aria-label={`Delete ${note.title}`}
                      onClick={() => deleteNote({ id: note.id })}
                    >
                      <Trash size="1rem" />
                    </ActionIcon>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Section>
      <NoteModal id={editing} onClose={() => setEditing(undefined)} />
    </Page>
  );
}

function NoteModal({ id, onClose }: { id?: string; onClose: () => void }) {
  const invalidate = useInvalidate();
  const note = useRead("GetNote", { id: id ?? "" }, { enabled: !!id }).data;
  const form = useForm({
    mode: "controlled",
    initialValues: { title: "", content: "" },
    validate: {
      title: (title) => (title.trim().length ? null : "Title cannot be empty"),
    },
  });
  useEffect(() => {
    if (id === "") form.setValues({ title: "", content: "" });
    else if (note && note.id === id)
      form.setValues({ title: note.title, content: note.content });
  }, [id, note]);

  const onSuccess = () => {
    invalidate(["ListNotes"], ["GetNote"], ["GetStats"]);
    notifications.show({ message: "Note saved.", color: "green" });
    onClose();
  };
  const { mutate: create, isPending: createPending } = useWrite("CreateNote", {
    onSuccess,
  });
  const { mutate: update, isPending: updatePending } = useWrite("UpdateNote", {
    onSuccess,
  });

  return (
    <Modal
      opened={id !== undefined}
      onClose={onClose}
      title={id ? "Edit Note" : "New Note"}
      size="lg"
    >
      <form
        onSubmit={form.onSubmit((values) =>
          id ? update({ id, ...values }) : create(values),
        )}
      >
        <Stack>
          <TextInput
            {...form.getInputProps("title")}
            label="Title"
            placeholder="Note title"
            data-autofocus
          />
          <Textarea
            {...form.getInputProps("content")}
            label="Content"
            autosize
            minRows={6}
          />
          <Group justify="end">
            <Button type="submit" loading={createPending || updatePending}>
              Save
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
