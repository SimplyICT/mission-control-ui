import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const trackerPath = resolve(process.cwd(), "project-tracker", "tasks.json");

const validStatuses = new Set([
  "not_started",
  "in_progress",
  "blocked",
  "review",
  "done"
]);

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const current = argv[i];
    if (!current.startsWith("--")) continue;
    const key = current.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith("--")) {
      args[key] = "true";
      continue;
    }
    args[key] = next;
    i += 1;
  }
  return args;
}

function requireArg(args, key) {
  if (!args[key]) {
    throw new Error(`Missing required argument --${key}`);
  }
  return args[key];
}

async function run() {
  const args = parseArgs(process.argv.slice(2));
  const id = requireArg(args, "id");
  const status = requireArg(args, "status");

  if (!validStatuses.has(status)) {
    throw new Error(`Invalid status '${status}'. Allowed: ${Array.from(validStatuses).join(", ")}`);
  }

  const file = await readFile(trackerPath, "utf8");
  const data = JSON.parse(file);
  const task = data.tasks.find((item) => item.id === id);
  if (!task) {
    throw new Error(`Task '${id}' not found in ${trackerPath}`);
  }

  const timestamp = new Date().toISOString();
  task.status = status;
  task.last_updated = timestamp;

  if (args.owner) task.owner = args.owner;
  if (args.notes) task.notes = args.notes;
  if (args.target_date) task.target_date = args.target_date;

  if (args.proof) {
    task.proof = args.proof
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
  }

  if (task.status === "done" && (!task.proof || task.proof.length === 0)) {
    throw new Error(`Task '${id}' cannot be marked done without at least one proof URL (--proof).`);
  }

  data.meta.last_updated = timestamp;
  await writeFile(trackerPath, `${JSON.stringify(data, null, 2)}\n`, "utf8");
  console.log(`Updated ${id}: ${task.status}`);
}

run().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
