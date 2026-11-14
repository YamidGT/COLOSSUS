import { FormEvent, ReactNode, useCallback, useEffect, useState } from "react";
import { Link, Route, Routes, useNavigate, useParams } from "react-router";
import { ApiError, api, setCsrf, text } from "./api";

type Session = { operator: string; csrf_token: string | null };
type Project = {
  project_id: string;
  display_name: string;
  repo_url: string;
  revision: number;
  setup_state: string;
  admission_state: string;
  active_cycle: { cycle_id?: string; status?: string } | null;
  attention_count: number;
  deployment_summary: Record<string, unknown>;
  mirror_summary: Record<string, unknown>;
  cost_summary: Record<string, unknown>;
  feed_freshness: unknown[];
  owner_policy_id: string;
  assurance_profile: string;
  reason: string | null;
};
type ActionItem = {
  action_id: string;
  title: string;
  reason: string;
  kind: string;
};
type Finding = { finding_id?: string; title?: string; status?: string; cwe?: string };
type Gate = {
  gate_id?: string;
  check_profile_id?: string;
  status?: string;
  proof_outcome?: string | null;
  scope?: string[];
  assumptions?: string[];
  reason?: string;
};

function Shell({
  connected,
  children,
}: {
  connected: string;
  children: ReactNode;
}) {
  return (
    <div className="mx-auto min-h-screen max-w-[1200px] px-4 py-6 md:px-6">
      <header className="mb-8 flex h-14 items-center justify-between border-b border-line">
        <div className="flex items-baseline gap-6">
          <Link to="/" className="text-2xl leading-8 font-semibold tracking-tight">
            COLOSSUS
          </Link>
          <span className="text-[13px] leading-[18px] text-muted">Repositories</span>
        </div>
        <p className="text-[13px] leading-[18px] text-muted">{connected}</p>
      </header>
      {children}
    </div>
  );
}

function Banner({ tone, children }: { tone: "bad" | "warn"; children: string }) {
  const cls =
    tone === "bad" ? "bg-bad-tint text-bad" : "bg-warn-tint text-warn";
  return <p className={`rounded-md px-3 py-2 ${cls}`}>{children}</p>;
}

export function App() {
  const [ready, setReady] = useState(false);
  const [signedIn, setSignedIn] = useState(false);
  const [connected, setConnected] = useState("Checking connection");

  useEffect(() => {
    api<Session>("/session")
      .then((session) => {
        setCsrf(session.csrf_token);
        setSignedIn(true);
        setConnected("Connected");
      })
      .catch((error: unknown) => {
        setSignedIn(false);
        setConnected(error instanceof ApiError && error.status === 0 ? "Disconnected" : "Sign in required");
      })
      .finally(() => setReady(true));
  }, []);

  if (!ready) {
    return (
      <Shell connected={connected}>
        <p>Loading</p>
      </Shell>
    );
  }
  if (!signedIn) {
    return (
      <Shell connected={connected}>
        <Login
          onSuccess={() => {
            setSignedIn(true);
            setConnected("Connected");
          }}
        />
      </Shell>
    );
  }
  return (
    <Shell connected={connected}>
      <Routes>
        <Route path="/" element={<Repositories />} />
        <Route path="/projects/:projectId" element={<ProjectPage />} />
        <Route path="/projects/:projectId/cases/:caseId" element={<CasePage />} />
        <Route path="*" element={<p>That page is not available.</p>} />
      </Routes>
    </Shell>
  );
}

function Login({ onSuccess }: { onSuccess: () => void }) {
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      const session = await api<Session>("/sessions/exchange", {
        method: "POST",
        body: JSON.stringify({ code }),
      });
      setCsrf(session.csrf_token);
      onSuccess();
      navigate("/");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Sign in failed");
    }
  }

  return (
    <form onSubmit={submit} className="max-w-md space-y-4">
      <h1 className="text-2xl leading-8">Sign in</h1>
      <p className="text-[13px] leading-[18px] text-muted">
        Paste the one-time code from <span className="font-mono">colossus ui</span>. Provider keys are not entered here.
      </p>
      <label className="block">
        <span className="text-[13px] leading-[18px] text-muted">Login code</span>
        <input
          value={code}
          onChange={(event) => setCode(event.target.value)}
          autoComplete="one-time-code"
          className="mt-1 h-11 w-full rounded-md border border-[#7b8794] bg-surface px-3"
          required
        />
      </label>
      {error ? <Banner tone="bad">{error}</Banner> : null}
      <button type="submit" className="h-11 rounded-md bg-accent px-4 text-white">
        Continue
      </button>
    </form>
  );
}

function Repositories() {
  const [items, setItems] = useState<Project[] | null>(null);
  const [error, setError] = useState("");
  const [url, setUrl] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    try {
      const body = await api<{ items: Project[] }>("/projects");
      setItems(body.items);
      setError("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Disconnected");
    }
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => {
      if (!document.hidden) void load();
    }, 10000);
    void load();
    return () => window.clearInterval(timer);
  }, [load]);

  async function enroll(event: FormEvent) {
    event.preventDefault();
    setNotice("");
    try {
      await api("/projects", { method: "POST", body: JSON.stringify({ repo_url: url }) });
      setUrl("");
      setNotice("Enrollment accepted. Setup continues on the controller.");
      await load();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Enrollment failed");
    }
  }

  return (
    <div className="space-y-8">
      <form onSubmit={enroll} className="flex flex-col gap-3 md:flex-row">
        <label className="grow">
          <span className="sr-only">GitHub repository URL</span>
          <input
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="https://github.com/OWNER/REPO"
            className="h-11 w-full rounded-md border border-[#7b8794] bg-surface px-3"
            required
          />
        </label>
        <button type="submit" className="h-11 rounded-md bg-accent px-4 text-white">
          Add repository
        </button>
      </form>
      {notice ? <Banner tone="warn">{notice}</Banner> : null}
      {error ? <Banner tone="bad">{error}</Banner> : null}
      {items === null ? <p>Loading</p> : null}
      {items && items.length === 0 ? <p>No repositories enrolled.</p> : null}
      <ul className="divide-y divide-line border-y border-line bg-surface">
        {(items || []).map((project) => (
          <li key={project.project_id} className="flex flex-col gap-1 px-3 py-4 md:flex-row md:items-center md:justify-between">
            <div>
              <Link to={`/projects/${project.project_id}`} className="font-medium">
                {text(project.display_name)}
              </Link>
              <p className="font-mono text-[13px] leading-5 text-muted">{text(project.repo_url)}</p>
            </div>
            <p className="text-[13px] leading-[18px] text-muted">
              {text(project.setup_state)} · {text(project.admission_state)} · attention {project.attention_count}
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}

function ProjectPage() {
  const { projectId = "" } = useParams();
  const [project, setProject] = useState<Project | null>(null);
  const [actions, setActions] = useState<ActionItem[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const [status, actionBody, findingBody] = await Promise.all([
        api<Project>(`/projects/${projectId}/status`),
        api<{ items: ActionItem[] }>(`/projects/${projectId}/actions`),
        api<{ items: Finding[] }>(`/projects/${projectId}/findings`),
      ]);
      setProject(status);
      setActions(actionBody.items);
      setFindings(findingBody.items);
      setError("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Disconnected");
    }
  }, [projectId]);

  useEffect(() => {
    const delay = project?.active_cycle ? 2000 : 10000;
    const timer = window.setInterval(() => {
      if (!document.hidden) void load();
    }, delay);
    void load();
    return () => window.clearInterval(timer);
  }, [load, project?.active_cycle]);

  const cost = project?.cost_summary?.reserved;
  return (
    <div className="grid gap-8 lg:grid-cols-[minmax(0,1fr)_280px]">
      <section className="space-y-6">
        <div>
          <h1 className="text-2xl leading-8">{project ? text(project.display_name) : "Loading"}</h1>
          <p className="font-mono text-[13px] leading-5 text-muted">{project ? text(project.repo_url) : ""}</p>
          <p className="text-[13px] leading-[18px] text-muted">
            {project ? `${text(project.owner_policy_id)} · ${text(project.assurance_profile)}` : "Not available"}
          </p>
        </div>
        {error ? <Banner tone="bad">{error}</Banner> : null}
        <div>
          <h2 className="mb-2 text-[13px] leading-[18px] tracking-wide text-muted uppercase">Needs attention</h2>
          {actions.length === 0 ? <p>Nothing needs your attention</p> : null}
          <ul className="divide-y divide-line border-y border-line bg-surface">
            {actions.map((item) => (
              <li key={item.action_id} className="px-3 py-3">
                <p className="font-medium">{text(item.title)}</p>
                <p className="text-[13px] leading-[18px] text-muted">{text(item.reason)}</p>
              </li>
            ))}
          </ul>
        </div>
        <div>
          <h2 className="mb-2 text-[13px] leading-[18px] tracking-wide text-muted uppercase">Findings</h2>
          {findings.length === 0 ? <p>Not available</p> : null}
          <ul className="divide-y divide-line border-y border-line bg-surface">
            {findings.map((finding) => (
              <li key={finding.finding_id || finding.title} className="px-3 py-3">
                <p>{text(finding.title)}</p>
                <p className="text-[13px] leading-[18px] text-muted">
                  {text(finding.status)} {finding.cwe ? `· ${finding.cwe}` : ""}
                </p>
              </li>
            ))}
          </ul>
        </div>
      </section>
      <aside className="space-y-4 text-[13px] leading-[18px]">
        <h2 className="tracking-wide text-muted uppercase">Deployment</h2>
        <p>Setup {project ? text(project.setup_state) : "Not available"}</p>
        <p>Mirror {project && Object.keys(project.mirror_summary).length ? "recorded" : "Not available"}</p>
        <p>Cycle {project?.active_cycle ? text(project.active_cycle.status) : "Not available"}</p>
        <p className="font-mono">Cost reserved {text(cost)}</p>
        <p>Feeds {project ? String(project.feed_freshness.length) : "Not available"}</p>
        {project?.reason ? <p>{project.reason}</p> : null}
      </aside>
    </div>
  );
}

function CasePage() {
  const { projectId = "", caseId = "" } = useParams();
  const [record, setRecord] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api<Record<string, unknown>>(`/cases/${caseId}`)
      .then((body) => {
        setRecord(body);
        setError("");
      })
      .catch((caught: unknown) => setError(caught instanceof Error ? caught.message : "Disconnected"));
  }, [caseId]);

  const gates = Array.isArray(record?.gate_results) ? (record.gate_results as Gate[]) : [];
  return (
    <div className="space-y-6">
      <p className="text-[13px] leading-[18px]">
        <Link to={`/projects/${projectId}`}>Back to repository</Link>
      </p>
      <h1 className="text-2xl leading-8">Case review</h1>
      {error ? <Banner tone="bad">{error}</Banner> : null}
      <p className="font-mono text-[13px] leading-5">{caseId}</p>
      <h2 className="text-[13px] leading-[18px] tracking-wide text-muted uppercase">Gates</h2>
      {gates.length === 0 ? <p>Not available</p> : null}
      <ul className="divide-y divide-line border-y border-line bg-surface">
        {gates.map((gate) => (
          <li key={gate.gate_id || gate.check_profile_id} className="space-y-1 px-3 py-3">
            <p className="font-medium">{text(gate.check_profile_id)}</p>
            <p>
              Status {text(gate.status)} · Proof {text(gate.proof_outcome)}
            </p>
            <p className="text-[13px] leading-[18px] text-muted">
              Scope {gate.scope?.length ? gate.scope.join(", ") : "Not available"}
            </p>
            <p className="text-[13px] leading-[18px] text-muted">
              Assumptions {gate.assumptions?.length ? gate.assumptions.join(", ") : "Not available"}
            </p>
            {gate.reason ? <p>{gate.reason}</p> : null}
          </li>
        ))}
      </ul>
    </div>
  );
}
