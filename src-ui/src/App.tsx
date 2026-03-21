import { startTransition, useDeferredValue, useEffect, useState } from "react";
import "./App.css";
import { type AppStatus, type ProjectSummary, useTauri } from "./hooks/useTauri";

function formatStateLabel(state: AppStatus["state"]) {
  switch (state) {
    case "unlocked":
      return "Session active";
    case "locked":
      return "Vault locked";
    case "missing":
      return "Vault missing";
  }
}

function formatSession(minutes: number | null) {
  if (minutes === null) {
    return "Awaiting daemon";
  }

  const hours = Math.floor(minutes / 60);
  const remainder = minutes % 60;
  return `${hours}h ${remainder}m remaining`;
}

function App() {
  const tauri = useTauri();
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [selectedProject, setSelectedProject] = useState<string | null>(null);
  const deferredProject = useDeferredValue(selectedProject);
  const [keys, setKeys] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(true);

  useEffect(() => {
    let active = true;

    async function loadWorkspace() {
      setIsRefreshing(true);
      setError(null);

      try {
        const nextStatus = await tauri.invoke<AppStatus>("app_status");
        if (!active) {
          return;
        }

        startTransition(() => {
          setStatus(nextStatus);
        });

        if (nextStatus.state !== "unlocked") {
          startTransition(() => {
            setProjects([]);
            setSelectedProject(null);
            setKeys([]);
          });
          return;
        }

        const nextProjects = await tauri.invoke<ProjectSummary[]>("list_projects");
        if (!active) {
          return;
        }

        startTransition(() => {
          setProjects(nextProjects);
          setSelectedProject((current) => {
            if (current && nextProjects.some((project) => project.name === current)) {
              return current;
            }
            if (nextStatus.defaultProject) {
              const defaultProject = nextProjects.find(
                (project) => project.name === nextStatus.defaultProject,
              );
              if (defaultProject) {
                return defaultProject.name;
              }
            }
            return nextProjects[0]?.name ?? null;
          });
        });
      } catch (loadError) {
        if (!active) {
          return;
        }
        setError(loadError instanceof Error ? loadError.message : String(loadError));
      } finally {
        if (active) {
          setIsRefreshing(false);
        }
      }
    }

    void loadWorkspace();
    return () => {
      active = false;
    };
  }, [tauri]);

  useEffect(() => {
    let active = true;

    async function loadKeys() {
      if (!deferredProject || status?.state !== "unlocked") {
        setKeys([]);
        return;
      }

      try {
        const nextKeys = await tauri.invoke<string[]>("list_project_keys", {
          project: deferredProject,
        });
        if (!active) {
          return;
        }
        startTransition(() => {
          setKeys(nextKeys);
        });
      } catch (loadError) {
        if (!active) {
          return;
        }
        setError(loadError instanceof Error ? loadError.message : String(loadError));
      }
    }

    void loadKeys();
    return () => {
      active = false;
    };
  }, [deferredProject, status?.state, tauri]);

  const stateLabel = formatStateLabel(status?.state ?? "locked");
  const keyCountLabel =
    status?.state === "unlocked" ? `${keys.length} key names visible` : "Read-only shell";

  return (
    <main className="app-shell">
      <div className="ambient ambient-left" aria-hidden="true" />
      <div className="ambient ambient-right" aria-hidden="true" />

      <header className="masthead">
        <div>
          <p className="eyebrow">Local-first secret runtime</p>
          <h1>LokalVault</h1>
        </div>
        <div className="status-cluster">
          <span className={`signal signal-${status?.state ?? "locked"}`} />
          <div>
            <p className="label">Bridge</p>
            <strong>{tauri.runtimeLabel}</strong>
          </div>
        </div>
      </header>

      <section className="topline">
        <div>
          <p className="label">Workspace state</p>
          <strong>{stateLabel}</strong>
          <p>{status?.daemonRunning ? "Daemon is serving sanitized metadata." : "Unlock to expose project summaries and key names."}</p>
        </div>
        <dl>
          <div>
            <dt>Projects</dt>
            <dd>{status?.projectCount ?? 0}</dd>
          </div>
          <div>
            <dt>Session</dt>
            <dd>{formatSession(status?.estimatedSessionRemainingMinutes ?? null)}</dd>
          </div>
          <div>
            <dt>Version</dt>
            <dd>{status?.version ?? "loading"}</dd>
          </div>
        </dl>
      </section>

      <section className="workspace">
        <aside className="rail">
          <div>
            <p className="label">Focus</p>
            <h2>Session</h2>
          </div>
          <ul className="meta-list">
            <li>
              <span>Vault</span>
              <strong>{status?.vaultExists ? "Present" : "Not created"}</strong>
            </li>
            <li>
              <span>Default project</span>
              <strong>{status?.defaultProject ?? "Unset"}</strong>
            </li>
            <li>
              <span>Env warning</span>
              <strong>{status?.dotenvWarning ? ".env detected" : "Clean"}</strong>
            </li>
          </ul>
          <button className="refresh-button" type="button" onClick={() => window.location.reload()}>
            {isRefreshing ? "Refreshing" : "Refresh shell"}
          </button>
        </aside>

        <section className="project-pane">
          <div className="pane-header">
            <div>
              <p className="label">Project index</p>
              <h2>Available projects</h2>
            </div>
            <span className="hint">{status?.state === "unlocked" ? "Name + key counts only" : "Locked until daemon session exists"}</span>
          </div>

          <div className="project-list" role="list" aria-label="Projects">
            {projects.length === 0 ? (
              <div className="empty-state">
                <strong>No project metadata available</strong>
                <p>When the daemon is unlocked, this column lists project names and per-project key counts without exposing values.</p>
              </div>
            ) : (
              projects.map((project, index) => (
                <button
                  key={project.name}
                  className={`project-row ${project.name === selectedProject ? "selected" : ""}`}
                  type="button"
                  style={{ animationDelay: `${index * 70}ms` }}
                  onClick={() => setSelectedProject(project.name)}
                >
                  <span>{project.name}</span>
                  <strong>{project.secretCount} keys</strong>
                </button>
              ))
            )}
          </div>
        </section>

        <aside className="detail-pane">
          <div className="pane-header">
            <div>
              <p className="label">Inspector</p>
              <h2>{selectedProject ?? "No project selected"}</h2>
            </div>
            <span className="hint">{keyCountLabel}</span>
          </div>

          <div className="detail-copy">
            <p>
              This first shell proves the Tauri bridge, keeps secrets inside the existing CLI and daemon boundaries, and only surfaces read-only metadata to the renderer.
            </p>
          </div>

          <ul className="key-list" aria-label="Project keys">
            {keys.length === 0 ? (
              <li className="key-empty">Key names appear here after selecting an unlocked project.</li>
            ) : (
              keys.map((key) => <li key={key}>{key}</li>)
            )}
          </ul>
        </aside>
      </section>

      {error ? <p className="error-banner">{error}</p> : null}
    </main>
  );
}

export default App;
