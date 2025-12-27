import { useEffect, useState } from "react";

const emptyState = {
  agents: [],
  targets: [],
  config: null,
  error: null,
  loading: true
};

async function fetchJson(path) {
  const response = await fetch(path, {
    headers: {
      Accept: "application/json"
    }
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed: ${response.status}`);
  }

  return response.json();
}

export default function App() {
  const [state, setState] = useState(emptyState);

  useEffect(() => {
    let active = true;

    const load = async () => {
      try {
        const [agents, targets, config] = await Promise.all([
          fetchJson("/api/agents"),
          fetchJson("/api/targets"),
          fetchJson("/api/config")
        ]);

        if (active) {
          setState({
            agents,
            targets,
            config,
            error: null,
            loading: false
          });
        }
      } catch (error) {
        if (active) {
          setState((prev) => ({
            ...prev,
            error,
            loading: false
          }));
        }
      }
    };

    load();

    return () => {
      active = false;
    };
  }, []);

  return (
    <div className="app">
      <header className="hero">
        <h1>Rust SmokePing</h1>
        <p>
          React + Vite frontend served by Axum. Build once to ship a single
          executable.
        </p>
      </header>

      <section className="panel">
        <h2>Status</h2>
        {state.loading ? (
          <p>Loading API data...</p>
        ) : state.error ? (
          <div className="error">
            <strong>API Error:</strong> {state.error.message}
            <p>
              If this is a 401, configure HTTP Basic auth or complete setup at
              <code> /setup</code>.
            </p>
          </div>
        ) : (
          <div className="stats">
            <div>
              <span className="label">Agents</span>
              <span className="value">{state.agents.length}</span>
            </div>
            <div>
              <span className="label">Targets</span>
              <span className="value">{state.targets.length}</span>
            </div>
            <div>
              <span className="label">Interval (s)</span>
              <span className="value">{state.config?.interval_seconds}</span>
            </div>
          </div>
        )}
      </section>

      <section className="panel">
        <h2>Next Steps</h2>
        <ul>
          <li>Run the Rust server on <code>0.0.0.0:8080</code>.</li>
          <li>
            Use <code>npm run dev</code> to develop the frontend separately.
          </li>
          <li>
            Execute <code>./build.sh</code> to bundle frontend assets into the
            binary.
          </li>
        </ul>
      </section>
    </div>
  );
}
