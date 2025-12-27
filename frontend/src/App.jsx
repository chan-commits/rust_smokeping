import { useCallback, useEffect, useMemo, useState } from "react";

const translations = {
  en: {
    app_title: "Rust SmokePing",
    app_tagline: "Premium latency observability with agents.",
    settings_title: "Settings",
    interval_label: "Interval",
    timeout_label: "Timeout",
    mtr_runs_label: "MTR Runs",
    interval_seconds: "Interval Seconds",
    timeout_seconds: "Timeout Seconds",
    mtr_runs_input: "MTR Runs",
    update_button: "Update",
    add_target_title: "Add Target",
    target_name: "Name",
    target_name_placeholder: "edge-sg-1",
    target_address: "Address",
    target_address_placeholder: "203.0.113.10",
    target_category: "Category",
    target_category_placeholder: "core",
    target_sort_order: "Sort Order",
    add_button: "Add",
    register_agent_title: "Register Agent",
    agent_name: "Name",
    agent_name_placeholder: "edge-sg-1",
    agent_ip: "Agent IP",
    agent_ip_placeholder: "203.0.113.10",
    register_button: "Register",
    agents_title: "Agents",
    delete_button: "Delete",
    last_seen: "Last seen",
    measurement_time: "Time",
    measurement_agent: "Agent",
    measurement_latency: "Latency",
    measurement_loss: "Packet loss",
    measurement_success: "Success",
    measurement_mtr: "MTR Output",
    measurement_traceroute: "Traceroute Output",
    no_measurements: "No measurements yet.",
    success_yes: "Yes",
    success_no: "No",
    loading: "Loading data...",
    load_error: "Failed to load API data.",
    setup_hint: "If this is a 401, configure HTTP Basic auth or complete setup at",
    never: "never"
  },
  zh: {
    app_title: "Rust SmokePing",
    app_tagline: "使用代理的高质量延迟观测。",
    settings_title: "设置",
    interval_label: "间隔",
    timeout_label: "超时",
    mtr_runs_label: "MTR 次数",
    interval_seconds: "间隔（秒）",
    timeout_seconds: "超时（秒）",
    mtr_runs_input: "MTR 次数",
    update_button: "更新",
    add_target_title: "添加目标",
    target_name: "名称",
    target_name_placeholder: "edge-sg-1",
    target_address: "地址",
    target_address_placeholder: "203.0.113.10",
    target_category: "分类",
    target_category_placeholder: "core",
    target_sort_order: "排序",
    add_button: "添加",
    register_agent_title: "注册代理",
    agent_name: "名称",
    agent_name_placeholder: "edge-sg-1",
    agent_ip: "代理 IP",
    agent_ip_placeholder: "203.0.113.10",
    register_button: "注册",
    agents_title: "代理列表",
    delete_button: "删除",
    last_seen: "最近在线",
    measurement_time: "时间",
    measurement_agent: "代理",
    measurement_latency: "延迟",
    measurement_loss: "丢包率",
    measurement_success: "成功",
    measurement_mtr: "MTR 输出",
    measurement_traceroute: "Traceroute 输出",
    no_measurements: "暂无测量数据。",
    success_yes: "是",
    success_no: "否",
    loading: "加载数据中...",
    load_error: "加载 API 数据失败。",
    setup_hint: "如果遇到 401，请配置 HTTP Basic 认证或访问",
    never: "从未"
  }
};

const initialState = {
  agents: [],
  targets: [],
  config: null,
  measurements: []
};

const buildUrl = (path) => new URL(path, window.location.href).toString();

const request = async (path, options = {}) => {
  const response = await fetch(buildUrl(path), {
    ...options,
    headers: {
      ...(options.headers || {})
    }
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed: ${response.status}`);
  }

  return response;
};

const requestJson = async (path) => {
  const response = await request(path, {
    headers: {
      Accept: "application/json"
    }
  });
  return response.json();
};

export default function App() {
  const [data, setData] = useState(initialState);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lang] = useState(() => (navigator.language || "en").toLowerCase());
  const dict = useMemo(
    () => (lang.startsWith("zh") ? translations.zh : translations.en),
    [lang]
  );
  const t = useCallback((key) => dict[key] ?? key, [dict]);
  const setupPath = useMemo(
    () => new URL("setup", window.location.href).pathname,
    []
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [agents, targets, config, measurements] = await Promise.all([
        requestJson("api/agents"),
        requestJson("api/targets"),
        requestJson("api/config"),
        requestJson("api/measurements/latest")
      ]);
      setData({ agents, targets, config, measurements });
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const measurementMap = useMemo(() => {
    const map = new Map();
    data.measurements.forEach((measurement) => {
      map.set(
        `${measurement.agent_id}-${measurement.target_id}`,
        measurement
      );
    });
    return map;
  }, [data.measurements]);

  const formatTimestamp = (timestamp) => {
    if (!timestamp) {
      return t("never");
    }
    const date = new Date(timestamp * 1000);
    if (Number.isNaN(date.getTime())) {
      return t("never");
    }
    return date.toISOString();
  };

  const handleConfigSubmit = async (event) => {
    event.preventDefault();
    const form = event.target;
    await request("api/config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        interval_seconds: Number(form.interval_seconds.value || 60),
        timeout_seconds: Number(form.timeout_seconds.value || 10),
        mtr_runs: Number(form.mtr_runs.value || 10)
      })
    });
    load();
  };

  const handleTargetSubmit = async (event) => {
    event.preventDefault();
    const form = event.target;
    await request("api/targets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: form.name.value,
        address: form.address.value,
        category: form.category.value,
        sort_order: Number(form.sort_order.value || 0)
      })
    });
    form.reset();
    load();
  };

  const handleAgentSubmit = async (event) => {
    event.preventDefault();
    const form = event.target;
    await request("api/agents", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: form.name.value,
        address: form.address.value
      })
    });
    form.reset();
    load();
  };

  const handleDeleteTarget = async (id) => {
    await request(`api/targets/${id}`, { method: "DELETE" });
    load();
  };

  const handleDeleteAgent = async (id) => {
    await request(`api/agents/${id}`, { method: "DELETE" });
    load();
  };

  return (
    <div className="app">
      <header>
        <h1>{t("app_title")}</h1>
        <p>{t("app_tagline")}</p>
      </header>

      <main>
        {loading && (
          <section className="card">
            <p>{t("loading")}</p>
          </section>
        )}
        {error && (
          <section className="card error">
            <p>{t("load_error")}</p>
            <p>{error.message}</p>
            <p>
              {t("setup_hint")} <code>{setupPath}</code>.
            </p>
          </section>
        )}

        <section className="card">
          <h2>{t("settings_title")}</h2>
          <div className="pill-group">
            <span className="pill">
              {t("interval_label")}: {data.config?.interval_seconds ?? "-"}s
            </span>
            <span className="pill">
              {t("timeout_label")}: {data.config?.timeout_seconds ?? "-"}s
            </span>
            <span className="pill">
              {t("mtr_runs_label")}: {data.config?.mtr_runs ?? "-"}
            </span>
          </div>
          <form className="grid" onSubmit={handleConfigSubmit}>
            <label>
              <span>{t("interval_seconds")}</span>
              <input
                name="interval_seconds"
                type="number"
                defaultValue={data.config?.interval_seconds ?? 60}
              />
            </label>
            <label>
              <span>{t("timeout_seconds")}</span>
              <input
                name="timeout_seconds"
                type="number"
                defaultValue={data.config?.timeout_seconds ?? 10}
              />
            </label>
            <label>
              <span>{t("mtr_runs_input")}</span>
              <input
                name="mtr_runs"
                type="number"
                min="1"
                defaultValue={data.config?.mtr_runs ?? 10}
              />
            </label>
            <div>
              <button type="submit">{t("update_button")}</button>
            </div>
          </form>
        </section>

        <section className="card">
          <h2>{t("add_target_title")}</h2>
          <form className="grid" onSubmit={handleTargetSubmit}>
            <label>
              <span>{t("target_name")}</span>
              <input
                name="name"
                placeholder={t("target_name_placeholder")}
                required
              />
            </label>
            <label>
              <span>{t("target_address")}</span>
              <input
                name="address"
                placeholder={t("target_address_placeholder")}
                required
              />
            </label>
            <label>
              <span>{t("target_category")}</span>
              <input
                name="category"
                placeholder={t("target_category_placeholder")}
                required
              />
            </label>
            <label>
              <span>{t("target_sort_order")}</span>
              <input name="sort_order" type="number" defaultValue={0} />
            </label>
            <div>
              <button type="submit">{t("add_button")}</button>
            </div>
          </form>
        </section>

        <section className="card">
          <h2>{t("register_agent_title")}</h2>
          <form className="grid" onSubmit={handleAgentSubmit}>
            <label>
              <span>{t("agent_name")}</span>
              <input
                name="name"
                placeholder={t("agent_name_placeholder")}
                required
              />
            </label>
            <label>
              <span>{t("agent_ip")}</span>
              <input
                name="address"
                placeholder={t("agent_ip_placeholder")}
                required
              />
            </label>
            <div>
              <button className="secondary" type="submit">
                {t("register_button")}
              </button>
            </div>
          </form>
        </section>

        <section className="card">
          <h2>{t("agents_title")}</h2>
          <ul className="agent-list">
            {data.agents.map((agent) => (
              <li key={agent.id}>
                <details className="agent-toggle">
                  <summary>
                    <div className="agent-summary">
                      <div className="agent-meta">
                        <strong>{agent.name}</strong>
                        <div className="pill">{agent.address}</div>
                      </div>
                      <div className="agent-actions">
                        <span className="pill">
                          {t("last_seen")}: {formatTimestamp(agent.last_seen)}
                        </span>
                        <button
                          className="danger"
                          type="button"
                          onClick={(event) => {
                            event.stopPropagation();
                            handleDeleteAgent(agent.id);
                          }}
                        >
                          {t("delete_button")}
                        </button>
                      </div>
                    </div>
                  </summary>
                  <ul className="targets">
                    {data.targets.map((target) => {
                      const measurement = measurementMap.get(
                        `${agent.id}-${target.id}`
                      );
                      const avgMs = measurement?.avg_ms;
                      const packetLoss = measurement?.packet_loss;
                      return (
                        <li key={target.id}>
                          <details className="target-toggle">
                            <summary>
                              <div className="target-summary">
                                <div className="target-info">
                                  <span className="target-name">
                                    {target.name}
                                  </span>
                                  <span className="target-address">
                                    {target.address} · {target.category}
                                  </span>
                                </div>
                                <div className="graph-links">
                                  <a
                                    className="link"
                                    href={buildUrl(
                                      `graph/${target.id}?range=1h`
                                    )}
                                  >
                                    1h
                                  </a>
                                  <a
                                    className="link"
                                    href={buildUrl(
                                      `graph/${target.id}?range=3h`
                                    )}
                                  >
                                    3h
                                  </a>
                                  <a
                                    className="link"
                                    href={buildUrl(
                                      `graph/${target.id}?range=1d`
                                    )}
                                  >
                                    1d
                                  </a>
                                  <a
                                    className="link"
                                    href={buildUrl(
                                      `graph/${target.id}?range=7d`
                                    )}
                                  >
                                    7d
                                  </a>
                                  <a
                                    className="link"
                                    href={buildUrl(
                                      `graph/${target.id}?range=1m`
                                    )}
                                  >
                                    1m
                                  </a>
                                  <button
                                    className="danger"
                                    type="button"
                                    onClick={(event) => {
                                      event.stopPropagation();
                                      handleDeleteTarget(target.id);
                                    }}
                                  >
                                    {t("delete_button")}
                                  </button>
                                </div>
                              </div>
                            </summary>
                            <div className="target-body">
                              <img
                                className="graph"
                                src={buildUrl(
                                  `graph/${target.id}?range=1h`
                                )}
                                alt="Latency graph"
                              />
                              {measurement ? (
                                <div className="measurement">
                                  <div className="pill-group">
                                    <span className="pill">
                                      {t("measurement_time")}: {formatTimestamp(
                                        measurement.timestamp
                                      )}
                                    </span>
                                    <span className="pill">
                                      {t("measurement_agent")}: {measurement.agent_name}
                                    </span>
                                    <span className="pill">
                                      {t("measurement_latency")}: {avgMs?.toFixed(2) ?? "-"} ms
                                    </span>
                                    <span className="pill">
                                      {t("measurement_loss")}: {packetLoss?.toFixed(2) ?? "-"}%
                                    </span>
                                    <span className="pill">
                                      {t("measurement_success")}: {measurement.success === 1
                                        ? t("success_yes")
                                        : t("success_no")}
                                    </span>
                                  </div>
                                  <details>
                                    <summary>{t("measurement_mtr")}</summary>
                                    <pre>{measurement.mtr}</pre>
                                  </details>
                                  <details>
                                    <summary>{t("measurement_traceroute")}</summary>
                                    <pre>{measurement.traceroute}</pre>
                                  </details>
                                </div>
                              ) : (
                                <div className="measurement">
                                  <em>{t("no_measurements")}</em>
                                </div>
                              )}
                            </div>
                          </details>
                        </li>
                      );
                    })}
                  </ul>
                </details>
              </li>
            ))}
          </ul>
        </section>
      </main>
    </div>
  );
}
