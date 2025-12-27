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
    last_seen: "Online for",
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
    never: "never",
    agent_status_online: "Online",
    agent_status_offline: "Offline",
    loss_alert: "Loss > 10%",
    last_loss: "Last loss",
    select_agent: "Select an agent",
    agent_overview: "Agent overview",
    timezone_label: "Timezone",
    timezone_local: "Local",
    auto_target_title: "Auto Target",
    auto_target_hint: "Scan a range and use the first reachable IP.",
    auto_octet1: "Octet 1",
    auto_octet2: "Octet 2",
    auto_third_start: "Third start",
    auto_third_end: "Third end",
    auto_name: "Name (optional)",
    auto_category: "Category",
    auto_sort_order: "Sort Order",
    auto_target_button: "Auto add"
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
    last_seen: "已在线",
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
    never: "从未",
    agent_status_online: "在线",
    agent_status_offline: "离线",
    loss_alert: "丢包 > 10%",
    last_loss: "上次丢包",
    select_agent: "选择代理",
    agent_overview: "代理概览",
    timezone_label: "时区",
    timezone_local: "本地",
    auto_target_title: "自动添加目标",
    auto_target_hint: "扫描范围并选择第一个响应的 IP。",
    auto_octet1: "第一段",
    auto_octet2: "第二段",
    auto_third_start: "第三段起始",
    auto_third_end: "第三段结束",
    auto_name: "名称（可选）",
    auto_category: "分类",
    auto_sort_order: "排序",
    auto_target_button: "自动探测"
  }
};

const initialState = {
  agents: [],
  targets: [],
  config: null,
  measurements: []
};

const buildBaseUrl = () => {
  const basePath = window.location.pathname.endsWith("/")
    ? window.location.pathname
    : `${window.location.pathname}/`;
  return `${window.location.origin}${basePath}`;
};

const buildUrl = (path) => new URL(path, buildBaseUrl()).toString();
const TIMEZONE_STORAGE_KEY = "smokeping.timezone";
const TIMEZONE_OPTIONS = [
  { value: "local", labelKey: "timezone_local" },
  { value: "UTC", label: "UTC" },
  { value: "Asia/Shanghai", label: "Asia/Shanghai" },
  { value: "Asia/Singapore", label: "Asia/Singapore" },
  { value: "Asia/Tokyo", label: "Asia/Tokyo" },
  { value: "Europe/London", label: "Europe/London" },
  { value: "America/New_York", label: "America/New_York" },
  { value: "America/Los_Angeles", label: "America/Los_Angeles" }
];

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
  const [selectedAgentId, setSelectedAgentId] = useState(null);
  const [targetRanges, setTargetRanges] = useState({});
  const [timeZone, setTimeZone] = useState(() => {
    const saved = localStorage.getItem(TIMEZONE_STORAGE_KEY);
    if (saved) {
      return saved;
    }
    return Intl.DateTimeFormat().resolvedOptions().timeZone ?? "UTC";
  });
  const [lang] = useState(() => (navigator.language || "en").toLowerCase());
  const dict = useMemo(
    () => (lang.startsWith("zh") ? translations.zh : translations.en),
    [lang]
  );
  const t = useCallback((key) => dict[key] ?? key, [dict]);
  const setupPath = useMemo(
    () => new URL("setup", buildBaseUrl()).pathname,
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

  useEffect(() => {
    localStorage.setItem(TIMEZONE_STORAGE_KEY, timeZone);
  }, [timeZone]);

  useEffect(() => {
    if (!selectedAgentId && data.agents.length > 0) {
      setSelectedAgentId(data.agents[0].id);
    }
  }, [data.agents, selectedAgentId]);

  const selectedAgent = useMemo(
    () => data.agents.find((agent) => agent.id === selectedAgentId) ?? null,
    [data.agents, selectedAgentId]
  );

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

  const lastLossMeasurement = useMemo(() => {
    if (!selectedAgentId) {
      return null;
    }
    const cutoff = Date.now() / 1000 - 60 * 60 * 3;
    let latest = null;
    data.measurements.forEach((measurement) => {
      if (measurement.agent_id !== selectedAgentId) {
        return;
      }
      const lossTimestamp = measurement.last_loss_timestamp;
      if (!lossTimestamp || lossTimestamp < cutoff) {
        return;
      }
      if (!latest || lossTimestamp > latest.timestamp) {
        latest = { targetId: measurement.target_id, timestamp: lossTimestamp };
      }
    });
    return latest;
  }, [data.measurements, selectedAgentId]);

  const timestampFormatter = useMemo(() => {
    const options = {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false
    };
    if (timeZone !== "local") {
      options.timeZone = timeZone;
    }
    return new Intl.DateTimeFormat(lang, options);
  }, [lang, timeZone]);

  const formatTimestamp = (timestamp) => {
    if (!timestamp) {
      return t("never");
    }
    const date = new Date(timestamp * 1000);
    if (Number.isNaN(date.getTime())) {
      return t("never");
    }
    return timestampFormatter.format(date);
  };

  const formatMetric = (value) => (value ?? 0).toFixed(2);
  const formatDuration = (timestamp) => {
    if (!timestamp) {
      return t("never");
    }
    const lastSeenMs = timestamp * 1000;
    if (Number.isNaN(lastSeenMs)) {
      return t("never");
    }
    const diffMs = Math.max(Date.now() - lastSeenMs, 0);
    const totalMinutes = Math.floor(diffMs / (60 * 1000));
    const days = Math.floor(totalMinutes / (60 * 24));
    const hours = Math.floor((totalMinutes % (60 * 24)) / 60);
    const minutes = totalMinutes % 60;
    if (lang.startsWith("zh")) {
      if (days > 0) {
        return `${days}天${hours}小时${minutes}分钟`;
      }
      if (hours > 0) {
        return `${hours}小时${minutes}分钟`;
      }
      return `${minutes}分钟`;
    }
    if (days > 0) {
      return `${days}d ${hours}h ${minutes}m`;
    }
    if (hours > 0) {
      return `${hours}h ${minutes}m`;
    }
    return `${minutes}m`;
  };
  const isAgentOffline = (agent) => {
    if (!agent?.last_seen) {
      return true;
    }
    const lastSeenMs = agent.last_seen * 1000;
    return Date.now() - lastSeenMs > 5 * 60 * 1000;
  };
  const timeRanges = ["1h", "3h", "1d", "7d", "1m"];

  const setTargetRange = (targetId, range) => {
    setTargetRanges((prev) => ({ ...prev, [targetId]: range }));
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

  const handleAutoTargetSubmit = async (event) => {
    event.preventDefault();
    const form = event.target;
    await request("api/targets/auto", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        octet1: Number(form.octet1.value),
        octet2: Number(form.octet2.value),
        third_start: Number(form.third_start.value),
        third_end: Number(form.third_end.value),
        name: form.name.value || null,
        category: form.category.value || null,
        sort_order: form.sort_order.value
          ? Number(form.sort_order.value)
          : null
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
        <div className="header-inner">
          <div>
            <h1>{t("app_title")}</h1>
            <p>{t("app_tagline")}</p>
          </div>
          <div className="timezone-control">
            <label>
              <span>{t("timezone_label")}</span>
              <select
                value={timeZone}
                onChange={(event) => setTimeZone(event.target.value)}
              >
                {TIMEZONE_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.labelKey ? t(option.labelKey) : option.label}
                  </option>
                ))}
              </select>
            </label>
          </div>
        </div>
      </header>

      <main>
        <div className="layout">
          <aside className="sidebar">
            <section className="card">
              <h2>{t("agents_title")}</h2>
              <p className="subtle">{t("select_agent")}</p>
              <ul className="agent-list">
                {data.agents.map((agent) => {
                  const offline = isAgentOffline(agent);
                  return (
                    <li key={agent.id}>
                      <button
                        className={`agent-item${agent.id === selectedAgentId ? " active" : ""}`}
                        type="button"
                        onClick={() => setSelectedAgentId(agent.id)}
                      >
                        <div>
                          <strong>{agent.name}</strong>
                          <div className="agent-address">{agent.address}</div>
                        </div>
                        <div className="agent-status">
                          <span className={`pill status ${offline ? "offline" : "online"}`}>
                            {offline ? t("agent_status_offline") : t("agent_status_online")}
                          </span>
                          <span className="pill">
                            {t("last_seen")}: {formatDuration(agent.last_seen)}
                          </span>
                        </div>
                      </button>
                    </li>
                  );
                })}
              </ul>
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
          </aside>

          <div className="content">
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

            <section className="card overview">
              <div className="overview-header">
                <div>
                  <h2>{t("agent_overview")}</h2>
                  <p className="subtle">
                    {selectedAgent
                      ? `${selectedAgent.name} · ${selectedAgent.address}`
                      : t("agents_title")}
                  </p>
                </div>
                {selectedAgent && (
                  <button
                    className="danger"
                    type="button"
                    onClick={() => handleDeleteAgent(selectedAgent.id)}
                  >
                    {t("delete_button")}
                  </button>
                )}
              </div>
              <div className="pill-group">
                {selectedAgent && (
                  <span
                    className={`pill status ${
                      isAgentOffline(selectedAgent) ? "offline" : "online"
                    }`}
                  >
                    {isAgentOffline(selectedAgent)
                      ? t("agent_status_offline")
                      : t("agent_status_online")}
                  </span>
                )}
                <span className="pill">
                  {t("interval_label")}: {data.config?.interval_seconds ?? 0}s
                </span>
                <span className="pill">
                  {t("timeout_label")}: {data.config?.timeout_seconds ?? 0}s
                </span>
                <span className="pill">
                  {t("mtr_runs_label")}: {data.config?.mtr_runs ?? 0}
                </span>
              </div>
            </section>

            <section className="card">
              <h2>{t("agents_title")}</h2>
              {!selectedAgent && (
                <p className="subtle">{t("select_agent")}</p>
              )}
              {selectedAgent && (
                <ul className="targets">
                  {data.targets.map((target) => {
                    const measurement = measurementMap.get(
                      `${selectedAgent.id}-${target.id}`
                    );
                    const activeRange = targetRanges[target.id] ?? "1h";
                    const avgMs = measurement?.avg_ms;
                    const packetLoss = measurement?.packet_loss;
                    const lastLossTimestamp =
                      lastLossMeasurement?.targetId === target.id
                        ? lastLossMeasurement.timestamp
                        : null;
                    return (
                      <li key={target.id}>
                        <details className="target-toggle">
                          <summary>
                            <div className="target-summary">
                              <div className="target-info">
                                <span className="target-name">{target.name}</span>
                                <span className="target-address">
                                  {target.address} · {target.category}
                                </span>
                              </div>
                              <div className="target-meta">
                                <span className="pill warning">
                                  {t("last_loss")}: {formatTimestamp(lastLossTimestamp)}
                                </span>
                              </div>
                              <div className="graph-links">
                                {timeRanges.map((range) => (
                                  <button
                                    key={range}
                                    className={`range-button${
                                      range === activeRange ? " active" : ""
                                    }`}
                                    type="button"
                                    onClick={(event) => {
                                      event.stopPropagation();
                                      setTargetRange(target.id, range);
                                    }}
                                  >
                                    {range}
                                  </button>
                                ))}
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
                                `graph/${target.id}?range=${activeRange}`
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
                                    {t("measurement_latency")}: {formatMetric(avgMs)} ms
                                  </span>
                                  <span className="pill">
                                    {t("measurement_loss")}: {formatMetric(packetLoss)}%
                                  </span>
                                  {lastLossMeasurement?.targetId === target.id && (
                                    <span className="pill warning">
                                      {t("last_loss")}: {formatTimestamp(
                                        lastLossMeasurement.timestamp
                                      )}
                                    </span>
                                  )}
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
              )}
            </section>

            <section className="card">
              <h2>{t("settings_title")}</h2>
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
              <h2>{t("auto_target_title")}</h2>
              <p className="subtle">{t("auto_target_hint")}</p>
              <form className="grid" onSubmit={handleAutoTargetSubmit}>
                <label>
                  <span>{t("auto_octet1")}</span>
                  <input name="octet1" type="number" min="0" max="255" required />
                </label>
                <label>
                  <span>{t("auto_octet2")}</span>
                  <input name="octet2" type="number" min="0" max="255" required />
                </label>
                <label>
                  <span>{t("auto_third_start")}</span>
                  <input
                    name="third_start"
                    type="number"
                    min="0"
                    max="255"
                    required
                  />
                </label>
                <label>
                  <span>{t("auto_third_end")}</span>
                  <input
                    name="third_end"
                    type="number"
                    min="0"
                    max="255"
                    required
                  />
                </label>
                <label>
                  <span>{t("auto_name")}</span>
                  <input name="name" placeholder="auto-60.48.183-189" />
                </label>
                <label>
                  <span>{t("auto_category")}</span>
                  <input name="category" placeholder={t("target_category_placeholder")} />
                </label>
                <label>
                  <span>{t("auto_sort_order")}</span>
                  <input name="sort_order" type="number" defaultValue={0} />
                </label>
                <div>
                  <button type="submit">{t("auto_target_button")}</button>
                </div>
              </form>
            </section>

          </div>
        </div>
      </main>
    </div>
  );
}
