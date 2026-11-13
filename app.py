import json
from io import StringIO

import networkx as nx
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from pydantic import BaseModel, Field, ValidationError


# ---------------------------------------------------------
# PAGE SETUP
# ---------------------------------------------------------
st.set_page_config(
    page_title="Dependency Trust Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------
# CYBERSECURITY DASHBOARD STYLING
# ---------------------------------------------------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

    :root {
        --bg: #080d1b;
        --panel: #111a2e;
        --panel2: #151f36;
        --border: #253451;
        --muted: #91a0ba;
        --text: #edf3ff;
        --blue: #48a8ff;
        --purple: #9875ff;
        --cyan: #36d7e8;
    }

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    .stApp {
        background:
            radial-gradient(circle at 75% 0%, rgba(79, 70, 229, .15), transparent 30%),
            radial-gradient(circle at 5% 20%, rgba(14, 165, 233, .10), transparent 28%),
            var(--bg);
        color: var(--text);
    }
    [data-testid="stHeader"] { background: rgba(8,13,27,.75); }
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #101a30 0%, #0b1222 100%);
        border-right: 1px solid var(--border);
    }
    [data-testid="stSidebar"] * { color: #dce7fb; }
    .block-container { padding-top: 2rem; padding-bottom: 3rem; max-width: 1500px; }

    h1, h2, h3 { color: #f4f7ff !important; letter-spacing: -0.5px; }
    p, label, span { color: inherit; }

    .hero {
        padding: 28px 32px;
        border: 1px solid #344b78;
        border-radius: 20px;
        background: linear-gradient(115deg, rgba(28,75,139,.85), rgba(83,54,154,.78));
        box-shadow: 0 16px 45px rgba(0,0,0,.22);
        margin-bottom: 24px;
    }
    .hero-kicker {
        color: #b9dcff;
        font-size: 12px;
        font-weight: 800;
        letter-spacing: 2px;
        text-transform: uppercase;
        margin-bottom: 9px;
    }
    .hero-title {
        color: white;
        font-size: 34px;
        font-weight: 800;
        margin: 0;
        line-height: 1.2;
    }
    .hero-subtitle {
        color: #d9e7ff;
        font-size: 14px;
        margin-top: 10px;
        max-width: 780px;
    }
    .section-label {
        color: #9fb4d7;
        font-size: 12px;
        font-weight: 800;
        letter-spacing: 1.6px;
        text-transform: uppercase;
        margin: 25px 0 12px 0;
    }
    .metric-card {
        background: linear-gradient(145deg, #17243d, #101a2e);
        border: 1px solid #2a3c5d;
        border-radius: 16px;
        padding: 18px 20px;
        min-height: 120px;
        box-shadow: 0 8px 25px rgba(0,0,0,.14);
    }
    .metric-label {
        color: #9eacc5;
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .metric-value {
        color: #f5f8ff;
        font-size: 31px;
        font-weight: 800;
        margin-top: 8px;
    }
    .metric-note { color: #8fa2c2; font-size: 11px; margin-top: 3px; }
    .panel {
        background: rgba(17,26,46,.88);
        border: 1px solid #263653;
        border-radius: 16px;
        padding: 18px 20px;
    }
    .small-muted { color: #91a0ba; font-size: 12px; }
    div[data-testid="stDataFrame"], div[data-testid="stPlotlyChart"] {
        border: 1px solid #263653;
        border-radius: 13px;
        overflow: hidden;
    }
    .stButton > button, .stDownloadButton > button {
        border-radius: 9px;
        border: 1px solid #3a6fba;
        background: linear-gradient(100deg, #2468b8, #654ac3);
        color: white;
        font-weight: 700;
    }
    .stButton > button:hover, .stDownloadButton > button:hover {
        border-color: #7cc8ff;
        color: white;
    }
    [data-testid="stMetric"] {
        background: #14213a;
        border: 1px solid #293c5d;
        border-radius: 12px;
        padding: 12px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------
# DATA MODELS AND RISK LOGIC
# ---------------------------------------------------------
class Package(BaseModel):
    name: str
    version: str
    dependencies: list[str] = Field(default_factory=list)
    advisory_points: int = Field(default=0, ge=0, le=35)
    maintenance_points: int = Field(default=0, ge=0, le=20)
    provenance_points: int = Field(default=0, ge=0, le=20)
    license_points: int = Field(default=0, ge=0, le=15)
    exposure_points: int = Field(default=0, ge=0, le=10)


class Manifest(BaseModel):
    project_name: str
    packages: list[Package] = Field(min_length=1)


def calculate_risk(package: Package):
    score = (
        package.advisory_points
        + package.maintenance_points
        + package.provenance_points
        + package.license_points
        + package.exposure_points
    )

    if score <= 24:
        level = "Routine review"
    elif score <= 49:
        level = "Review"
    elif score <= 74:
        level = "High priority"
    else:
        level = "Urgent review"

    return score, level


def risk_color(level):
    return {
        "Routine review": "#35c995",
        "Review": "#f5bd4f",
        "High priority": "#ff8b55",
        "Urgent review": "#ff5576",
    }.get(level, "#48a8ff")


def package_rows(packages):
    rows = []
    for package in packages:
        score, level = calculate_risk(package)
        rows.append({
            "Package": package.name,
            "Version": package.version,
            "Risk Score": score,
            "Priority": level,
            "Dependencies": len(package.dependencies),
            "Advisory": package.advisory_points,
            "Maintenance": package.maintenance_points,
            "Provenance": package.provenance_points,
            "License": package.license_points,
            "Exposure": package.exposure_points,
        })
    return pd.DataFrame(rows)


def create_graph(packages):
    graph = nx.DiGraph()
    known = {package.name for package in packages}
    for package in packages:
        graph.add_node(package.name)
        for dependency in package.dependencies:
            graph.add_node(dependency, external=dependency not in known)
            graph.add_edge(package.name, dependency)
    return graph


# ---------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ DEPENDENCY TRUST")
    st.caption("SOFTWARE SUPPLY-CHAIN SECURITY")
    st.markdown("---")
    st.markdown("### 📂 Manifest")
    uploaded_file = st.file_uploader("Upload a JSON manifest", type=["json"])
    use_sample = st.toggle("Use sample project", value=True)
    st.markdown("---")
    st.markdown("### 🎯 Risk priority guide")
    st.markdown("🟢 **0–24** · Routine review")
    st.markdown("🟡 **25–49** · Review")
    st.markdown("🟠 **50–74** · High priority")
    st.markdown("🔴 **75–100** · Urgent review")
    st.markdown("---")
    st.markdown("### ℹ️ About")
    st.caption(
        "A transparent, rule-based dependency review dashboard. "
        "Scores help prioritize investigation; they are not proof that a package is safe or compromised."
    )


# ---------------------------------------------------------
# HEADER
# ---------------------------------------------------------
st.markdown(
    """
    <div class="hero">
      <div class="hero-kicker">SECURITY POSTURE • SOFTWARE SUPPLY CHAIN</div>
      <div class="hero-title">Dependency Trust Engine</div>
      <div class="hero-subtitle">
        Understand your package ecosystem, identify dependency risks, and focus
        security reviews where they matter most.
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------
# SAMPLE DATA AND MANIFEST LOADING
# ---------------------------------------------------------
SAMPLE_MANIFEST = {
    "project_name": "Sentinel Web Platform",
    "packages": [
        {"name": "fastapi", "version": "0.115.0", "dependencies": ["pydantic", "starlette"], "advisory_points": 8, "maintenance_points": 2, "provenance_points": 2, "license_points": 0, "exposure_points": 3},
        {"name": "pydantic", "version": "2.9.2", "dependencies": ["typing-extensions"], "advisory_points": 5, "maintenance_points": 1, "provenance_points": 1, "license_points": 0, "exposure_points": 2},
        {"name": "starlette", "version": "0.38.6", "dependencies": ["anyio"], "advisory_points": 18, "maintenance_points": 5, "provenance_points": 3, "license_points": 0, "exposure_points": 5},
        {"name": "requests", "version": "2.32.3", "dependencies": ["urllib3", "certifi"], "advisory_points": 28, "maintenance_points": 4, "provenance_points": 3, "license_points": 2, "exposure_points": 7},
        {"name": "urllib3", "version": "2.2.3", "dependencies": [], "advisory_points": 12, "maintenance_points": 2, "provenance_points": 1, "license_points": 0, "exposure_points": 4},
        {"name": "numpy", "version": "2.1.1", "dependencies": [], "advisory_points": 2, "maintenance_points": 1, "provenance_points": 1, "license_points": 0, "exposure_points": 2},
        {"name": "legacy-parser", "version": "0.4.0", "dependencies": ["requests"], "advisory_points": 30, "maintenance_points": 18, "provenance_points": 16, "license_points": 8, "exposure_points": 9},
        {"name": "typing-extensions", "version": "4.12.2", "dependencies": [], "advisory_points": 0, "maintenance_points": 1, "provenance_points": 1, "license_points": 0, "exposure_points": 1},
        {"name": "certifi", "version": "2024.8.30", "dependencies": [], "advisory_points": 3, "maintenance_points": 1, "provenance_points": 1, "license_points": 0, "exposure_points": 1},
        {"name": "anyio", "version": "4.6.0", "dependencies": [], "advisory_points": 6, "maintenance_points": 2, "provenance_points": 1, "license_points": 0, "exposure_points": 2},
    ],
}

manifest_data = None
if uploaded_file is not None:
    try:
        manifest_data = json.load(uploaded_file)
    except json.JSONDecodeError as error:
        st.error(f"Could not read the JSON file: {error}")
        st.stop()
elif use_sample:
    manifest_data = SAMPLE_MANIFEST
else:
    st.info("Upload a JSON manifest in the sidebar, or turn on **Use sample project**.")
    st.stop()

try:
    manifest = Manifest.model_validate(manifest_data)
except ValidationError as error:
    st.error("The manifest does not match the required format.")
    st.code(str(error))
    st.stop()

packages = manifest.packages
df = package_rows(packages)
package_names = [package.name for package in packages]
duplicates = sorted({name for name in package_names if package_names.count(name) > 1})
known_names = set(package_names)
missing_dependencies = sorted({
    dependency
    for package in packages
    for dependency in package.dependencies
    if dependency not in known_names
})

if duplicates:
    st.warning("Duplicate package names found: " + ", ".join(duplicates))
if missing_dependencies:
    st.info("Dependencies not included as packages in this manifest: " + ", ".join(missing_dependencies))


# ---------------------------------------------------------
# TOP METRICS
# ---------------------------------------------------------
total_packages = len(packages)
high_count = int((df["Risk Score"] >= 50).sum())
urgent_count = int((df["Risk Score"] >= 75).sum())
average_score = float(df["Risk Score"].mean()) if total_packages else 0

st.markdown('<div class="section-label">01 / SECURITY OVERVIEW</div>', unsafe_allow_html=True)
m1, m2, m3, m4 = st.columns(4)
metrics = [
    (m1, "TOTAL PACKAGES", f"{total_packages}", "Components in this manifest", "#48a8ff"),
    (m2, "HIGH-RISK PACKAGES", f"{high_count}", "Score of 50 or above", "#ff8b55"),
    (m3, "URGENT REVIEWS", f"{urgent_count}", "Score of 75 or above", "#ff5576"),
    (m4, "AVERAGE RISK SCORE", f"{average_score:.1f}/100", "Mean review-priority score", "#9875ff"),
]
for column, label, value, note, accent in metrics:
    with column:
        st.markdown(
            f"""
            <div class="metric-card">
              <div class="metric-label">{label}</div>
              <div class="metric-value" style="color:{accent}">{value}</div>
              <div class="metric-note">{note}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------
# RISK ANALYTICS
# ---------------------------------------------------------
st.markdown('<div class="section-label">02 / RISK INTELLIGENCE</div>', unsafe_allow_html=True)
left, right = st.columns([1.35, 1])

priority_order = ["Routine review", "Review", "High priority", "Urgent review"]
priority_counts = (
    df["Priority"].value_counts()
    .reindex(priority_order, fill_value=0)
    .rename_axis("Priority")
    .reset_index(name="Packages")
)
color_map = {
    "Routine review": "#35c995",
    "Review": "#f5bd4f",
    "High priority": "#ff8b55",
    "Urgent review": "#ff5576",
}

with left:
    st.markdown("### Package risk ranking")
    ranked = df.sort_values("Risk Score", ascending=True)
    fig_bar = px.bar(
        ranked,
        x="Risk Score",
        y="Package",
        color="Priority",
        color_discrete_map=color_map,
        orientation="h",
        hover_data=["Version", "Priority"],
    )
    fig_bar.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#dce7fb",
        height=390,
        margin=dict(l=5, r=15, t=10, b=10),
        xaxis=dict(gridcolor="#263653", range=[0, 100], title="Review-priority score"),
        yaxis=dict(title="", gridcolor="rgba(0,0,0,0)"),
        legend=dict(orientation="h", y=1.12, x=0),
    )
    st.plotly_chart(fig_bar, width="stretch")

with right:
    st.markdown("### Risk distribution")
    fig_donut = go.Figure(data=[go.Pie(
        labels=priority_counts["Priority"],
        values=priority_counts["Packages"],
        hole=0.68,
        marker=dict(colors=[color_map[x] for x in priority_counts["Priority"]]),
        textinfo="value",
        hovertemplate="%{label}: %{value} packages<extra></extra>",
    )])
    fig_donut.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#dce7fb",
        height=390,
        margin=dict(l=5, r=5, t=10, b=10),
        showlegend=True,
        legend=dict(orientation="h", y=-0.08, x=0.05),
        annotations=[dict(
            text=f"<b>{total_packages}</b><br><span style='font-size:11px'>PACKAGES</span>",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=20, color="#f4f7ff"),
        )],
    )
    st.plotly_chart(fig_donut, width="stretch")


# ---------------------------------------------------------
# PACKAGE INVENTORY
# ---------------------------------------------------------
st.markdown('<div class="section-label">03 / DEPENDENCY INVENTORY</div>', unsafe_allow_html=True)
search_col, filter_col = st.columns([2, 1])
with search_col:
    search_text = st.text_input("Search packages", placeholder="Type a package name...")
with filter_col:
    selected_priority = st.selectbox(
        "Filter by priority",
        ["All priorities"] + priority_order,
    )

filtered = df.copy()
if search_text:
    filtered = filtered[filtered["Package"].str.contains(search_text, case=False, na=False)]
if selected_priority != "All priorities":
    filtered = filtered[filtered["Priority"] == selected_priority]

st.dataframe(
    filtered,
    hide_index=True,
    width="stretch",
    column_config={
        "Risk Score": st.column_config.ProgressColumn(
            "Risk Score", min_value=0, max_value=100, format="%d"
        ),
    },
)

# ---------------------------------------------------------
# PACKAGE DETAILS
# ---------------------------------------------------------
st.markdown('<div class="section-label">04 / PACKAGE DEEP DIVE</div>', unsafe_allow_html=True)
selected_package_name = st.selectbox("Select a package to inspect", package_names)
selected_package = next(p for p in packages if p.name == selected_package_name)
selected_score, selected_level = calculate_risk(selected_package)

detail_a, detail_b = st.columns([1, 1.2])
with detail_a:
    st.markdown("### " + selected_package.name)
    st.caption(f"Version {selected_package.version}")
    st.markdown(
        f"<h2 style='color:{risk_color(selected_level)}; margin-bottom:0'>{selected_score}/100</h2>"
        f"<p style='color:{risk_color(selected_level)}; font-weight:700'>{selected_level}</p>",
        unsafe_allow_html=True,
    )
    st.progress(selected_score / 100)
    st.markdown("**Direct dependencies**")
    if selected_package.dependencies:
        for dependency in selected_package.dependencies:
            st.markdown(f"- `{dependency}`")
    else:
        st.caption("No direct dependencies listed.")

with detail_b:
    st.markdown("### Risk factor breakdown")
    factors = {
        "Security advisories": (selected_package.advisory_points, 35),
        "Maintenance": (selected_package.maintenance_points, 20),
        "Provenance / integrity": (selected_package.provenance_points, 20),
        "License policy": (selected_package.license_points, 15),
        "Dependency exposure": (selected_package.exposure_points, 10),
    }
    for label, (value, maximum) in factors.items():
        st.markdown(f"**{label}** · {value}/{maximum}")
        st.progress(value / maximum if maximum else 0)


# ---------------------------------------------------------
# DEPENDENCY GRAPH
# ---------------------------------------------------------
st.markdown('<div class="section-label">05 / DEPENDENCY MAP</div>', unsafe_allow_html=True)
st.markdown("### Package relationship network")
st.caption("Arrows show a package pointing to one of its dependencies. Dashed nodes are dependencies absent from the uploaded package list.")

graph = create_graph(packages)
if graph.number_of_nodes() > 0:
    positions = nx.spring_layout(graph, seed=17, k=0.9)
    edge_x, edge_y = [], []
    for source, target in graph.edges():
        x0, y0 = positions[source]
        x1, y1 = positions[target]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        mode="lines",
        line=dict(width=1.4, color="#486184"),
        hoverinfo="none",
    )

    node_x, node_y, node_text, node_colors, node_symbols = [], [], [], [], []
    score_lookup = {p.name: calculate_risk(p)[0] for p in packages}
    for node in graph.nodes():
        x, y = positions[node]
        node_x.append(x)
        node_y.append(y)
        if node in score_lookup:
            score = score_lookup[node]
            level = next(
                p for p in packages if p.name == node
            )
            node_colors.append(risk_color(calculate_risk(level)[1]))
            node_symbols.append("circle")
            node_text.append(f"{node}<br>Risk score: {score}")
        else:
            node_colors.append("#718096")
            node_symbols.append("diamond")
            node_text.append(f"{node}<br>Not included in manifest")

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        text=list(graph.nodes()),
        textposition="bottom center",
        textfont=dict(color="#dce7fb", size=10),
        hovertext=node_text,
        hoverinfo="text",
        marker=dict(
            size=22,
            color=node_colors,
            symbol=node_symbols,
            line=dict(width=1.5, color="#dce7fb"),
        ),
    )
    graph_fig = go.Figure(data=[edge_trace, node_trace])
    graph_fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#dce7fb",
        height=510,
        margin=dict(l=10, r=10, t=10, b=10),
        showlegend=False,
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
    )
    st.plotly_chart(graph_fig, width="stretch")
else:
    st.info("No dependency relationships to display.")


# ---------------------------------------------------------
# EXPORT AND METHODOLOGY
# ---------------------------------------------------------
st.markdown('<div class="section-label">06 / REPORTING</div>', unsafe_allow_html=True)
export_col, info_col = st.columns([1, 2])
with export_col:
    csv_data = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇ Download risk report (CSV)",
        data=csv_data,
        file_name="dependency_trust_report.csv",
        mime="text/csv",
        width="stretch",
    )
with info_col:
    st.caption(
        "Scoring is a transparent demonstration model using the values in the manifest. "
        "It does not query live vulnerability databases and does not certify package safety. "
        "Use the results to prioritize human review."
    )

st.markdown(
    "<p style='text-align:center; color:#71819e; font-size:11px; margin-top:35px'>"
    "DEPENDENCY TRUST ENGINE · SOFTWARE SUPPLY-CHAIN REVIEW DASHBOARD"
    "</p>",
    unsafe_allow_html=True,
)
