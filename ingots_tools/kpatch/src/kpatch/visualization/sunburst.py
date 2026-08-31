from dataclasses import dataclass, field
from enum import StrEnum
from html import escape
import json
import math
from pathlib import Path
from tempfile import NamedTemporaryFile
import webbrowser

import plotly.graph_objects as go  # type: ignore[import-untyped]
import plotly.io as pio  # type: ignore[import-untyped]

from ..git import GitCommit


class _MetricMode(StrEnum):
    FILE_TOUCHES = "file_touches"
    UNIQUE_COMMITS = "unique_commits"
    EXCLUSIVE_COMMITS = "exclusive_commits"


class _NodeKind(StrEnum):
    DIRECTORY = "directory"
    FILE = "file"
    OTHER = "aggregate"


@dataclass(slots=True)
class _TreeNode:
    id: str
    label: str
    path: str
    kind: _NodeKind
    children: dict[tuple[_NodeKind, str], "_TreeNode"] = field(
        default_factory=dict
    )
    commit_ids: set[str] = field(default_factory=set)
    commit_touch_counts: dict[str, int] = field(default_factory=dict)
    exclusive_commit_ids: set[str] = field(default_factory=set)
    file_touches: int = 0

    @property
    def unique_commits(self) -> int:
        return len(self.commit_ids)

    @property
    def exclusive_commits(self) -> int:
        return len(self.exclusive_commit_ids)


@dataclass(frozen=True, slots=True)
class _ViewNode:
    id: str
    label: str
    parent_id: str
    value: float
    path: str
    kind: _NodeKind
    file_touches: int
    unique_commits: int
    exclusive_commits: int
    hidden_items: int = 0
    sidebar_item_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _Breadcrumb:
    id: str
    label: str


@dataclass(frozen=True, slots=True)
class _SidebarItem:
    id: str
    label: str
    path: str
    kind: _NodeKind
    file_touches: int
    unique_commits: int
    exclusive_commits: int


@dataclass(frozen=True, slots=True)
class _ChartView:
    root_id: str
    root_path: str
    mode: _MetricMode
    breadcrumbs: tuple[_Breadcrumb, ...]
    sidebar_items: tuple[_SidebarItem, ...]
    nodes: tuple[_ViewNode, ...]


def _normalized_path(path: str) -> str | None:
    parts = [
        part
        for part in path.removeprefix("./").split("/")
        if part not in ("", ".")
    ]
    return "/".join(parts) or None


def _build_commit_tree(commits: list[GitCommit]) -> _TreeNode:
    paths_by_commit: dict[str, set[str]] = {}
    for commit in commits:
        commit_paths = paths_by_commit.setdefault(commit.commit_id, set())
        for file_change in commit.diff.files:
            normalized_path = _normalized_path(file_change.file)
            if normalized_path is not None:
                commit_paths.add(normalized_path)

    root = _TreeNode(
        id="dir:.",
        label="repository",
        path=".",
        kind=_NodeKind.DIRECTORY,
    )
    for commit_id, paths in paths_by_commit.items():
        for path in sorted(paths):
            parts = path.split("/")
            parent = root
            directory_parts: list[str] = []
            for part in parts[:-1]:
                directory_parts.append(part)
                directory_path = "/".join(directory_parts)
                key = (_NodeKind.DIRECTORY, part)
                if key not in parent.children:
                    parent.children[key] = _TreeNode(
                        id=f"dir:{directory_path}",
                        label=part,
                        path=directory_path,
                        kind=_NodeKind.DIRECTORY,
                    )
                parent = parent.children[key]

            filename = parts[-1]
            file_key = (_NodeKind.FILE, filename)
            if file_key not in parent.children:
                parent.children[file_key] = _TreeNode(
                    id=f"file:{path}",
                    label=filename,
                    path=path,
                    kind=_NodeKind.FILE,
                )
            parent.children[file_key].commit_ids.add(commit_id)

    def finalize(node: _TreeNode) -> None:
        if node.kind is _NodeKind.FILE:
            node.commit_touch_counts = {
                commit_id: 1 for commit_id in node.commit_ids
            }
            node.exclusive_commit_ids = {
                commit_id
                for commit_id in node.commit_ids
                if len(paths_by_commit[commit_id]) == 1
            }
            node.file_touches = node.unique_commits
            return

        for child in node.children.values():
            finalize(child)
            node.commit_ids.update(child.commit_ids)
            node.file_touches += child.file_touches
            for commit_id, touch_count in child.commit_touch_counts.items():
                node.commit_touch_counts[commit_id] = (
                    node.commit_touch_counts.get(commit_id, 0) + touch_count
                )
        node.exclusive_commit_ids = {
            commit_id
            for commit_id, touch_count in node.commit_touch_counts.items()
            if touch_count == len(paths_by_commit[commit_id])
        }

    finalize(root)
    return root


def _node_weight(node: _TreeNode, mode: _MetricMode) -> int:
    if mode is _MetricMode.FILE_TOUCHES:
        return node.file_touches
    if mode is _MetricMode.UNIQUE_COMMITS:
        return node.unique_commits
    return node.exclusive_commits


def _allocated_children(
    node: _TreeNode,
    mode: _MetricMode,
    node_fraction: float,
) -> list[tuple[_TreeNode, float]]:
    children = sorted(
        (
            child
            for child in node.children.values()
            if _node_weight(child, mode) > 0
        ),
        key=lambda child: (-_node_weight(child, mode), child.path, child.kind),
    )
    total_weight = (
        node.exclusive_commits
        if mode is _MetricMode.EXCLUSIVE_COMMITS
        else sum(_node_weight(child, mode) for child in children)
    )
    if total_weight == 0:
        return []

    allocations: list[tuple[_TreeNode, float]] = []
    remaining = node_fraction
    for index, child in enumerate(children):
        if mode is not _MetricMode.EXCLUSIVE_COMMITS and index == len(children) - 1:
            fraction = remaining
        else:
            fraction = node_fraction * _node_weight(child, mode) / total_weight
            remaining -= fraction
        allocations.append((child, fraction))
    return allocations


def _build_chart_view(
    root: _TreeNode,
    mode: _MetricMode,
    min_sector_fraction: float,
) -> _ChartView:
    view_nodes: list[_ViewNode] = []

    def visit(
        node: _TreeNode,
        parent_id: str,
        fraction: float,
        sidebar_item_ids: tuple[str, ...],
    ) -> None:
        view_nodes.append(
            _ViewNode(
                id=node.id,
                label=node.label,
                parent_id=parent_id,
                value=fraction,
                path=node.path,
                kind=node.kind,
                file_touches=node.file_touches,
                unique_commits=node.unique_commits,
                exclusive_commits=node.exclusive_commits,
                sidebar_item_ids=sidebar_item_ids,
            )
        )
        allocations = _allocated_children(node, mode, fraction)
        visible = [
            allocation
            for allocation in allocations
            if allocation[1] >= min_sector_fraction
        ]
        hidden = [
            allocation
            for allocation in allocations
            if allocation[1] < min_sector_fraction
        ]

        for child, child_fraction in visible:
            child_sidebar_ids = (
                (child.id,) if node is root else sidebar_item_ids
            )
            visit(child, node.id, child_fraction, child_sidebar_ids)

        if hidden:
            hidden_children = [child for child, _ in hidden]
            hidden_commits: set[str] = set()
            for child in hidden_children:
                hidden_commits.update(child.commit_ids)
            hidden_fraction = sum(
                child_fraction for _, child_fraction in hidden
            )
            item_count = len(hidden_children)
            view_nodes.append(
                _ViewNode(
                    id=f"other:{mode.value}:{root.id}:{node.id}",
                    label=f"Other ({item_count} items)",
                    parent_id=node.id,
                    value=hidden_fraction,
                    path=f"{node.path.rstrip('/')}/Other",
                    kind=_NodeKind.OTHER,
                    file_touches=sum(
                        child.file_touches for child in hidden_children
                    ),
                    unique_commits=len(hidden_commits),
                    exclusive_commits=sum(
                        child.exclusive_commits for child in hidden_children
                    ),
                    hidden_items=item_count,
                    sidebar_item_ids=(
                        tuple(child.id for child in hidden_children)
                        if node is root
                        else sidebar_item_ids
                    ),
                )
            )

    visit(root, "", 1.0, ())
    breadcrumbs = [_Breadcrumb(id="dir:.", label=".")]
    if root.path != ".":
        path_parts: list[str] = []
        for part in root.path.split("/"):
            path_parts.append(part)
            breadcrumbs.append(
                _Breadcrumb(
                    id=f"dir:{'/'.join(path_parts)}",
                    label=part,
                )
            )
    sidebar_items = tuple(
        _SidebarItem(
            id=child.id,
            label=child.label,
            path=child.path,
            kind=child.kind,
            file_touches=child.file_touches,
            unique_commits=child.unique_commits,
            exclusive_commits=child.exclusive_commits,
        )
        for child in sorted(
            root.children.values(),
            key=lambda child: (-_node_weight(child, mode), child.path, child.kind),
        )
    )
    return _ChartView(
        root_id=root.id,
        root_path=root.path,
        mode=mode,
        breadcrumbs=tuple(breadcrumbs),
        sidebar_items=sidebar_items,
        nodes=tuple(view_nodes),
    )


def _directory_index(root: _TreeNode) -> dict[str, _TreeNode]:
    directories: dict[str, _TreeNode] = {}

    def visit(node: _TreeNode) -> None:
        if node.kind is _NodeKind.DIRECTORY:
            directories[node.id] = node
        for child in node.children.values():
            visit(child)

    visit(root)
    return directories


def _build_directory_views(
    root: _TreeNode,
    min_sector_fraction: float,
) -> dict[_MetricMode, dict[str, _ChartView]]:
    directories = _directory_index(root)
    views: dict[_MetricMode, dict[str, _ChartView]] = {
        mode: {} for mode in _MetricMode
    }
    for root_id, chart_root in directories.items():
        for mode in _MetricMode:
            views[mode][root_id] = _build_chart_view(
                chart_root,
                mode,
                min_sector_fraction,
            )

    return views


def _hover_text(node: _ViewNode) -> str:
    details = [
        f"<b>{escape(node.path)}</b>",
        f"Type: {escape(node.kind.value)}",
        f"File touches: {node.file_touches:,}",
        f"Unique commits: {node.unique_commits:,}",
        f"Exclusive commits: {node.exclusive_commits:,}",
    ]
    if node.hidden_items:
        details.append(f"Grouped items: {node.hidden_items:,}")
    return "<br>".join(details)


def _trace_dict(view: _ChartView) -> dict[str, object]:
    return {
        "type": "sunburst",
        "ids": [node.id for node in view.nodes],
        "labels": [node.label for node in view.nodes],
        "parents": [node.parent_id for node in view.nodes],
        "values": [node.value for node in view.nodes],
        "customdata": [
            [
                node.kind.value,
                node.file_touches,
                node.unique_commits,
                node.sidebar_item_ids,
                node.exclusive_commits,
            ]
            for node in view.nodes
        ],
        "hovertext": [_hover_text(node) for node in view.nodes],
        "hovertemplate": "%{hovertext}<br>Area: %{percentRoot:.2%}<extra></extra>",
        "branchvalues": "total",
        "sort": False,
        "insidetextorientation": "radial",
    }


def _serialized_views(
    views: dict[_MetricMode, dict[str, _ChartView]],
) -> dict[str, dict[str, dict[str, object]]]:
    return {
        mode.value: {
            root_id: {
                "rootPath": view.root_path,
                "breadcrumbs": [
                    {"id": breadcrumb.id, "label": breadcrumb.label}
                    for breadcrumb in view.breadcrumbs
                ],
                "sidebarItems": [
                    {
                        "id": item.id,
                        "label": item.label,
                        "path": item.path,
                        "kind": item.kind.value,
                        "fileTouches": item.file_touches,
                        "uniqueCommits": item.unique_commits,
                        "exclusiveCommits": item.exclusive_commits,
                    }
                    for item in view.sidebar_items
                ],
                "trace": _trace_dict(view),
            }
            for root_id, view in mode_views.items()
        }
        for mode, mode_views in views.items()
    }


_BASE_LAYOUT: dict[str, object] = {
    "autosize": True,
    "margin": {"t": 64, "r": 16, "b": 16, "l": 16},
    "paper_bgcolor": "#fafafa",
    "plot_bgcolor": "#fafafa",
    "uniformtext": {"minsize": 10, "mode": "hide"},
}

_POST_SCRIPT = r"""
const graph = document.getElementById("kpatch-commit-sunburst");
const views = __VIEWS_JSON__;
const layoutBase = __LAYOUT_JSON__;
const config = {responsive: true, displaylogo: false};
let mode = "file_touches";
let rootId = "dir:.";
let maxDepth = __MAX_DEPTH__;

const style = document.createElement("style");
style.textContent = `
  html, body { height: 100%; margin: 0; background: #fafafa; }
  body { font-family: system-ui, sans-serif; color: #1f2937; }
  .kpatch-toolbar { box-sizing: border-box; min-height: 58px; padding: 10px 16px;
    display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
    border-bottom: 1px solid #d1d5db; background: white; }
  .kpatch-toolbar button, .kpatch-toolbar select, .kpatch-toolbar input {
    font: inherit; padding: 5px 9px;
    border: 1px solid #9ca3af; border-radius: 5px; background: white; }
  .kpatch-depth-input { box-sizing: border-box; width: 64px; }
  .kpatch-toolbar button:not(:disabled) { cursor: pointer; }
  .kpatch-toolbar button:disabled { opacity: .45; }
  .kpatch-breadcrumbs { display: flex; align-items: center; gap: 0; flex-wrap: wrap; }
  .kpatch-breadcrumbs button { border: 0; color: #2563eb; padding: 3px 1px; }
  .kpatch-breadcrumbs button:hover { text-decoration: underline; }
  .kpatch-separator { color: #6b7280; }
  .kpatch-workspace { display: flex; height: calc(100vh - 58px); min-height: 0; }
  .kpatch-sidebar { box-sizing: border-box; width: 430px; min-width: 330px;
    display: flex; flex-direction: column; border-right: 1px solid #d1d5db;
    background: white; }
  .kpatch-sidebar-title { margin: 0; padding: 14px 14px 2px; font-size: 16px; }
  .kpatch-sidebar-summary { padding: 0 14px 10px; color: #6b7280; font-size: 12px; }
  .kpatch-sidebar-columns, .kpatch-sidebar-row { display: grid;
    grid-template-columns: minmax(0, 1fr) 68px 68px 72px; gap: 8px;
    align-items: center; }
  .kpatch-sidebar-columns { padding: 7px 12px; border-top: 1px solid #e5e7eb;
    border-bottom: 1px solid #e5e7eb; color: #6b7280; font-size: 11px;
    font-weight: 600; text-transform: uppercase; }
  .kpatch-sidebar-columns span:not(:first-child),
  .kpatch-sidebar-row span:not(:first-child) { text-align: right; }
  .kpatch-sidebar-list { overflow: auto; min-height: 0; }
  .kpatch-sidebar-row { box-sizing: border-box; width: 100%; min-height: 34px;
    padding: 6px 12px; border: 0; border-bottom: 1px solid #f3f4f6;
    color: inherit; background: transparent; font: inherit; text-align: left; }
  button.kpatch-sidebar-row { cursor: pointer; }
  button.kpatch-sidebar-row:hover { background: #eff6ff; }
  .kpatch-sidebar-row.kpatch-highlighted { background: #fef3c7; outline: 2px solid #f59e0b;
    outline-offset: -2px; }
  .kpatch-sidebar-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .kpatch-sidebar-metric { font-variant-numeric: tabular-nums; }
  #kpatch-commit-sunburst { flex: 1; min-width: 0; height: 100% !important; }
  @media (max-width: 760px) {
    .kpatch-sidebar { width: 330px; min-width: 280px; }
  }
`;
document.head.appendChild(style);

const toolbar = document.createElement("div");
toolbar.className = "kpatch-toolbar";

const back = document.createElement("button");
back.type = "button";
back.textContent = "Back";
back.addEventListener("click", () => {
  const breadcrumbs = currentView().breadcrumbs;
  if (breadcrumbs.length > 1) {
    rootId = breadcrumbs[breadcrumbs.length - 2].id;
    render();
  }
});
toolbar.appendChild(back);

const modeLabel = document.createElement("label");
modeLabel.textContent = "Area mode: ";
const modeSelect = document.createElement("select");
modeSelect.innerHTML = `
  <option value="file_touches">File touches</option>
  <option value="unique_commits">Unique commits</option>
  <option value="exclusive_commits">Exclusive commits</option>
`;
modeSelect.addEventListener("change", () => {
  mode = modeSelect.value;
  render();
});
modeLabel.appendChild(modeSelect);
toolbar.appendChild(modeLabel);

const depthLabel = document.createElement("label");
depthLabel.textContent = "Visible child layers: ";
depthLabel.title = "Maximum rings outside the currently selected folder";
const depthInput = document.createElement("input");
depthInput.className = "kpatch-depth-input";
depthInput.type = "number";
depthInput.min = "1";
depthInput.step = "1";
depthInput.value = String(maxDepth);
depthInput.addEventListener("change", () => {
  const requestedDepth = Number.parseInt(depthInput.value, 10);
  if (Number.isInteger(requestedDepth) && requestedDepth >= 1) {
    maxDepth = requestedDepth;
    render();
  } else {
    depthInput.value = String(maxDepth);
  }
});
depthLabel.appendChild(depthInput);
toolbar.appendChild(depthLabel);

const breadcrumbs = document.createElement("nav");
breadcrumbs.className = "kpatch-breadcrumbs";
breadcrumbs.setAttribute("aria-label", "Directory path");
toolbar.appendChild(breadcrumbs);

const graphParent = graph.parentNode;
graphParent.insertBefore(toolbar, graph);
const workspace = document.createElement("div");
workspace.className = "kpatch-workspace";
graphParent.insertBefore(workspace, graph);

const sidebar = document.createElement("aside");
sidebar.className = "kpatch-sidebar";
const sidebarTitle = document.createElement("h2");
sidebarTitle.className = "kpatch-sidebar-title";
sidebar.appendChild(sidebarTitle);
const sidebarSummary = document.createElement("div");
sidebarSummary.className = "kpatch-sidebar-summary";
sidebar.appendChild(sidebarSummary);
const sidebarColumns = document.createElement("div");
sidebarColumns.className = "kpatch-sidebar-columns";
sidebarColumns.innerHTML = `
  <span>Name</span>
  <span>Touches</span>
  <span>Commits</span>
  <span title="Commits whose entire visualized change is inside this item">Exclusive</span>
`;
sidebar.appendChild(sidebarColumns);
const sidebarList = document.createElement("div");
sidebarList.className = "kpatch-sidebar-list";
sidebar.appendChild(sidebarList);
workspace.appendChild(sidebar);
workspace.appendChild(graph);
let sidebarRows = new Map();

function currentView() {
  return views[mode][rootId];
}

function updateBreadcrumbs() {
  breadcrumbs.replaceChildren();
  currentView().breadcrumbs.forEach((breadcrumb, index) => {
    if (index > 0) {
      const separator = document.createElement("span");
      separator.className = "kpatch-separator";
      separator.textContent = "/";
      breadcrumbs.appendChild(separator);
    }
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = breadcrumb.label;
    button.addEventListener("click", () => {
      rootId = breadcrumb.id;
      render();
    });
    breadcrumbs.appendChild(button);
  });
}

function updateSidebar() {
  const view = currentView();
  sidebarTitle.textContent = `Contents of ${view.rootPath}`;
  const sortLabels = {
    file_touches: "file touches",
    unique_commits: "unique commits",
    exclusive_commits: "exclusive commits"
  };
  const sortLabel = sortLabels[mode];
  sidebarSummary.textContent = `${view.sidebarItems.length.toLocaleString()} items · sorted by ${sortLabel}`;
  sidebarList.replaceChildren();
  sidebarRows = new Map();
  view.sidebarItems.forEach(item => {
    const row = document.createElement(item.kind === "directory" ? "button" : "div");
    row.className = "kpatch-sidebar-row";
    row.title = item.path;
    if (item.kind === "directory") {
      row.type = "button";
      row.addEventListener("click", () => {
        rootId = item.id;
        render();
      });
    }
    const name = document.createElement("span");
    name.className = "kpatch-sidebar-name";
    name.textContent = item.kind === "directory" ? `${item.label}/` : item.label;
    const touches = document.createElement("span");
    touches.className = "kpatch-sidebar-metric";
    touches.textContent = item.fileTouches.toLocaleString();
    const commits = document.createElement("span");
    commits.className = "kpatch-sidebar-metric";
    commits.textContent = item.uniqueCommits.toLocaleString();
    const exclusive = document.createElement("span");
    exclusive.className = "kpatch-sidebar-metric";
    exclusive.textContent = item.exclusiveCommits.toLocaleString();
    row.append(name, touches, commits, exclusive);
    sidebarList.appendChild(row);
    sidebarRows.set(item.id, row);
  });
}

function highlightSidebar(itemIds) {
  const highlighted = new Set(itemIds || []);
  sidebarRows.forEach((row, itemId) => {
    row.classList.toggle("kpatch-highlighted", highlighted.has(itemId));
  });
  if (highlighted.size === 1) {
    const row = sidebarRows.get(highlighted.values().next().value);
    if (row) {
      row.scrollIntoView({block: "nearest"});
    }
  }
}

function render() {
  const view = currentView();
  const modeTitles = {
    file_touches: "File touches",
    unique_commits: "Unique commits",
    exclusive_commits: "Exclusive commits"
  };
  const modeTitle = modeTitles[mode];
  const layout = Object.assign({}, layoutBase, {
    title: {text: `${modeTitle}: ${view.rootPath}`, x: 0.5, xanchor: "center"}
  });
  back.disabled = view.breadcrumbs.length === 1;
  updateBreadcrumbs();
  updateSidebar();
  const trace = Object.assign({}, view.trace, {maxdepth: maxDepth + 1});
  Plotly.react(graph, [trace], layout, config);
}

graph.on("plotly_sunburstclick", event => {
  const point = event.points && event.points[0];
  if (point && point.id !== rootId && views[mode][point.id]) {
    rootId = point.id;
    render();
  }
  return false;
});

graph.on("plotly_hover", event => {
  const point = event.points && event.points[0];
  highlightSidebar(point && point.customdata ? point.customdata[3] : []);
});

graph.on("plotly_unhover", () => {
  highlightSidebar([]);
});

render();
"""


def _render_html(
    root: _TreeNode,
    min_sector_fraction: float,
    max_depth: int,
) -> str:
    views = _build_directory_views(root, min_sector_fraction)
    serialized_views = json.dumps(
        _serialized_views(views),
        separators=(",", ":"),
    ).replace("<", "\\u003c")
    serialized_layout = json.dumps(_BASE_LAYOUT, separators=(",", ":"))
    post_script = (
        _POST_SCRIPT.replace("__VIEWS_JSON__", serialized_views)
        .replace("__LAYOUT_JSON__", serialized_layout)
        .replace("__MAX_DEPTH__", str(max_depth))
    )

    initial_view = views[_MetricMode.FILE_TOUCHES][root.id]
    initial_trace = {**_trace_dict(initial_view), "maxdepth": max_depth + 1}
    figure = go.Figure(
        data=[initial_trace],
        layout={
            **_BASE_LAYOUT,
            "title": {
                "text": f"File touches: {root.path}",
                "x": 0.5,
                "xanchor": "center",
            },
        },
    )
    return pio.to_html(
        figure,
        config={"responsive": True, "displaylogo": False},
        include_plotlyjs=True,
        full_html=True,
        post_script=post_script,
        div_id="kpatch-commit-sunburst",
        default_width="100%",
        default_height="100%",
    )


def show_commit_sunburst(
    commits: list[GitCommit],
    *,
    min_sector_fraction: float = 0.01,
    max_depth: int = 3,
    open_browser: bool = True,
) -> Path:
    """Render commit file touches as an interactive sunburst in a browser.

    The returned temporary HTML file is intentionally retained so that the
    browser can load it asynchronously and callers can save or remove it.
    ``max_depth`` counts child rings outside the currently selected folder.
    """

    if not math.isfinite(min_sector_fraction) or not (
        0 <= min_sector_fraction < 1
    ):
        raise ValueError("min_sector_fraction must be finite and in [0, 1)")
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 1:
        raise ValueError("max_depth must be a positive integer")

    root = _build_commit_tree(commits)
    if root.file_touches == 0:
        raise ValueError("commits do not contain any changed files")

    rendered_html = _render_html(root, min_sector_fraction, max_depth)
    with NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix="kpatch-commits-",
        suffix=".html",
        delete=False,
    ) as output:
        output.write(rendered_html)
        output_path = Path(output.name)

    if open_browser:
        webbrowser.open(output_path.resolve().as_uri(), new=2)
    return output_path
