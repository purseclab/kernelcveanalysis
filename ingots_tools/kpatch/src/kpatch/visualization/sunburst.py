from collections import deque
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
    file_touches: int = 0

    @property
    def unique_commits(self) -> int:
        return len(self.commit_ids)


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
    hidden_items: int = 0


@dataclass(frozen=True, slots=True)
class _Breadcrumb:
    id: str
    label: str


@dataclass(frozen=True, slots=True)
class _ChartView:
    root_id: str
    root_path: str
    mode: _MetricMode
    breadcrumbs: tuple[_Breadcrumb, ...]
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
            node.file_touches = node.unique_commits
            return

        for child in node.children.values():
            finalize(child)
            node.commit_ids.update(child.commit_ids)
            node.file_touches += child.file_touches

    finalize(root)
    return root


def _node_weight(node: _TreeNode, mode: _MetricMode) -> int:
    if mode is _MetricMode.FILE_TOUCHES:
        return node.file_touches
    return node.unique_commits


def _allocated_children(
    node: _TreeNode,
    mode: _MetricMode,
    node_fraction: float,
) -> list[tuple[_TreeNode, float]]:
    children = sorted(
        node.children.values(),
        key=lambda child: (-_node_weight(child, mode), child.path, child.kind),
    )
    total_weight = sum(_node_weight(child, mode) for child in children)
    if total_weight == 0:
        return []

    allocations: list[tuple[_TreeNode, float]] = []
    remaining = node_fraction
    for index, child in enumerate(children):
        if index == len(children) - 1:
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

    def visit(node: _TreeNode, parent_id: str, fraction: float) -> None:
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
            visit(child, node.id, child_fraction)

        if hidden:
            hidden_children = [child for child, _ in hidden]
            hidden_commits: set[str] = set()
            for child in hidden_children:
                hidden_commits.update(child.commit_ids)
            hidden_fraction = fraction - sum(
                child_fraction for _, child_fraction in visible
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
                    hidden_items=item_count,
                )
            )

    visit(root, "", 1.0)
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
    return _ChartView(
        root_id=root.id,
        root_path=root.path,
        mode=mode,
        breadcrumbs=tuple(breadcrumbs),
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


def _build_reachable_views(
    root: _TreeNode,
    min_sector_fraction: float,
) -> dict[_MetricMode, dict[str, _ChartView]]:
    directories = _directory_index(root)
    views: dict[_MetricMode, dict[str, _ChartView]] = {
        mode: {} for mode in _MetricMode
    }
    pending = deque([root.id])
    queued = {root.id}

    while pending:
        root_id = pending.popleft()
        chart_root = directories[root_id]
        for mode in _MetricMode:
            view = _build_chart_view(chart_root, mode, min_sector_fraction)
            views[mode][root_id] = view
            for view_node in view.nodes:
                if (
                    view_node.kind is _NodeKind.DIRECTORY
                    and view_node.id not in queued
                ):
                    queued.add(view_node.id)
                    pending.append(view_node.id)

    return views


def _hover_text(node: _ViewNode) -> str:
    details = [
        f"<b>{escape(node.path)}</b>",
        f"Type: {escape(node.kind.value)}",
        f"File touches: {node.file_touches:,}",
        f"Unique commits: {node.unique_commits:,}",
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
            [node.kind.value, node.file_touches, node.unique_commits]
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

const style = document.createElement("style");
style.textContent = `
  html, body { height: 100%; margin: 0; background: #fafafa; }
  body { font-family: system-ui, sans-serif; color: #1f2937; }
  .kpatch-toolbar { box-sizing: border-box; min-height: 58px; padding: 10px 16px;
    display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
    border-bottom: 1px solid #d1d5db; background: white; }
  .kpatch-toolbar button, .kpatch-toolbar select { font: inherit; padding: 5px 9px;
    border: 1px solid #9ca3af; border-radius: 5px; background: white; }
  .kpatch-toolbar button:not(:disabled) { cursor: pointer; }
  .kpatch-toolbar button:disabled { opacity: .45; }
  .kpatch-breadcrumbs { display: flex; align-items: center; gap: 0; flex-wrap: wrap; }
  .kpatch-breadcrumbs button { border: 0; color: #2563eb; padding: 3px 1px; }
  .kpatch-breadcrumbs button:hover { text-decoration: underline; }
  .kpatch-separator { color: #6b7280; }
`;
document.head.appendChild(style);
graph.style.height = "calc(100vh - 58px)";

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
`;
modeSelect.addEventListener("change", () => {
  mode = modeSelect.value;
  render();
});
modeLabel.appendChild(modeSelect);
toolbar.appendChild(modeLabel);

const breadcrumbs = document.createElement("nav");
breadcrumbs.className = "kpatch-breadcrumbs";
breadcrumbs.setAttribute("aria-label", "Directory path");
toolbar.appendChild(breadcrumbs);
graph.parentNode.insertBefore(toolbar, graph);

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

function render() {
  const view = currentView();
  const modeTitle = mode === "file_touches" ? "File touches" : "Unique commits";
  const layout = Object.assign({}, layoutBase, {
    title: {text: `${modeTitle}: ${view.rootPath}`, x: 0.5, xanchor: "center"}
  });
  back.disabled = view.breadcrumbs.length === 1;
  updateBreadcrumbs();
  Plotly.react(graph, [view.trace], layout, config);
}

graph.on("plotly_sunburstclick", event => {
  const point = event.points && event.points[0];
  if (point && point.id !== rootId && views[mode][point.id]) {
    rootId = point.id;
    render();
  }
  return false;
});

render();
"""


def _render_html(root: _TreeNode, min_sector_fraction: float) -> str:
    views = _build_reachable_views(root, min_sector_fraction)
    serialized_views = json.dumps(
        _serialized_views(views),
        separators=(",", ":"),
    ).replace("<", "\\u003c")
    serialized_layout = json.dumps(_BASE_LAYOUT, separators=(",", ":"))
    post_script = _POST_SCRIPT.replace("__VIEWS_JSON__", serialized_views).replace(
        "__LAYOUT_JSON__", serialized_layout
    )

    initial_view = views[_MetricMode.FILE_TOUCHES][root.id]
    figure = go.Figure(
        data=[_trace_dict(initial_view)],
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
    open_browser: bool = True,
) -> Path:
    """Render commit file touches as an interactive sunburst in a browser.

    The returned temporary HTML file is intentionally retained so that the
    browser can load it asynchronously and callers can save or remove it.
    """

    if not math.isfinite(min_sector_fraction) or not (
        0 <= min_sector_fraction < 1
    ):
        raise ValueError("min_sector_fraction must be finite and in [0, 1)")

    root = _build_commit_tree(commits)
    if root.file_touches == 0:
        raise ValueError("commits do not contain any changed files")

    rendered_html = _render_html(root, min_sector_fraction)
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
