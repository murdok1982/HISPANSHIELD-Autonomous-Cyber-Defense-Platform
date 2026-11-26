/**
 * Deterministic, force-less radial layout for the asset relationship graph.
 *
 * No external graph library: nodes are grouped by BFS depth from the root and
 * placed on concentric rings, which keeps the drawing stable between renders
 * (a physical simulation would move on every refetch and hurt legibility).
 */
import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import type { AssetGraph, GraphEdge, GraphNode } from "./types";
import { useI18n } from "../../../lib/i18n";

export interface PlacedNode {
  node: GraphNode;
  x: number;
  y: number;
  depth: number;
}

export interface PlacedEdge {
  edge: GraphEdge;
  from: { x: number; y: number };
  to: { x: number; y: number };
}

export interface GraphLayout {
  nodes: PlacedNode[];
  edges: PlacedEdge[];
  root: PlacedNode | null;
}

export function layoutGraph(graph: AssetGraph, width = 720, height = 440): GraphLayout {
  const rootId = graph.root_id;
  const adjacency = new Map<string, string[]>();
  for (const node of graph.nodes) adjacency.set(node.id, []);
  for (const edge of graph.edges) {
    adjacency.get(edge.source_asset_id)?.push(edge.target_asset_id);
    adjacency.get(edge.target_asset_id)?.push(edge.source_asset_id);
  }

  const depths = new Map<string, number>([[rootId, 0]]);
  const queue: string[] = [rootId];
  while (queue.length) {
    const current = queue.shift() as string;
    const depth = depths.get(current) ?? 0;
    for (const neighbour of adjacency.get(current) ?? []) {
      if (depths.has(neighbour)) continue;
      depths.set(neighbour, depth + 1);
      queue.push(neighbour);
    }
  }

  // Nodes unreachable from the root are still known relationships: keep them
  // in the outermost ring instead of silently hiding them.
  const unreachableDepth = Math.max(1, ...Array.from(depths.values())) + 1;
  for (const node of graph.nodes) {
    if (!depths.has(node.id)) depths.set(node.id, unreachableDepth);
  }

  const groups = new Map<number, GraphNode[]>();
  for (const node of graph.nodes) {
    const depth = depths.get(node.id) ?? unreachableDepth;
    const bucket = groups.get(depth) ?? [];
    bucket.push(node);
    groups.set(depth, bucket);
  }

  const cx = width / 2;
  const cy = height / 2;
  const maxDepth = Math.max(1, ...Array.from(groups.keys()));
  const maxRadius = Math.min(width, height) / 2 - 58;
  const positions = new Map<string, { x: number; y: number }>();

  for (const [depth, bucket] of Array.from(groups.entries()).sort((a, b) => a[0] - b[0])) {
    if (depth === 0) {
      const rootNode = bucket[0];
      if (rootNode) positions.set(rootNode.id, { x: cx, y: cy });
      continue;
    }
    const radius = (maxRadius / maxDepth) * depth;
    const count = bucket.length;
    bucket.forEach((node, index) => {
      const angle = -Math.PI / 2 + (index * (2 * Math.PI)) / Math.max(1, count);
      positions.set(node.id, { x: cx + Math.cos(angle) * radius, y: cy + Math.sin(angle) * radius });
    });
  }

  const placedNodes: PlacedNode[] = graph.nodes.map((node) => {
    const position = positions.get(node.id) ?? { x: cx, y: cy };
    return { node, x: position.x, y: position.y, depth: depths.get(node.id) ?? 0 };
  });
  const positionById = new Map(placedNodes.map((item) => [item.node.id, item]));

  const placedEdges: PlacedEdge[] = [];
  for (const edge of graph.edges) {
    const from = positionById.get(edge.source_asset_id);
    const to = positionById.get(edge.target_asset_id);
    if (!from || !to) continue;
    placedEdges.push({ edge, from: { x: from.x, y: from.y }, to: { x: to.x, y: to.y } });
  }

  return { nodes: placedNodes, edges: placedEdges, root: positionById.get(rootId) ?? null };
}

function nodeColor(criticality: number): string {
  if (criticality >= 5) return "var(--critical)";
  if (criticality === 4) return "var(--danger)";
  if (criticality === 3) return "var(--warning)";
  if (criticality >= 1) return "var(--accent)";
  return "var(--dim)";
}

function truncateLabel(value: string, max = 16): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

export function AssetGraphView({ graph }: { graph: AssetGraph }) {
  const navigate = useNavigate();
  const { lang } = useI18n();
  const layout = useMemo(() => layoutGraph(graph), [graph]);
  const width = 720;
  const height = 440;

  if (!graph.nodes.length) {
    return (
      <div className="empty-state" style={{ padding: 28 }}>
        <p>{lang === "es" ? "Sin nodos en el grafo" : "No nodes in the graph"}</p>
      </div>
    );
  }

  return (
    <div className="chart-wrap" style={{ overflow: "hidden" }}>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        style={{ width: "100%", height: "auto", display: "block" }}
        role="img"
        aria-label={
          lang === "es"
            ? `Grafo de relaciones: ${graph.nodes.length} activos, ${graph.edges.length} relaciones, profundidad ${graph.depth}`
            : `Relationship graph: ${graph.nodes.length} assets, ${graph.edges.length} relationships, depth ${graph.depth}`
        }
      >
        <title>{lang === "es" ? "Grafo radial de relaciones entre activos" : "Radial asset relationship graph"}</title>
        <defs>
          <marker id="asset-edge-arrow" viewBox="0 0 10 10" refX="18" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--border-strong)" />
          </marker>
        </defs>

        {layout.edges.map(({ edge, from, to }) => (
          <line
            key={edge.id}
            x1={from.x}
            y1={from.y}
            x2={to.x}
            y2={to.y}
            stroke="var(--border-strong)"
            strokeWidth={1}
            strokeOpacity={0.6}
            markerEnd="url(#asset-edge-arrow)"
          />
        ))}

        {layout.nodes.map(({ node, x, y, depth }) => {
          const isRoot = node.id === graph.root_id;
          const color = isRoot ? "var(--accent)" : nodeColor(node.criticality);
          return (
            <g
              key={node.id}
              role="button"
              tabIndex={0}
              aria-label={`${node.name} · ${node.kind} · ${node.criticality}/5`}
              style={{ cursor: isRoot ? "default" : "pointer" }}
              onClick={() => {
                if (!isRoot) navigate(`/assets/${node.id}`);
              }}
              onKeyDown={(event) => {
                if ((event.key === "Enter" || event.key === " ") && !isRoot) {
                  event.preventDefault();
                  navigate(`/assets/${node.id}`);
                }
              }}
            >
              <circle
                cx={x}
                cy={y}
                r={isRoot ? 28 : 22}
                fill={isRoot ? "var(--accent-soft)" : "var(--surface-2)"}
                stroke={color}
                strokeWidth={isRoot ? 2.4 : 1.6}
              />
              <text
                x={x}
                y={y + 4}
                textAnchor="middle"
                fontSize={9}
                fontFamily="var(--font-mono)"
                fill="var(--text-secondary)"
              >
                {truncateLabel(node.asset_key, isRoot ? 14 : 11)}
              </text>
              <text
                x={x}
                y={y + (isRoot ? 44 : 38)}
                textAnchor="middle"
                fontSize={9}
                fill="var(--muted)"
                fontFamily="var(--font-sans)"
              >
                {truncateLabel(node.name, 22)}
              </text>
              {depth > 0 ? (
                <text x={x} y={y - 30} textAnchor="middle" fontSize={8} fontFamily="var(--font-mono)" fill="var(--dim)">
                  d{depth}
                </text>
              ) : null}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
