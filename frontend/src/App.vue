<template>
	<div class="app-shell">
		<header class="toolbar">
			<div class="title-block">
				<p class="kicker">MCP Files</p>
				<h1>Browser</h1>
			</div>
			<div class="toolbar-controls">
				<label class="field">
					<span>Root</span>
					<select v-model="currentRoot" @change="handleRootChange">
						<option
							v-for="root in roots"
							:key="root.path"
							:value="root.path">{{ root.path }}</option>
					</select>
				</label>
				<div class="field search-field">
					<span>Find</span>
					<input
						v-model="query"
						type="search"
						placeholder="Search files or content"
						@input="queueSearch"/>
				</div>
				<div class="mode-toggle">
					<button
						type="button"
						:class="{ active: searchMode === 'name' }"
						@click="setSearchMode('name')">
						Name
					</button>
					<button
						type="button"
						:class="{ active: searchMode === 'content' }"
						@click="setSearchMode('content')">
						Content
					</button>
				</div>
				<button
					class="refresh"
					type="button"
					@click="refreshAll"
					:disabled="loading">
					Refresh
				</button>
			</div>
		</header>
		<div class="status-bar">
			<div class="status">
				<span v-if="loading">Loading tree…</span>
				<span v-else-if="error">{{ error }}</span>
				<span v-else>{{ treeSummary }}</span>
			</div>
			<div class="status" v-if="query">{{ searchSummary }}</div>
		</div>
		<main class="workspace">
			<section class="pane pane-tree">
				<div class="pane-header">
					<h2>Files</h2>
					<span>{{ currentRootLabel }}</span>
				</div>
				<div class="pane-body">
					<div v-if="!treeNodes.length && !loading" class="empty">
						No entries found for this root.
					</div>
					<TreeNodeItem
						v-for="node in treeNodes"
						:key="node.path"
						:node="node"
						:level="0"
						:selected-path="selectedPath"
						:filter-active="filterActive"
						:is-visible="isVisible"
						:is-matched="isMatched"
						:is-expanded="isExpanded"
						:on-toggle="toggleNode"
						:on-select="openFile"/>
				</div>
			</section>
			<section class="pane pane-preview">
				<div class="pane-header">
					<h2>Preview</h2>
					<div class="pane-actions">
						<span>{{ selectedPath || "No file selected" }}</span>
						<button
							class="copy"
							type="button"
							:disabled="!selectedPath || previewLoading"
							@click="copyToClipboard">{{ copyLabel }}</button>
					</div>
				</div>
				<div class="pane-body">
					<div v-if="!selectedPath" class="empty">
						Select a file to view highlighted content.
					</div>
					<div v-else-if="previewError" class="empty">{{ previewError }}</div>
					<div v-else-if="previewLoading" class="empty">
						Loading file…
					</div>
					<div
						v-else
						class="preview"
						v-html="previewHtml"></div>
				</div>
			</section>
		</main>
	</div>
</template>
<script setup lang="ts">
	import { computed, onMounted, ref } from "vue";
	import TreeNodeItem from "./TreeNodeItem.vue";
	import type { TreeNode } from "./types";
	type RootItem = { path: string; default?: boolean };
	type SearchMode = "name" | "content";
	const roots = ref<RootItem[]>([]);
	const currentRoot = ref(".");
	const treeNodes = ref<TreeNode[]>([]);
	const selectedPath = ref("");
	const previewHtml = ref("");
	const loading = ref(false);
	const previewLoading = ref(false);
	const error = ref("");
	const previewError = ref("");
	const copyLabel = ref("Copy");
	const query = ref("");
	const searchMode = ref<SearchMode>("name");
	const matchPaths = ref<Set<string>>(new Set());
	const visiblePaths = ref<Set<string> | null>(null);
	const hasVisibleChildPaths = ref<Set<string>>(new Set());
	let searchTimer: number | undefined;
	const filterActive = computed(() => query.value.trim().length > 0);
	const currentRootLabel = computed(
		() => {
			if (!currentRoot.value) return "";
			const rootEntry = roots.value.find((root) => root.path === currentRoot.value);
			if (!rootEntry) return currentRoot.value;
			return rootEntry.default ? `${rootEntry.path} (default)` : rootEntry.path;
		}
	);
	const treeSummary = computed(
		() => {
			const count = countNodes(treeNodes.value);
			return `${count.files} file${count.files === 1 ? "" : "s"}, ${count.dirs} folder${
				count.dirs === 1 ? "" : "s"
			}`;
		}
	);
	const searchSummary = computed(
		() => {
			if (!filterActive.value) return "";
			const matches = matchPaths.value.size;
			const label = searchMode.value === "content" ? "content" : "name";
			return `${matches} match${matches === 1 ? "" : "es"} (${label})`;
		}
	);
	function ensureMcp() {
		const mcp = (window as unknown as { mcp?: { callTool?: any } }).mcp;
		if (!mcp?.callTool) {
			throw new Error("mcp.callTool unavailable");
		}
		return mcp.callTool.bind(mcp);
	}
	async function callTool(name: string, argumentsParam: Record<string, unknown> = {}, meta?: Record<string, unknown>) {
		const call = ensureMcp();
		const payload: { name: string; arguments?: Record<string, unknown>; _meta?: Record<string, unknown> } = { name, arguments: argumentsParam };
		if (meta) {
			payload._meta = meta;
		}
		console.debug("[mcp-ui] tool call", payload);
		const result = await call(payload);
		console.debug("[mcp-ui] tool result", name, result);
		return result;
	}
	function resolvePath(root: string, rel: string) {
		if (!rel) return root;
		if (rel.startsWith("/")) return rel;
		if (root === "." || root === "") return rel;
		if (root.endsWith("/")) return `${root}${rel}`;
		return `${root}/${rel}`;
	}
	function normalizeEntry(entry: string) {
		if (entry.endsWith("/")) {
			return { path: entry.slice(0, -1), isDir: true };
		}
		return { path: entry, isDir: false };
	}
	function buildTree(matches: string[]) {
		const nodes = new Map<string, TreeNode>();
		const rootsOut: TreeNode[] = [];
		const expanded = new Set(treeNodes.value.flatMap((node) => collectExpanded(node)));
		const getNode = (path: string, name: string, isDir: boolean) => {
			const key = `${path}|${isDir ? "dir" : "file"}`;
			const existing = nodes.get(key);
			if (existing) return existing;
			const node: TreeNode = {
				name,
				path,
				isDir,
				children: [],
				expanded: expanded.has(path)
			};
			nodes.set(key, node);
			return node;
		};
		matches.map(normalizeEntry)
			.forEach(
				({ path, isDir }) => {
					if (!path) return;
					const parts = path.split("/");
					let currentPath = "";
					let parentNode: TreeNode | null = null;
					parts.forEach(
						(segment, index) => {
							currentPath = currentPath ? `${currentPath}/${segment}` : segment;
							const isLeaf = index === parts.length - 1;
							const nodeIsDir = isLeaf ? isDir : true;
							const node = getNode(currentPath, segment, nodeIsDir);
							if (parentNode && !parentNode.children.includes(node)) {
								parentNode.children.push(node);
							}
							if (!parentNode && !rootsOut.includes(node)) {
								rootsOut.push(node);
							}
							parentNode = node;
						}
					);
				}
			);
		const sortTree = (node: TreeNode) => {
			node.children
				.sort(
					(a, b) => {
						if (a.isDir && !b.isDir) return -1;
						if (!a.isDir && b.isDir) return 1;
						return a.name.localeCompare(b.name);
					}
				);
			node.children.forEach(sortTree);
		};
		rootsOut.sort(
			(a, b) => {
				if (a.isDir && !b.isDir) return -1;
				if (!a.isDir && b.isDir) return 1;
				return a.name.localeCompare(b.name);
			}
		);
		rootsOut.forEach(sortTree);
		treeNodes.value = rootsOut;
		updateVisibility();
	}
	function collectExpanded(node: TreeNode) {
		const paths = node.expanded ? [node.path] : [];
		node.children.forEach((child) => paths.push(...collectExpanded(child)));
		return paths;
	}
	function countNodes(nodes: TreeNode[]) {
		let files = 0;
		let dirs = 0;
		const walk = (node: TreeNode) => {
			if (node.isDir) {
				dirs += 1;
			}
			else {
				files += 1;
			}
			node.children.forEach(walk);
		};
		nodes.forEach(walk);
		return { files, dirs };
	}
	function updateVisibility() {
		if (!filterActive.value) {
			visiblePaths.value = null;
			hasVisibleChildPaths.value = new Set();
			return;
		}
		const visible = new Set<string>();
		const hasVisibleChild = new Set<string>();
		const matches = matchPaths.value;
		const mark = (node: TreeNode): boolean => {
			let isVisibleNode = matches.has(node.path);
			let childVisible = false;
			node.children.forEach(
				(child) => {
					if (mark(child)) {
						childVisible = true;
					}
				}
			);
			if (childVisible) {
				hasVisibleChild.add(node.path);
			}
			if (isVisibleNode || childVisible) {
				visible.add(node.path);
			}
			return isVisibleNode || childVisible;
		};
		treeNodes.value.forEach((node) => mark(node));
		visiblePaths.value = visible;
		hasVisibleChildPaths.value = hasVisibleChild;
	}
	function isVisible(node: TreeNode) {
		if (!filterActive.value) return true;
		return visiblePaths.value?.has(node.path) ?? false;
	}
	function isMatched(node: TreeNode) {
		if (!filterActive.value) return false;
		return matchPaths.value.has(node.path);
	}
	function isExpanded(node: TreeNode) {
		if (!filterActive.value) return node.expanded;
		if (hasVisibleChildPaths.value.has(node.path)) return true;
		return node.expanded;
	}
	function toggleNode(node: TreeNode) {
		if (!node.isDir) return;
		node.expanded = !node.expanded;
	}
	async function openFile(node: TreeNode) {
		if (node.isDir) return;
		previewLoading.value = true;
		previewError.value = "";
		selectedPath.value = node.path;
		copyLabel.value = "Copy";
		try {
			const absolutePath = resolvePath(currentRoot.value, node.path);
			const result = await callTool("read_file", { path: absolutePath, limit: 0 }, { highlight: true });
			const structured = result?.structuredContent ?? result;
			previewHtml.value = structured?.content || "";
		}
		catch (err) {
			previewError.value = errinstanceofError ? err.message : "Failed to load file";
		}
		finally {
			previewLoading.value = false;
		}
	}
	function stripLineNumbers(content: string) {
		return content.split("\n").map((line) => line.replace(/^\d+:\s?/, "")).join("\n");
	}
	async function copyToClipboard() {
		if (!selectedPath.value) return;
		copyLabel.value = "Copying…";
		try {
			const absolutePath = resolvePath(currentRoot.value, selectedPath.value);
			const result = await callTool("read_file", { path: absolutePath, limit: 0 });
			const structured = result?.structuredContent ?? result;
			const raw = structured?.content ? String(structured.content) : "";
			const cleaned = stripLineNumbers(raw);
			if (navigator.clipboard?.writeText) {
				await navigator.clipboard.writeText(cleaned);
			}
			else {
				const textarea = document.createElement("textarea");
				textarea.value = cleaned;
				textarea.setAttribute("readonly", "true");
				textarea.style.position = "absolute";
				textarea.style.left = "-9999px";
				document.body.appendChild(textarea);
				textarea.select();
				document.execCommand("copy");
				textarea.remove();
			}
			copyLabel.value = "Copied";
			window.setTimeout(
				() => {
					copyLabel.value = "Copy";
				},
				1200
			);
		}
		catch (err) {
			copyLabel.value = "Copy";
			previewError.value = errinstanceofError ? err.message : "Copy failed";
		}
	}
	async function loadRoots() {
		const result = await callTool("list_roots");
		const structured = result?.structuredContent ?? result;
		console.debug("[mcp-ui] list_roots structured", structured);
		const items = (structured?.roots || []) as RootItem[];
		roots.value = items;
		const defaultRoot = items.find((root) => root.default)?.path;
		currentRoot.value = defaultRoot || items[0]?.path || ".";
	}
	async function loadTree() {
		if (!currentRoot.value) return;
		loading.value = true;
		error.value = "";
		try {
			const result = await callTool("find_files", { root: currentRoot.value, pattern: "", limit: 0 });
			const structured = result?.structuredContent ?? result;
			console.debug("[mcp-ui] find_files structured", structured);
			const matches = (structured?.matches || []) as string[];
			buildTree(matches);
		}
		catch (err) {
			error.value = errinstanceofError ? err.message : "Failed to load tree";
			treeNodes.value = [];
		}
		finally {
			loading.value = false;
		}
	}
	async function runSearch() {
		const term = query.value.trim();
		if (!term) {
			matchPaths.value = new Set();
			updateVisibility();
			return;
		}
		try {
			if (searchMode.value === "name") {
				const result = await callTool("find_files", {
					root: currentRoot.value,
					pattern: term,
					glob: true,
					limit: 0
				});
				const structured = result?.structuredContent ?? result;
				const entries = (structured?.matches || []) as string[];
				const normalized = entries.map((entry) => normalizeEntry(entry).path);
				matchPaths.value = new Set(normalized);
			}
			else {
				const result = await callTool("search_files", { root: currentRoot.value, pattern: term, context: 0 });
				const structured = result?.structuredContent ?? result;
				const files = (structured?.files || []) as Array<{ path: string }>;
				matchPaths.value = new Set(files.map((file) => file.path));
			}
		}
		catch (err) {
			error.value = errinstanceofError ? err.message : "Search failed";
			matchPaths.value = new Set();
		}
		finally {
			updateVisibility();
		}
	}
	function queueSearch() {
		if (searchTimer) {
			window.clearTimeout(searchTimer);
		}
		searchTimer = window.setTimeout(
			() => {
				runSearch();
			},
			250
		);
	}
	function setSearchMode(mode: SearchMode) {
		if (searchMode.value === mode) return;
		searchMode.value = mode;
		if (query.value.trim()) {
			runSearch();
		}
	}
	async function refreshAll() {
		await loadTree();
		if (query.value.trim()) {
			await runSearch();
		}
	}
	async function handleRootChange() {
		selectedPath.value = "";
		previewHtml.value = "";
		matchPaths.value = new Set();
		query.value = "";
		await loadTree();
	}
	onMounted(
		async() => {
			try {
				await loadRoots();
				await loadTree();
			}
			catch (err) {
				error.value = errinstanceofError ? err.message : "Failed to initialize";
			}
		}
	);
</script>
