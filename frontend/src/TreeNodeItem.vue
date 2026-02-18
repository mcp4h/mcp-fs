<template>
	<div v-if="isVisible(node)" class="tree-node">
		<button
			class="tree-entry"
			type="button"
			:class="{ active: node.path === selectedPath, matched: isMatched(node) }"
			:style="{ paddingLeft: `${12 + level * 16}px` }"
			@click="handleClick">
			<span class="caret" :class="{ open: node.isDir && isExpanded(node) }">
				<svg
					v-if="node.isDir"
					viewBox="0 0 16 16"
					class="caret-icon">
					<path d="M6 4.5 10 8l-4 3.5"/>
				</svg>
			</span>
			<span class="icon" aria-hidden="true">
				<svg
					v-if="node.isDir"
					viewBox="0 0 24 24"
					class="icon-svg">
					<path
						d="M3 6.5A2.5 2.5 0 0 1 5.5 4h4.8c.7 0 1.4.3 1.9.8l1.2 1.2h5.1A2.5 2.5 0 0 1 21 8.5v8A2.5 2.5 0 0 1 18.5 19h-13A2.5 2.5 0 0 1 3 16.5z"/>
					<path d="M3 9h18"/>
				</svg>
				<svg
					v-else
					viewBox="0 0 24 24"
					class="icon-svg">
					<path d="M6.5 3h7l4 4v12.5A1.5 1.5 0 0 1 16 21h-9a1.5 1.5 0 0 1-1.5-1.5v-15A1.5 1.5 0 0 1 6.5 3z"/>
					<path d="M13.5 3v4h4"/>
				</svg>
			</span>
			<span class="entry-name">{{ node.name }}</span>
		</button>
		<div v-if="node.isDir && isExpanded(node)" class="tree-children">
			<TreeNodeItem
				v-for="child in node.children"
				:key="child.path"
				:node="child"
				:level="level + 1"
				:selected-path="selectedPath"
				:filter-active="filterActive"
				:is-visible="isVisible"
				:is-matched="isMatched"
				:is-expanded="isExpanded"
				:on-toggle="onToggle"
				:on-select="onSelect"/>
		</div>
	</div>
</template>
<script setup lang="ts">
	import type { TreeNode } from "./types";
	const props = defineProps<{
		node: TreeNode;
		level: number;
		selectedPath: string;
		filterActive: boolean;
		isVisible: (node: TreeNode) => boolean;
		isMatched: (node: TreeNode) => boolean;
		isExpanded: (node: TreeNode) => boolean;
		onToggle: (node: TreeNode) => void;
		onSelect: (node: TreeNode) => void;
	}>();
	function handleClick() {
		if (props.node.isDir) {
			props.onToggle(props.node);
		}
		else {
			props.onSelect(props.node);
		}
	}
</script>
