export type TreeNode = {
	name: string;
	path: string;
	isDir: boolean;
	children: TreeNode[];
	expanded: boolean;
};
