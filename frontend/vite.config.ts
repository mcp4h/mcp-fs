import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import { resolve } from "path";
export default defineConfig(
	{
		plugins: [vue(), { name: "rewrite-index-for-bridge", apply: "build" }],
		build: {
			outDir: resolve(__dirname, "../assets/ui/browser"),
			emptyOutDir: true,
			cssCodeSplit: false,
			modulePreload: false,
			rollupOptions: {
				input: resolve(__dirname, "index.html"),
				output: {
					format: "iife",
					inlineDynamicImports: true,
					entryFileNames: "app.js",
					chunkFileNames: "app.js",
					assetFileNames: (assetInfo) => {
						if (assetInfo.name && assetInfo.name.endsWith(".css")) {
							return "app.css";
						}
						return "assets/[name][extname]";
					}
				}
			}
		}
	}
);
