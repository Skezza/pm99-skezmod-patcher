/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_COUNTER_API_BASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
