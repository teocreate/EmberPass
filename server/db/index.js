import { config } from '../config.js';
import { createMemoryStore } from './memory.js';
import { createPostgresStore } from './pg.js';

let store = null;

export async function getStore() {
  if (store) return store;
  store = config.databaseUrl ? await createPostgresStore(config.databaseUrl) : createMemoryStore();
  return store;
}

export async function closeStore() {
  if (!store) return;
  await store.close();
  store = null;
}
