import { Config } from './types';
let config: Config;

export function init(cfg: Config) {
  config = cfg;
}

export function getConfig(): Config {
  if (!config) {
    throw new Error('Auth package not initialized. Call init() first.');
  }
  return config;
}