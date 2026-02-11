import commonjs from '@rollup/plugin-commonjs';
import pluginJson from '@rollup/plugin-json';

import pkg from './package.json' with { type: 'json' };

const { module, main, dependencies, peerDependencies, optionalDependencies } = pkg;

const external = new Set(
  ['node:crypto', 'node:url', 'node:assert']
    .concat(Object.keys(dependencies))
    .concat(Object.keys(peerDependencies))
    .concat(Object.keys(optionalDependencies ?? []))
);

export default [
  {
    input: module,
    external: [...external],
    plugins: [commonjs(), pluginJson()],
    output: [
      {
        file: main,
        exports: 'named',
        format: 'cjs',
      },
    ],
  },
];
