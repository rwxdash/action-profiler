// See: https://rollupjs.org/introduction/

import commonjs from '@rollup/plugin-commonjs'
import json from '@rollup/plugin-json'
import nodeResolve from '@rollup/plugin-node-resolve'
import typescript from '@rollup/plugin-typescript'

function plugins() {
  return [
    typescript(),
    nodeResolve({ preferBuiltins: true }),
    commonjs(),
    json()
  ]
}

const shared = {
  esModule: true,
  format: 'es',
  sourcemap: true
}

export default [
  {
    input: 'src/main.ts',
    output: { ...shared, file: 'dist/main/index.js' },
    plugins: plugins()
  },
  {
    input: 'src/post.ts',
    output: { ...shared, file: 'dist/post/index.js' },
    plugins: plugins()
  }
]
