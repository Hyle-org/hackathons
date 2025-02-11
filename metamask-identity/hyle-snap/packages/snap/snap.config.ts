import { merge, SnapConfig } from '@metamask/snaps-cli';
import { resolve } from 'path';

require('@babel/core').transformSync('code', {
  plugins: [['@babel/plugin-proposal-decorators', { version: '2023-11' }]],
});

const config: SnapConfig = {
  bundler: 'webpack',
  input: resolve(__dirname, 'src/index.tsx'),
  server: {
    port: 8080,
  },
  polyfills: {
    buffer: true,
  },
};

export default config;
