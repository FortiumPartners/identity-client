/** @type {import('jest').Config} */
export default {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  roots: ['<rootDir>/tests', '<rootDir>/packages'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
    '^@fortium/identity-client$': '<rootDir>/packages/core/src/index.ts',
  },
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      useESM: true,
      tsconfig: {
        target: 'ES2022',
        module: 'ESNext',
        moduleResolution: 'bundler',
        esModuleInterop: true,
        strict: true,
        skipLibCheck: true,
        lib: ['ES2022', 'DOM'],
      },
    }],
  },
  testMatch: ['**/tests/**/*.test.ts'],
  modulePathIgnorePatterns: ['<rootDir>/packages/.*/dist'],
};
