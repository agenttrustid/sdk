/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  collectCoverage: true,
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/index.ts',
    '!src/types.ts',
    '!src/**/*.d.ts',
  ],
  coverageThreshold: {
    global: { statements: 82, branches: 60, functions: 85, lines: 82 },
    './src/keys.ts': { statements: 100, branches: 100, functions: 100, lines: 100 },
    './src/errors.ts': { statements: 100, branches: 100, functions: 100, lines: 100 },
  },
};
