const PYTHON_TEST_FILE_RE =
  /(?:^|\/)(?:tests?|__tests__)\/|(?:^|\/)(?:test_.*|.*_(?:test|spec))\.py$/i;

export function isPythonTestFile(filePath: string): boolean {
  return PYTHON_TEST_FILE_RE.test(filePath);
}
