// ReDoS fixtures for the probe tests.
export const vulnerable = (s) => /^(\w+\s?)*$/.test(s);
export const linear = (s) => /^\w+(?:\s\w+)*$/.test(s);
