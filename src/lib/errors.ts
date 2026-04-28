// Typed error classes for the LLMO CLI. Every error path in the codebase
// throws one of these (or a subclass) so that consumers, tests, and the
// CLI's exit-code logic can discriminate between failure modes without
// string-matching messages.

export interface SchemaIssue {
  path: string;
  message: string;
  keyword: string;
}

export class LlmoError extends Error {
  public readonly section: string | undefined;
  constructor(message: string, section?: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'LlmoError';
    this.section = section;
  }
}

export class JcsError extends LlmoError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, '§4.3.2', options);
    this.name = 'JcsError';
  }
}

export class JwsError extends LlmoError {
  constructor(message: string, section: string = '§4.3.1', options?: { cause?: unknown }) {
    super(message, section, options);
    this.name = 'JwsError';
  }
}

export class SchemaError extends LlmoError {
  public readonly issues: readonly SchemaIssue[];
  constructor(message: string, issues: readonly SchemaIssue[]) {
    super(message, '§3');
    this.name = 'SchemaError';
    this.issues = issues;
  }
}

export class JwksError extends LlmoError {
  constructor(message: string, section: string = '§4.2', options?: { cause?: unknown }) {
    super(message, section, options);
    this.name = 'JwksError';
  }
}
