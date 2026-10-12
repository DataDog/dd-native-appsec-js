/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
type rules = object;

type diagnosticsInfo = {
  addresses?: {
    optional: string[],
    required: string[]
  },
  loaded: string[],
  failed: string[],
  skipped?: string[],
  errors: {
    [errorString: string]: string[]
  },
  warnings?: {
    [warningString: string]: string[]
  }
}

type diagnosticsError = {
  error: string
}

type diagnosticsResult = diagnosticsInfo | diagnosticsError

type TruncationMetrics = {
  maxTruncatedString?: number;
  maxTruncatedContainerSize?: number;
  maxTruncatedContainerDepth?: number;
}

type result = {
  timeout?: boolean;
  duration?: number;
  events?: object[]; // https://github.com/DataDog/libddwaf/blob/master/schema/events.json
  /**
   * Since libddwaf 2.0 this is also set when only attributes or actions were
   * produced, so it no longer implies that a rule matched.
   * Test `events.length` rather than `status` to detect an attack.
   */
  status?: 'match';
  actions?: {
    [actionType: string]: {
      [parameter: string]: string | number | boolean
    }
  };
  attributes?: object;
  metrics: TruncationMetrics;
  errorCode?: number;
  keep?: boolean;
  evaluated?: number;
}

/**
 * Evaluates data which must not persist in the parent context. It inherits the
 * data already provided to that context, but its own data and side effects stay
 * local to it. Replaces the `ephemeral` payload of previous versions.
 */
declare class DDWAFSubcontext {
  readonly disposed: boolean;

  run(data: object, timeout: number): result;
  dispose(): void;
}

declare class DDWAFContext {
  readonly disposed: boolean;

  run(data: object, timeout: number): result;
  createSubcontext(): DDWAFSubcontext;
  dispose(): void;
}

export class DDWAF {
  static version(): string;

  readonly disposed: boolean;

  readonly configPaths: string[];

  readonly diagnostics: {
    ruleset_version?: string,
    rules?: diagnosticsResult,
    custom_rules?: diagnosticsResult,
    exclusions?: diagnosticsResult,
    rules_override?: diagnosticsResult,
    rules_data?: diagnosticsResult,
    processors?: diagnosticsResult,
    actions?: diagnosticsResult,
    scanners?: diagnosticsResult
  };

  readonly knownAddresses: Set<string>;
  readonly knownActions: Set<string>;

  constructor(rules: rules, rulesPath: string, config?: {
    obfuscatorKeyRegex?: string,
    obfuscatorValueRegex?: string
  });

  createOrUpdateConfig(config: rules, path: string): boolean;
  removeConfig(path: string): boolean;

  /**
   * Returns `null` when the instance currently has no ruleset, which is what
   * removing every configuration produces. Add a configuration back to make it
   * usable again.
   */
  createContext(): DDWAFContext | null;
  dispose(): void;
}
