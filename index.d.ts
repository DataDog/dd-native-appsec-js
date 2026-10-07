/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
type Rules = Readonly<Record<string, unknown>>;

type DiagnosticsMessages = Readonly<Record<string, readonly string[]>>;

type DiagnosticsResult = {
  readonly addresses?: {
    readonly optional: readonly string[];
    readonly required: readonly string[];
  };
  readonly loaded?: readonly string[];
  readonly failed?: readonly string[];
  readonly skipped?: readonly string[];
  readonly errors?: DiagnosticsMessages;
  readonly warnings?: DiagnosticsMessages;
  readonly error?: string;
};

type TruncationMetrics = {
  readonly maxTruncatedString?: number;
  readonly maxTruncatedContainerSize?: number;
  readonly maxTruncatedContainerDepth?: number;
  /** Set when the cumulative node budget stopped the conversion. */
  readonly truncatedByNodeLimit?: true;
  /** Set when the cumulative retained byte budget (keys and truncated values) stopped conversion. */
  readonly truncatedByByteLimit?: true;
}

type ActionParameters = Readonly<Record<string, string | number | boolean>>;
type Actions = Readonly<Record<string, ActionParameters>>;
type Event = Readonly<Record<string, unknown>>;

type Result = {
  readonly timeout?: boolean;
  readonly duration?: number;
  readonly events?: readonly Event[]; // https://github.com/DataDog/libddwaf/blob/master/schema/events.json
  /**
   * Since libddwaf 2.0 this is also set when only attributes or actions were
   * produced, so it no longer implies that a rule matched.
   * Test `events.length` rather than `status` to detect an attack.
   */
  readonly status?: 'match';
  readonly actions?: Actions;
  readonly attributes?: Readonly<Record<string, unknown>>;
  readonly metrics: TruncationMetrics;
  readonly errorCode?: number;
  readonly keep?: boolean;
  readonly evaluated?: number;
}

/**
 * Evaluates data which must not persist in the parent context. It inherits the
 * data already provided to that context, but its own data and side effects stay
 * local to it. Replaces the `ephemeral` payload of previous versions.
 */
declare class DDWAFSubcontext {
  readonly disposed: boolean;

  run(data: Readonly<Record<string, unknown>>, timeout: number): Result;
  dispose(): void;
}

declare class DDWAFContext {
  readonly disposed: boolean;

  run(data: Readonly<Record<string, unknown>>, timeout: number): Result;
  createSubcontext(): DDWAFSubcontext;
  dispose(): void;
}

export class DDWAF {
  static version(): string;

  readonly disposed: boolean;

  readonly configPaths: readonly string[];

  readonly diagnostics: {
    readonly ruleset_version?: string;
    readonly rules?: DiagnosticsResult;
    readonly custom_rules?: DiagnosticsResult;
    readonly exclusions?: DiagnosticsResult;
    readonly rules_override?: DiagnosticsResult;
    readonly rules_data?: DiagnosticsResult;
    readonly processors?: DiagnosticsResult;
    readonly actions?: DiagnosticsResult;
    readonly scanners?: DiagnosticsResult;
  };

  readonly knownAddresses: Set<string>;
  readonly knownActions: Set<string>;

  constructor(rules: Rules, rulesPath: string, config?: {
    readonly obfuscatorKeyRegex?: string;
    readonly obfuscatorValueRegex?: string;
  });

  createOrUpdateConfig(config: Rules, path: string): boolean;
  removeConfig(path: string): boolean;

  /**
   * Returns `null` when the instance currently has no ruleset, which is what
   * removing every configuration produces. Add a configuration back to make it
   * usable again.
   */
  createContext(): DDWAFContext | null;
  dispose(): void;
}
