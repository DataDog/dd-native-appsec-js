/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
type rules = object;
type diagnosticsInfo = {
  loaded: string[],
  failed: string[],
  error: string,
  errors: {
    [errorString: string]: string[]
  }
}

type result = {
  timeout: boolean;
  totalRuntime?: number;
  events?: object[]; // https://github.com/DataDog/libddwaf/blob/master/schema/events.json
  status?: 'match'; // TODO: remove this if new statuses are never added
  actions?: string[];
  derivatives?: object;
};

declare class DDWAFContext {
  readonly disposed: boolean;

  run(inputs: object, timeout: number): result;
  dispose(): void;
}

export class DDWAF {
  static version(): string;

  readonly disposed: boolean;

  readonly diagnostics: {
    ruleset_version?: string,
    rules?: diagnosticsInfo,
    custom_rules?: diagnosticsInfo,
    exclusions?: diagnosticsInfo,
    rules_override?: diagnosticsInfo,
    rules_data?: diagnosticsInfo
  };

  readonly requiredAddresses: Set<string>;

  constructor(rules: rules, config?: {
    obfuscatorKeyRegex?: string,
    obfuscatorValueRegex?: string
  });

  update(rules: rules): void;

  createContext(): DDWAFContext;
  dispose(): void;
}
