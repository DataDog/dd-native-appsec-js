/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
type rules = object;

type result = {
  timeout: boolean;
  totalRuntime?: number;
  data?: string;
  action?: 'monitor' | 'block';
};

declare class DDWAFContext {
  readonly disposed: boolean;

  run(inputs: object, timeout: number): result;
  dispose(): void;
}

export class DDWAF {
  static version(): { major: number, minor: number, patch: number };

  readonly disposed: boolean;

  readonly rulesInfo: {
    version?: string,
    loaded: number,
    failed: number,
    errors: {
      [errorString: string]: string[]
    }
  };

  constructor(rules: rules, config?: {
    obfuscatorKeyRegex?: string,
    obfuscatorValueRegex?: string
  });

  createContext(): DDWAFContext;
  dispose(): void;
}
