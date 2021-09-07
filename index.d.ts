type rules = object;

type result = {
  perfData?: string;
  perfTotalRuntime?: number;
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

  constructor(rules: rules);

  createContext(): DDWAFContext;
  dispose(): void;
}
