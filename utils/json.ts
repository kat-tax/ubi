import {JsonHigh} from '@xtao-org/jsonhilo';

interface JsonStreamOptions {
  object?: (obj: Record<string, unknown>) => void;
  array?: (arr: unknown[]) => void;
  level?: number;
}

export function JsonStream({
  object,
  array,
  level = 0
}: JsonStreamOptions = {}) {
  const ancestors: (Record<string, unknown> | unknown[])[] = [];
  let parent: Record<string, unknown> | unknown[] | null = null;
  let current: Record<string, unknown> | unknown[] | null = null;
  const path: (string | number)[] = [];
  let currentLevel = 0;

  const close = () => {
    --currentLevel;
    path.pop();
    if (currentLevel === level) {
      if (Array.isArray(current)) {
        array?.(current);
      } else if (current !== null) {
        object?.(current);
      }
      current = null;
      parent = null;
    } else if (currentLevel > level) {
      if (Array.isArray(parent) && current !== null) {
        parent.push(current);
      } else if (parent !== null && current !== null) {
        if (typeof parent === 'object' && parent !== null) {
          const key = path.at(-1);
          if (typeof key === 'string' || typeof key === 'number') {
            (parent as Record<string | number, unknown>)[key] = current;
          }
        }
      }
      current = parent;
      parent = ancestors.pop() || null;
    }
  };

  return JsonHigh({
    openArray: () => {
      ++currentLevel;
      if (currentLevel > level) {
        if (current !== null) {
          ancestors.push(parent as Record<string, unknown> | unknown[]);
          parent = current;
        }
        current = [];
        path.push(-1);
      }
    },
    openObject: () => {
      ++currentLevel;
      if (currentLevel > level) {
        if (current !== null) {
          ancestors.push(parent as Record<string, unknown> | unknown[]);
          parent = current;
        }
        current = {};
        path.push("");
      }
    },
    closeArray: close,
    closeObject: close,
    key: (k: string) => { 
      if (currentLevel > level) {
        path[path.length - 1] = k;
      }
    },
    value: (value: unknown) => {
      if (currentLevel > level) {
        if (Array.isArray(current)) {
          current.push(value);
        } else if (current !== null) {
          current[path.at(-1) as string | number] = value;
        }
      }
    },
  });
};
