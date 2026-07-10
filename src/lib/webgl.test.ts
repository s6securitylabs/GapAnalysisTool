import { describe, expect, it } from 'vitest';

import { boxGeometry, fitOrbitRadius, hexToRgb, identity, multiply, orbitEye, ringGeometry, smoothstep, supportsWebGL, type Bounds } from './webgl';

const CHAIN: Bounds = { min: [-25, 0, -3.4], max: [25, 8.6, 3.4] };
const TARGET = [0, 2.6, 0] as const;
const FOV = (45 * Math.PI) / 180;

describe('matrix helpers', () => {
  it('multiplies against the identity without changing a matrix', () => {
    const matrix = new Float32Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    expect([...multiply(matrix, identity())]).toEqual([...matrix]);
    expect([...multiply(identity(), matrix)]).toEqual([...matrix]);
  });

  it('places the orbit eye at the requested radius from the target', () => {
    const eye = orbitEye([0, 2, 0], 0.4, 0.5, 30);
    expect(Math.hypot(eye[0] - 0, eye[1] - 2, eye[2] - 0)).toBeCloseTo(30, 4);
  });
});

describe('camera fit', () => {
  it('pulls the camera in as the viewport gets wider', () => {
    const wide = fitOrbitRadius(CHAIN, TARGET, 0.28, 0.42, FOV, 3.0);
    const narrow = fitOrbitRadius(CHAIN, TARGET, 0.28, 0.42, FOV, 1.2);
    expect(wide).toBeGreaterThan(0);
    expect(wide).toBeLessThan(narrow);
  });

  it('keeps every corner of the scene inside the frustum', () => {
    for (const aspect of [0.8, 1.6, 3.2]) {
      const radius = fitOrbitRadius(CHAIN, TARGET, 0.28, 0.42, FOV, aspect, 1);
      const eye = orbitEye(TARGET, 0.28, 0.42, radius);
      const tanVertical = Math.tan(FOV / 2);
      const tanHorizontal = tanVertical * aspect;
      const direction: number[] = [eye[0] - TARGET[0], eye[1] - TARGET[1], eye[2] - TARGET[2]];
      const length = Math.hypot(...direction);
      const forward = direction.map((value) => value / length);
      const right = [forward[2], 0, -forward[0]];
      const rightLength = Math.hypot(...right);
      const unitRight = right.map((value) => value / rightLength);

      for (const x of [CHAIN.min[0], CHAIN.max[0]]) {
        for (const y of [CHAIN.min[1], CHAIN.max[1]]) {
          for (const z of [CHAIN.min[2], CHAIN.max[2]]) {
            const offset = [x - eye[0], y - eye[1], z - eye[2]];
            const depth = -(offset[0] * forward[0] + offset[1] * forward[1] + offset[2] * forward[2]);
            const horizontal = Math.abs(offset[0] * unitRight[0] + offset[2] * unitRight[2]);
            expect(depth).toBeGreaterThan(0);
            // Rounding tolerance only: the fit is exact for the horizontal constraint.
            expect(horizontal).toBeLessThanOrEqual(depth * tanHorizontal + 1e-3);
          }
        }
      }
    }
  });
});

describe('geometry and colour', () => {
  it('builds a closed unit box with one normal per vertex', () => {
    const box = boxGeometry();
    expect(box.positions).toHaveLength(24 * 3);
    expect(box.normals).toHaveLength(24 * 3);
    expect(box.indices).toHaveLength(36);
  });

  it('builds a ring with two vertices per segment', () => {
    const ring = ringGeometry(24);
    expect(ring.positions).toHaveLength(24 * 2 * 3);
    expect(ring.indices).toHaveLength(24 * 6);
  });

  it('converts hex colours to normalized rgb, long and short form', () => {
    expect(hexToRgb('#ffffff')).toEqual([1, 1, 1]);
    expect(hexToRgb('#000')).toEqual([0, 0, 0]);
    const accent = hexToRgb('#1864ab');
    expect(accent[0]).toBeCloseTo(24 / 255, 5);
  });

  it('clamps smoothstep to the closed unit interval', () => {
    expect(smoothstep(0, 1, -5)).toBe(0);
    expect(smoothstep(0, 1, 5)).toBe(1);
    expect(smoothstep(0, 1, 0.5)).toBeCloseTo(0.5, 5);
  });
});

describe('progressive enhancement', () => {
  it('reports no WebGL under jsdom, which is what forces the 2D fallback', () => {
    expect(supportsWebGL()).toBe(false);
  });
});
