/**
 * Minimal browser-native 3D helpers for the 3D Threat Simulation.
 *
 * The accepted decision allows Three.js or an equivalent browser-native renderer. This app
 * ships a small raw WebGL layer instead of a 3D framework: the scene is a few dozen boxes,
 * rings, and lines, and a static public demo should not take on a large runtime dependency
 * to draw them. Nothing here knows about threat models — it is geometry and matrices only.
 */

export type Mat4 = Float32Array;
export type Vec3 = readonly [number, number, number];

export function identity(): Mat4 {
  const out = new Float32Array(16);
  out[0] = 1;
  out[5] = 1;
  out[10] = 1;
  out[15] = 1;
  return out;
}

export function multiply(a: Mat4, b: Mat4): Mat4 {
  const out = new Float32Array(16);
  for (let column = 0; column < 4; column += 1) {
    for (let row = 0; row < 4; row += 1) {
      let sum = 0;
      for (let k = 0; k < 4; k += 1) sum += a[k * 4 + row] * b[column * 4 + k];
      out[column * 4 + row] = sum;
    }
  }
  return out;
}

export function perspective(fovYRadians: number, aspect: number, near: number, far: number): Mat4 {
  const f = 1 / Math.tan(fovYRadians / 2);
  const nf = 1 / (near - far);
  const out = new Float32Array(16);
  out[0] = f / aspect;
  out[5] = f;
  out[10] = (far + near) * nf;
  out[11] = -1;
  out[14] = 2 * far * near * nf;
  return out;
}

function normalize(v: Vec3): Vec3 {
  const length = Math.hypot(v[0], v[1], v[2]) || 1;
  return [v[0] / length, v[1] / length, v[2] / length];
}

function cross(a: Vec3, b: Vec3): Vec3 {
  return [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]];
}

function dot(a: Vec3, b: Vec3): number {
  return a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
}

export function lookAt(eye: Vec3, target: Vec3, up: Vec3): Mat4 {
  const zAxis = normalize([eye[0] - target[0], eye[1] - target[1], eye[2] - target[2]]);
  const xAxis = normalize(cross(up, zAxis));
  const yAxis = cross(zAxis, xAxis);
  const out = new Float32Array(16);
  out[0] = xAxis[0];
  out[1] = yAxis[0];
  out[2] = zAxis[0];
  out[4] = xAxis[1];
  out[5] = yAxis[1];
  out[6] = zAxis[1];
  out[8] = xAxis[2];
  out[9] = yAxis[2];
  out[10] = zAxis[2];
  out[12] = -dot(xAxis, eye);
  out[13] = -dot(yAxis, eye);
  out[14] = -dot(zAxis, eye);
  out[15] = 1;
  return out;
}

/** Translation, uniform-per-axis scale, and a Y rotation. Enough for an abstract scene. */
export function modelMatrix(translation: Vec3, scale: Vec3, rotationY = 0): Mat4 {
  const cos = Math.cos(rotationY);
  const sin = Math.sin(rotationY);
  const out = new Float32Array(16);
  out[0] = cos * scale[0];
  out[2] = -sin * scale[0];
  out[5] = scale[1];
  out[8] = sin * scale[2];
  out[10] = cos * scale[2];
  out[12] = translation[0];
  out[13] = translation[1];
  out[14] = translation[2];
  out[15] = 1;
  return out;
}

/** Orbit camera position from spherical coordinates around a target. */
export function orbitEye(target: Vec3, azimuth: number, elevation: number, radius: number): Vec3 {
  const clampedElevation = Math.max(0.05, Math.min(1.35, elevation));
  return [
    target[0] + radius * Math.cos(clampedElevation) * Math.sin(azimuth),
    target[1] + radius * Math.sin(clampedElevation),
    target[2] + radius * Math.cos(clampedElevation) * Math.cos(azimuth),
  ];
}

export interface Bounds {
  min: Vec3;
  max: Vec3;
}

/**
 * Smallest orbit radius that keeps an axis-aligned box inside the frustum.
 *
 * A bounding-sphere fit would push the camera far too far back for a long, thin chain in a
 * wide embed. This projects the eight corners into the camera basis and solves each corner's
 * horizontal and vertical constraint directly, so a wide viewport is allowed to pull in
 * close and a narrow one backs off.
 */
export function fitOrbitRadius(
  bounds: Bounds,
  target: Vec3,
  azimuth: number,
  elevation: number,
  fovYRadians: number,
  aspect: number,
  margin = 1.06,
): number {
  const direction = normalize(orbitEye([0, 0, 0], azimuth, elevation, 1));
  const right = normalize(cross([0, 1, 0], direction));
  const up = cross(direction, right);
  const tanVertical = Math.tan(fovYRadians / 2);
  const tanHorizontal = tanVertical * Math.max(aspect, 0.05);

  let radius = 0;
  for (const x of [bounds.min[0], bounds.max[0]]) {
    for (const y of [bounds.min[1], bounds.max[1]]) {
      for (const z of [bounds.min[2], bounds.max[2]]) {
        const offset: Vec3 = [x - target[0], y - target[1], z - target[2]];
        // Depth grows with the radius we are solving for: depth = radius - dot(offset, direction).
        const depthOffset = -dot(offset, direction);
        radius = Math.max(
          radius,
          Math.abs(dot(offset, right)) / tanHorizontal - depthOffset,
          Math.abs(dot(offset, up)) / tanVertical - depthOffset,
        );
      }
    }
  }
  return radius * margin;
}

export interface Geometry {
  positions: Float32Array;
  normals: Float32Array;
  indices: Uint16Array;
}

/** Unit cube centred on the origin, with flat face normals. */
export function boxGeometry(): Geometry {
  const faces: { normal: Vec3; corners: Vec3[] }[] = [
    { normal: [0, 0, 1], corners: [[-0.5, -0.5, 0.5], [0.5, -0.5, 0.5], [0.5, 0.5, 0.5], [-0.5, 0.5, 0.5]] },
    { normal: [0, 0, -1], corners: [[0.5, -0.5, -0.5], [-0.5, -0.5, -0.5], [-0.5, 0.5, -0.5], [0.5, 0.5, -0.5]] },
    { normal: [0, 1, 0], corners: [[-0.5, 0.5, 0.5], [0.5, 0.5, 0.5], [0.5, 0.5, -0.5], [-0.5, 0.5, -0.5]] },
    { normal: [0, -1, 0], corners: [[-0.5, -0.5, -0.5], [0.5, -0.5, -0.5], [0.5, -0.5, 0.5], [-0.5, -0.5, 0.5]] },
    { normal: [1, 0, 0], corners: [[0.5, -0.5, 0.5], [0.5, -0.5, -0.5], [0.5, 0.5, -0.5], [0.5, 0.5, 0.5]] },
    { normal: [-1, 0, 0], corners: [[-0.5, -0.5, -0.5], [-0.5, -0.5, 0.5], [-0.5, 0.5, 0.5], [-0.5, 0.5, -0.5]] },
  ];

  const positions: number[] = [];
  const normals: number[] = [];
  const indices: number[] = [];
  faces.forEach((face, faceIndex) => {
    for (const corner of face.corners) {
      positions.push(...corner);
      normals.push(...face.normal);
    }
    const base = faceIndex * 4;
    indices.push(base, base + 1, base + 2, base, base + 2, base + 3);
  });

  return { positions: new Float32Array(positions), normals: new Float32Array(normals), indices: new Uint16Array(indices) };
}

/** Flat ring in the XZ plane, outer radius 1. Used for detection sensors. */
export function ringGeometry(segments = 48, innerRadius = 0.86): Geometry {
  const positions: number[] = [];
  const normals: number[] = [];
  const indices: number[] = [];

  for (let i = 0; i < segments; i += 1) {
    const angle = (i / segments) * Math.PI * 2;
    const cos = Math.cos(angle);
    const sin = Math.sin(angle);
    positions.push(cos, 0, sin, cos * innerRadius, 0, sin * innerRadius);
    normals.push(0, 1, 0, 0, 1, 0);
  }
  for (let i = 0; i < segments; i += 1) {
    const a = i * 2;
    const b = a + 1;
    const c = ((i + 1) % segments) * 2;
    const d = c + 1;
    indices.push(a, b, c, b, d, c);
  }

  return { positions: new Float32Array(positions), normals: new Float32Array(normals), indices: new Uint16Array(indices) };
}

/** Grid lines in the XZ plane, drawn with gl.LINES. */
export function gridLines(halfWidth: number, halfDepth: number, step: number): Float32Array {
  const points: number[] = [];
  for (let x = -halfWidth; x <= halfWidth; x += step) points.push(x, 0, -halfDepth, x, 0, halfDepth);
  for (let z = -halfDepth; z <= halfDepth; z += step) points.push(-halfWidth, 0, z, halfWidth, 0, z);
  return new Float32Array(points);
}

export function compileProgram(gl: WebGLRenderingContext, vertexSource: string, fragmentSource: string): WebGLProgram | null {
  const compile = (type: number, source: string) => {
    const shader = gl.createShader(type);
    if (!shader) return null;
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
      gl.deleteShader(shader);
      return null;
    }
    return shader;
  };

  const vertex = compile(gl.VERTEX_SHADER, vertexSource);
  const fragment = compile(gl.FRAGMENT_SHADER, fragmentSource);
  if (!vertex || !fragment) return null;

  const program = gl.createProgram();
  if (!program) return null;
  gl.attachShader(program, vertex);
  gl.attachShader(program, fragment);
  gl.linkProgram(program);
  gl.deleteShader(vertex);
  gl.deleteShader(fragment);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
    gl.deleteProgram(program);
    return null;
  }
  return program;
}

/**
 * True only when a real WebGL context can be created. jsdom, hardened browsers, blocked GPU
 * processes, and remote sessions all land on false, which is exactly when the 2D map has to
 * carry the work.
 */
export function supportsWebGL(): boolean {
  if (typeof document === 'undefined') return false;
  try {
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('webgl') ?? canvas.getContext('experimental-webgl');
    return Boolean(context);
  } catch {
    return false;
  }
}

/** `#rrggbb` to normalized RGB. Keeps the scene palette in one place: the stylesheet. */
export function hexToRgb(hex: string): Vec3 {
  const value = hex.replace('#', '');
  const full = value.length === 3 ? value.split('').map((char) => char + char).join('') : value;
  const int = Number.parseInt(full, 16);
  return [((int >> 16) & 255) / 255, ((int >> 8) & 255) / 255, (int & 255) / 255];
}

/** Smooth 0..1 ramp used for entry, pulse, and hold animations. */
export function smoothstep(edge0: number, edge1: number, x: number): number {
  const t = Math.max(0, Math.min(1, (x - edge0) / (edge1 - edge0 || 1)));
  return t * t * (3 - 2 * t);
}
