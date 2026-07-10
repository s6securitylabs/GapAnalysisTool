import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ThreatScenario } from '../data/threat-model';
import { simulationTimeline, postureLabels, type SimulationEvent, type StagePosture } from '../lib/threat-model';
import {
  boxGeometry,
  compileProgram,
  fitOrbitRadius,
  gridLines,
  hexToRgb,
  lookAt,
  modelMatrix,
  multiply,
  orbitEye,
  perspective,
  ringGeometry,
  smoothstep,
  supportsWebGL,
  type Bounds,
  type Geometry,
  type Mat4,
  type Vec3,
} from '../lib/webgl';

/**
 * 3D Threat Simulation — progressive enhancement over the 2D Attack Chain Map.
 *
 * The scene is an abstract threat theatre: stage plinths along a chain, telemetry drawn as
 * light, gaps drawn as unlit ground, and controls that animate according to what they
 * actually do. A detection control pulses; it does not stop the actor. Only a block or a
 * containment halts the path. Nothing here is decided locally — every posture, effect, and
 * halt comes from the canonical threat model via `simulationTimeline`.
 *
 * If WebGL is unavailable, the fallback below renders the same timeline in SVG and points
 * back at the 2D map, which remains the authoritative and exportable view.
 */

const SPACING = 7.2;
const PLINTH_SIZE = 4.4;
const PACKET_Y = 1.55;
const FOV_RADIANS = (45 * Math.PI) / 180;
const TRAVEL_SECONDS = 0.95;
const DWELL_SECONDS = 1.25;
const HALT_SECONDS = 2.6;
const RESET_SECONDS = 1.4;

const postureColor: Record<StagePosture, Vec3> = {
  covered: hexToRgb('#1f7a50'),
  blind: hexToRgb('#25313f'),
  undetected: hexToRgb('#b42318'),
  unresolved: hexToRgb('#a56500'),
  'accepted-risk': hexToRgb('#59687a'),
  'no-action': hexToRgb('#3d4c5c'),
};

const SCENE_BACKGROUND: Vec3 = hexToRgb('#0d1826');
const GRID_COLOR = hexToRgb('#2b4c6b');
const TELEMETRY_COLOR = hexToRgb('#4aa3e0');
const UNLIT_COLOR = hexToRgb('#0a1119');
const CONTROL_BLOCK = hexToRgb('#1f7a50');
const CONTROL_DELAY = hexToRgb('#a56500');
const CONTROL_INVESTIGATE = hexToRgb('#7fb2d8');
const RAIL_COLOR = hexToRgb('#2b4c6b');
const ACTOR_COLOR = hexToRgb('#e8593f');

const VERTEX_SOURCE = `
attribute vec3 aPosition;
attribute vec3 aNormal;
uniform mat4 uModel;
uniform mat4 uViewProjection;
varying vec3 vNormal;
void main() {
  vec4 world = uModel * vec4(aPosition, 1.0);
  vNormal = mat3(uModel) * aNormal;
  gl_Position = uViewProjection * world;
}
`;

const FRAGMENT_SOURCE = `
precision mediump float;
varying vec3 vNormal;
uniform vec3 uColor;
uniform float uEmissive;
uniform float uAlpha;
void main() {
  vec3 normal = normalize(vNormal);
  vec3 key = normalize(vec3(0.35, 0.92, 0.4));
  float diffuse = max(dot(normal, key), 0.0);
  float rim = pow(1.0 - abs(normal.y), 2.0) * 0.16;
  vec3 shaded = uColor * (0.34 + 0.66 * diffuse) + uColor * uEmissive + rim * vec3(0.35, 0.55, 0.8);
  gl_FragColor = vec4(shaded, uAlpha);
}
`;

const LINE_VERTEX_SOURCE = `
attribute vec3 aPosition;
uniform mat4 uViewProjection;
void main() { gl_Position = uViewProjection * vec4(aPosition, 1.0); }
`;

const LINE_FRAGMENT_SOURCE = `
precision mediump float;
uniform vec3 uColor;
uniform float uAlpha;
void main() { gl_FragColor = vec4(uColor, uAlpha); }
`;

interface Segment {
  kind: 'travel' | 'dwell' | 'halt' | 'reset';
  from: number;
  to: number;
  duration: number;
}

function buildSegments(events: SimulationEvent[]): Segment[] {
  const segments: Segment[] = [];
  for (let index = 0; index < events.length; index += 1) {
    if (index > 0) {
      const slowed = events[index - 1].effects.includes('delay');
      segments.push({ kind: 'travel', from: index - 1, to: index, duration: TRAVEL_SECONDS * (slowed ? 2.1 : 1) });
    }
    segments.push({ kind: 'dwell', from: index, to: index, duration: DWELL_SECONDS });
    if (events[index].halted) {
      segments.push({ kind: 'halt', from: index, to: index, duration: HALT_SECONDS });
      break;
    }
  }
  segments.push({ kind: 'reset', from: 0, to: 0, duration: RESET_SECONDS });
  return segments;
}

function stageX(index: number, count: number): number {
  return (index - (count - 1) / 2) * SPACING;
}

/** Everything the scene can draw, so the camera can frame all of it at any embed width. */
function sceneBounds(count: number): Bounds {
  const halfChain = ((count - 1) * SPACING) / 2 + PLINTH_SIZE / 2 + 3.4;
  return { min: [-halfChain, 0, -3.4], max: [halfChain, 7.6, 3.4] };
}

interface Frame {
  packetX: number;
  activeIndex: number;
  segmentKind: Segment['kind'];
  segmentProgress: number;
  time: number;
}

function frameAt(elapsed: number, segments: Segment[], count: number): Frame {
  const total = segments.reduce((sum, segment) => sum + segment.duration, 0);
  const time = total === 0 ? 0 : elapsed % total;
  let cursor = 0;
  for (const segment of segments) {
    if (time < cursor + segment.duration) {
      const progress = (time - cursor) / segment.duration;
      if (segment.kind === 'travel') {
        const eased = smoothstep(0, 1, progress);
        return {
          packetX: stageX(segment.from, count) + (stageX(segment.to, count) - stageX(segment.from, count)) * eased,
          activeIndex: progress > 0.5 ? segment.to : segment.from,
          segmentKind: segment.kind,
          segmentProgress: progress,
          time: elapsed,
        };
      }
      if (segment.kind === 'reset') {
        return { packetX: stageX(0, count), activeIndex: 0, segmentKind: segment.kind, segmentProgress: progress, time: elapsed };
      }
      return { packetX: stageX(segment.from, count), activeIndex: segment.from, segmentKind: segment.kind, segmentProgress: progress, time: elapsed };
    }
    cursor += segment.duration;
  }
  return { packetX: stageX(0, count), activeIndex: 0, segmentKind: 'dwell', segmentProgress: 0, time: elapsed };
}

function prefersReducedMotion(): boolean {
  return typeof window !== 'undefined' && typeof window.matchMedia === 'function'
    ? window.matchMedia('(prefers-reduced-motion: reduce)').matches
    : false;
}

export function ThreatSimulation({ scenario }: { scenario: ThreatScenario }) {
  const events = useMemo(() => simulationTimeline(scenario), [scenario]);
  const [contextFailed, setContextFailed] = useState(false);
  const webglAvailable = useMemo(() => supportsWebGL(), []);
  const reducedMotion = useMemo(() => prefersReducedMotion(), []);

  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const cameraRef = useRef({ azimuth: 0.2, elevation: 0.3, radius: 44, autoFit: true });
  const clockRef = useRef({ elapsed: 0, last: 0 });
  const runningRef = useRef(!reducedMotion);
  const renderRef = useRef<(() => void) | null>(null);
  const activeIndexRef = useRef(0);
  const [running, setRunning] = useState(!reducedMotion);
  const [activeIndex, setActiveIndex] = useState(0);

  const segments = useMemo(() => buildSegments(events), [events]);

  const setRunningState = useCallback((next: boolean) => {
    runningRef.current = next;
    setRunning(next);
  }, []);

  const stepStage = useCallback(() => {
    const next = (activeIndex + 1) % events.length;
    let cursor = 0;
    for (const segment of segments) {
      if (segment.kind === 'dwell' && segment.from === next) break;
      cursor += segment.duration;
    }
    clockRef.current.elapsed = cursor + 0.01;
    activeIndexRef.current = next;
    setActiveIndex(next);
    renderRef.current?.();
  }, [activeIndex, events.length, segments]);

  const resetView = useCallback(() => {
    cameraRef.current = { azimuth: 0.2, elevation: 0.3, radius: 44, autoFit: true };
    renderRef.current?.();
  }, []);

  useEffect(() => {
    if (!webglAvailable) return undefined;
    const canvas = canvasRef.current;
    if (!canvas) return undefined;

    const clock = clockRef.current;
    const gl = (canvas.getContext('webgl', { antialias: true, alpha: false }) ??
      canvas.getContext('experimental-webgl', { antialias: true, alpha: false })) as WebGLRenderingContext | null;
    if (!gl) {
      setContextFailed(true);
      return undefined;
    }

    const meshProgram = compileProgram(gl, VERTEX_SOURCE, FRAGMENT_SOURCE);
    const lineProgram = compileProgram(gl, LINE_VERTEX_SOURCE, LINE_FRAGMENT_SOURCE);
    if (!meshProgram || !lineProgram) {
      setContextFailed(true);
      return undefined;
    }

    const uploadGeometry = (geometry: Geometry) => {
      const position = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, position);
      gl.bufferData(gl.ARRAY_BUFFER, geometry.positions, gl.STATIC_DRAW);
      const normal = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, normal);
      gl.bufferData(gl.ARRAY_BUFFER, geometry.normals, gl.STATIC_DRAW);
      const index = gl.createBuffer();
      gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, index);
      gl.bufferData(gl.ELEMENT_ARRAY_BUFFER, geometry.indices, gl.STATIC_DRAW);
      return { position, normal, index, count: geometry.indices.length };
    };

    const bounds = sceneBounds(events.length);
    const box = uploadGeometry(boxGeometry());
    const ring = uploadGeometry(ringGeometry());
    const grid = gridLines(30, 16, 2);
    const gridBuffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, gridBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, grid, gl.STATIC_DRAW);

    const meshAttributes = {
      position: gl.getAttribLocation(meshProgram, 'aPosition'),
      normal: gl.getAttribLocation(meshProgram, 'aNormal'),
    };
    const meshUniforms = {
      model: gl.getUniformLocation(meshProgram, 'uModel'),
      viewProjection: gl.getUniformLocation(meshProgram, 'uViewProjection'),
      color: gl.getUniformLocation(meshProgram, 'uColor'),
      emissive: gl.getUniformLocation(meshProgram, 'uEmissive'),
      alpha: gl.getUniformLocation(meshProgram, 'uAlpha'),
    };
    const lineUniforms = {
      viewProjection: gl.getUniformLocation(lineProgram, 'uViewProjection'),
      color: gl.getUniformLocation(lineProgram, 'uColor'),
      alpha: gl.getUniformLocation(lineProgram, 'uAlpha'),
    };
    const linePosition = gl.getAttribLocation(lineProgram, 'aPosition');

    let viewProjection: Mat4;

    const drawMesh = (
      mesh: typeof box,
      translation: Vec3,
      scale: Vec3,
      color: Vec3,
      emissive: number,
      alpha: number,
      rotationY = 0,
    ) => {
      gl.bindBuffer(gl.ARRAY_BUFFER, mesh.position);
      gl.enableVertexAttribArray(meshAttributes.position);
      gl.vertexAttribPointer(meshAttributes.position, 3, gl.FLOAT, false, 0, 0);
      gl.bindBuffer(gl.ARRAY_BUFFER, mesh.normal);
      gl.enableVertexAttribArray(meshAttributes.normal);
      gl.vertexAttribPointer(meshAttributes.normal, 3, gl.FLOAT, false, 0, 0);
      gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, mesh.index);
      gl.uniformMatrix4fv(meshUniforms.model, false, modelMatrix(translation, scale, rotationY));
      gl.uniformMatrix4fv(meshUniforms.viewProjection, false, viewProjection);
      gl.uniform3f(meshUniforms.color, color[0], color[1], color[2]);
      gl.uniform1f(meshUniforms.emissive, emissive);
      gl.uniform1f(meshUniforms.alpha, alpha);
      gl.drawElements(gl.TRIANGLES, mesh.count, gl.UNSIGNED_SHORT, 0);
    };

    const resize = () => {
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      const width = Math.max(1, Math.round(canvas.clientWidth * ratio));
      const height = Math.max(1, Math.round(canvas.clientHeight * ratio));
      if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
      }
    };

    const render = () => {
      resize();
      const frame = frameAt(clock.elapsed, segments, events.length);
      const aspect = canvas.width / Math.max(1, canvas.height);
      const camera = cameraRef.current;
      const target: Vec3 = [0, 1.5, 0];
      if (camera.autoFit) {
        // Frame the whole chain across whatever width the embed gives us.
        const needed = fitOrbitRadius(bounds, target, camera.azimuth, camera.elevation, FOV_RADIANS, aspect);
        camera.radius = Math.max(18, Math.min(90, needed));
      }
      const eye = orbitEye(target, camera.azimuth, camera.elevation, camera.radius);
      viewProjection = multiply(perspective(FOV_RADIANS, aspect, 0.1, 260), lookAt(eye, target, [0, 1, 0]));

      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.clearColor(SCENE_BACKGROUND[0], SCENE_BACKGROUND[1], SCENE_BACKGROUND[2], 1);
      gl.enable(gl.DEPTH_TEST);
      gl.depthFunc(gl.LEQUAL);
      gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);

      gl.useProgram(lineProgram);
      gl.bindBuffer(gl.ARRAY_BUFFER, gridBuffer);
      gl.enableVertexAttribArray(linePosition);
      gl.vertexAttribPointer(linePosition, 3, gl.FLOAT, false, 0, 0);
      gl.uniformMatrix4fv(lineUniforms.viewProjection, false, viewProjection);
      gl.uniform3f(lineUniforms.color, GRID_COLOR[0], GRID_COLOR[1], GRID_COLOR[2]);
      gl.uniform1f(lineUniforms.alpha, 0.5);
      gl.drawArrays(gl.LINES, 0, grid.length / 3);

      gl.useProgram(meshProgram);
      gl.disable(gl.BLEND);

      const count = events.length;
      const pulse = 0.5 + 0.5 * Math.sin(frame.time * 3.2);

      // The chain itself, then the actor's trace along it up to wherever they got.
      const railStart = stageX(0, count);
      const railEnd = stageX(count - 1, count);
      drawMesh(box, [(railStart + railEnd) / 2, 0.08, 0], [railEnd - railStart, 0.08, 0.44], RAIL_COLOR, 0.1, 1);
      const traceLength = Math.max(frame.packetX - railStart, 0.02);
      drawMesh(box, [railStart + traceLength / 2, 0.13, 0], [traceLength, 0.1, 0.28], ACTOR_COLOR, 0.4, 1);

      events.forEach((event, index) => {
        const x = stageX(index, count);
        const color = postureColor[event.posture];
        const beyond = !event.reached;
        const emissive = beyond ? 0 : event.lit ? 0.14 : 0.02;
        drawMesh(box, [x, 0.35, 0], [PLINTH_SIZE, 0.7, PLINTH_SIZE], color, emissive, beyond ? 0.45 : 1);

        // A wall only stands full height where the block actually stops the actor.
        if (event.effects.includes('block') && event.halted && event.stopKind === 'blocked') {
          drawMesh(box, [x + 2.9, 1.75, 0], [0.4, 2.9, 4.6], CONTROL_BLOCK, 0.2, 1);
        }
        if (event.effects.includes('contain')) {
          const closing = frame.activeIndex === index && frame.segmentKind === 'halt' ? smoothstep(0, 0.6, frame.segmentProgress) : 0;
          for (const [dx, dz] of [[-1.9, -1.9], [1.9, -1.9], [-1.9, 1.9], [1.9, 1.9]] as const) {
            drawMesh(box, [x + dx * (1 - closing * 0.35), 1.85, dz * (1 - closing * 0.35)], [0.34, 3.1, 0.34], CONTROL_BLOCK, 0.18, 1);
          }
        }
        if (event.effects.includes('delay')) {
          drawMesh(box, [x - 1.5, 1.15, 0], [0.22, 0.9, 3.6], CONTROL_DELAY, 0.15, 1);
          drawMesh(box, [x + 1.5, 1.15, 0], [0.22, 0.9, 3.6], CONTROL_DELAY, 0.15, 1);
        }
        if (event.effects.includes('investigate')) {
          drawMesh(box, [x, 2.1, -2.2], [0.16, 3.4, 0.16], CONTROL_INVESTIGATE, 0.35, 1);
        }
      });

      // The actor. Spinning, emissive, and never stopped by anything that only watches it.
      const halted = frame.segmentKind === 'halt';
      const collapse = halted ? 1 - 0.55 * smoothstep(0.25, 0.85, frame.segmentProgress) : 1;
      const packetScale = 0.95 * collapse;
      drawMesh(box, [frame.packetX, PACKET_Y, 0], [packetScale, packetScale, packetScale], ACTOR_COLOR, 0.45 + 0.25 * pulse, 1, frame.time * 1.6);

      gl.enable(gl.BLEND);
      gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
      gl.depthMask(false);

      events.forEach((event, index) => {
        const x = stageX(index, count);
        const beyond = !event.reached;
        if (event.lit) {
          // Telemetry drawn as light. Absence of the column is the absence of the evidence.
          drawMesh(box, [x, 4.0, 0], [0.5, 6.4, 0.5], TELEMETRY_COLOR, 0.6, beyond ? 0.08 : 0.24);
          drawMesh(ring, [x, 0.02, 0], [4.0, 1, 4.0], TELEMETRY_COLOR, 0.4, beyond ? 0.04 : 0.12);
        } else {
          // An unlit zone: the stage exists, and nothing shines on it.
          drawMesh(box, [x, 0.72, 0], [4.2, 0.06, 4.2], UNLIT_COLOR, 0, 0.82);
        }
        // A block that does not stop the actor is drawn breached: present, low, see-through.
        if (event.effects.includes('block') && !(event.halted && event.stopKind === 'blocked')) {
          drawMesh(box, [x + 2.9, 1.05, 0], [0.35, 1.7, 4.6], CONTROL_BLOCK, 0.1, 0.3);
        }
        if (event.effects.includes('detect')) {
          // A sensor sitting in an unlit zone is drawn dark and still: it has nothing to see.
          const active = frame.activeIndex === index && !beyond && event.lit;
          const scale = 3.2 + (active ? pulse * 0.5 : 0);
          const alpha = event.lit ? (active ? 0.85 : 0.35) : 0.16;
          drawMesh(ring, [x, 0.78, 0], [scale, 1, scale], TELEMETRY_COLOR, active ? 0.5 + pulse * 0.5 : 0.15, alpha);
        }
        if (event.effects.includes('contain') && frame.activeIndex === index && frame.segmentKind === 'halt') {
          const dome = smoothstep(0.2, 0.9, frame.segmentProgress);
          drawMesh(box, [x, 3.45, 0], [4.6, 0.14, 4.6], CONTROL_BLOCK, 0.3, 0.22 * dome);
        }
      });

      gl.depthMask(true);
      gl.disable(gl.BLEND);

      if (frame.activeIndex !== activeIndexRef.current) {
        activeIndexRef.current = frame.activeIndex;
        setActiveIndex(frame.activeIndex);
      }
    };

    renderRef.current = render;

    let animationHandle = 0;
    const tick = (now: number) => {
      const last = clock.last || now;
      clock.last = now;
      // Paused (or reduced motion) holds the last frame instead of redrawing an identical one.
      if (runningRef.current) {
        clock.elapsed += Math.min((now - last) / 1000, 0.05);
        render();
      }
      animationHandle = window.requestAnimationFrame(tick);
    };
    render();
    animationHandle = window.requestAnimationFrame(tick);

    const observer = typeof ResizeObserver === 'function' ? new ResizeObserver(() => render()) : null;
    observer?.observe(canvas);

    return () => {
      window.cancelAnimationFrame(animationHandle);
      observer?.disconnect();
      renderRef.current = null;
      clock.last = 0;
      gl.deleteProgram(meshProgram);
      gl.deleteProgram(lineProgram);
    };
    // The scene rebuilds when the scenario timeline changes; camera and clock live in refs.
  }, [webglAvailable, events, segments]);

  const onPointerDown = (event: React.PointerEvent<HTMLCanvasElement>) => {
    event.currentTarget.setPointerCapture(event.pointerId);
  };

  const onPointerMove = (event: React.PointerEvent<HTMLCanvasElement>) => {
    if (event.buttons !== 1) return;
    cameraRef.current.azimuth -= event.movementX * 0.006;
    cameraRef.current.elevation = Math.max(0.08, Math.min(1.3, cameraRef.current.elevation + event.movementY * 0.005));
    if (!runningRef.current) renderRef.current?.();
  };

  const onWheel = (event: React.WheelEvent<HTMLCanvasElement>) => {
    cameraRef.current.autoFit = false;
    cameraRef.current.radius = Math.max(14, Math.min(90, cameraRef.current.radius + event.deltaY * 0.05));
    if (!runningRef.current) renderRef.current?.();
  };

  const onKeyDown = (event: React.KeyboardEvent<HTMLCanvasElement>) => {
    const camera = cameraRef.current;
    if (event.key === 'ArrowLeft') camera.azimuth -= 0.1;
    else if (event.key === 'ArrowRight') camera.azimuth += 0.1;
    else if (event.key === 'ArrowUp') camera.elevation = Math.min(1.3, camera.elevation + 0.06);
    else if (event.key === 'ArrowDown') camera.elevation = Math.max(0.08, camera.elevation - 0.06);
    else if (event.key === '+' || event.key === '=') {
      camera.autoFit = false;
      camera.radius = Math.max(14, camera.radius - 2);
    } else if (event.key === '-') {
      camera.autoFit = false;
      camera.radius = Math.min(90, camera.radius + 2);
    } else return;
    event.preventDefault();
    if (!runningRef.current) renderRef.current?.();
  };

  if (!webglAvailable || contextFailed) {
    return <SimulationFallback scenario={scenario} events={events} />;
  }

  const active = events[Math.min(activeIndex, events.length - 1)];

  return (
    <div className="threat-simulation">
      <div className="sim-stage">
        <canvas
          ref={canvasRef}
          className="sim-canvas"
          tabIndex={0}
          role="img"
          aria-label={`Three-dimensional threat simulation of ${scenario.title}. Stage plinths are lit where telemetry exists and unlit where it does not. The stage list below carries the same information as text.`}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onWheel={onWheel}
          onKeyDown={onKeyDown}
        />
        <ThreatSceneOverlay events={events} activeIndex={activeIndex} />
        <div className="sim-overlay">
          <span className="sim-eyebrow">3D Threat Simulation</span>
          <strong>{scenario.title}</strong>
          <small>{scenario.actor}</small>
        </div>
        <div className="sim-hint">Drag to orbit · scroll to zoom · arrow keys when focused</div>
      </div>

      <div className="sim-controls">
        <div className="button-row">
          <button onClick={() => setRunningState(!running)} aria-pressed={running}>
            {running ? 'Pause simulation' : 'Play simulation'}
          </button>
          <button onClick={stepStage}>Step to next stage</button>
          <button onClick={resetView}>Reset view</button>
        </div>
        {reducedMotion && (
          <p className="sim-note">Reduced-motion preference detected, so the simulation starts paused. Use step to advance one stage at a time.</p>
        )}
      </div>

      <SimulationLegend />

      <ol className="sim-timeline" aria-label="Simulation timeline">
        {events.map((event, index) => (
          <li key={event.stageId} className={`sim-step ${event.posture} ${index === activeIndex ? 'active' : ''}`}>
            <span className="sim-step-head">
              <span className="stage-order">{event.order}</span>
              <strong>{event.stageLabel}</strong>
            </span>
            <span className={`posture-badge ${event.posture}`}>{postureLabels[event.posture]}</span>
            <em>{event.narration}</em>
          </li>
        ))}
      </ol>

      <p className="sim-live" role="status" aria-live="polite">
        Stage {active.order} of {events.length}: {active.stageLabel}. {active.narration}
      </p>
    </div>
  );
}

function overlayX(index: number, count: number): number {
  if (count <= 1) return 500;
  return 90 + (index * 820) / (count - 1);
}

function postureClass(posture: StagePosture): string {
  return posture.replace(/[^a-z0-9]/gi, '-');
}

function ThreatSceneOverlay({ events, activeIndex }: { events: SimulationEvent[]; activeIndex: number }) {
  const active = events[Math.min(activeIndex, events.length - 1)];
  const activeX = overlayX(activeIndex, events.length);
  const railEnd = overlayX(events.length - 1, events.length);

  return (
    <svg className="sim-graphics" viewBox="0 0 1000 360" aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id="sim-trace-gradient" x1="0" x2="1" y1="0" y2="0">
          <stop offset="0%" stopColor="#fb7185" stopOpacity="0.14" />
          <stop offset="72%" stopColor="#f97316" stopOpacity="0.62" />
          <stop offset="100%" stopColor="#ef4444" stopOpacity="0.95" />
        </linearGradient>
        <radialGradient id="sim-actor-glow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#fed7aa" stopOpacity="0.9" />
          <stop offset="48%" stopColor="#fb7185" stopOpacity="0.62" />
          <stop offset="100%" stopColor="#ef4444" stopOpacity="0" />
        </radialGradient>
        <filter id="sim-soft-glow" x="-60%" y="-60%" width="220%" height="220%">
          <feGaussianBlur stdDeviation="5" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      <path className="sim-svg-rail" d={`M ${overlayX(0, events.length)} 226 C 260 190, 410 258, 520 226 S 770 194, ${railEnd} 226`} />
      <path
        className="sim-svg-threat-trace"
        d={`M ${overlayX(0, events.length)} 226 C 260 190, 410 258, 520 226 S 770 194, ${activeX} 226`}
        filter="url(#sim-soft-glow)"
      />

      {events.map((event, index) => {
        const x = overlayX(index, events.length);
        const isActive = index === activeIndex;
        const posture = postureClass(event.posture);
        return (
          <g key={event.stageId} className={`sim-svg-node ${posture} ${isActive ? 'active' : ''} ${event.reached ? '' : 'beyond-stop'}`}>
            {!event.lit && <rect className="sim-svg-blind-zone" x={x - 38} y="82" width="76" height="170" rx="18" />}
            {event.lit && <path className="sim-svg-telemetry-beam" d={`M ${x - 24} 76 L ${x + 24} 76 L ${x + 42} 236 L ${x - 42} 236 Z`} />}
            {event.effects.includes('detect') && (
              <g className="sim-svg-sensor">
                <circle cx={x} cy="118" r="18" />
                <path d={`M ${x - 28} 118 Q ${x} 88 ${x + 28} 118`} />
                <path d={`M ${x - 42} 118 Q ${x} 70 ${x + 42} 118`} />
              </g>
            )}
            {event.effects.includes('block') && (
              <g className={`sim-svg-shield ${event.halted && event.stopKind === 'blocked' ? 'stopping' : 'bypassed'}`}>
                <path d={`M ${x + 34} 154 l 24 10 v 28 c 0 19 -10 33 -24 42 c -14 -9 -24 -23 -24 -42 v -28 z`} />
                {!(event.halted && event.stopKind === 'blocked') && <path className="sim-svg-breach" d={`M ${x + 20} 204 L ${x + 52} 170`} />}
              </g>
            )}
            {event.effects.includes('delay') && (
              <g className="sim-svg-delay">
                <path d={`M ${x - 42} 168 h 28 l -18 28 h 28 l -42 54 l 15 -38 h -28 z`} />
              </g>
            )}
            {event.effects.includes('contain') && (
              <g className="sim-svg-contain">
                <path d={`M ${x - 46} 218 Q ${x} 150 ${x + 46} 218`} />
                <path d={`M ${x - 52} 226 H ${x + 52}`} />
              </g>
            )}
            {event.posture === 'accepted-risk' && (
              <g className="sim-svg-accepted">
                <path d={`M ${x - 28} 166 h 56 v 42 h -56 z`} />
                <path d={`M ${x - 14} 166 v -10 c 0 -18 28 -18 28 0 v 10`} />
              </g>
            )}
            <circle className="sim-svg-stage-orb" cx={x} cy="226" r="25" />
            <text className="sim-svg-order" x={x} y="233" textAnchor="middle">{event.order}</text>
            {event.halted && <path className="sim-svg-stop" d={`M ${x - 40} 266 H ${x + 40}`} />}
          </g>
        );
      })}

      <g className={`sim-svg-actor ${active?.halted ? 'halted' : ''}`} transform={`translate(${activeX} 226)`} filter="url(#sim-soft-glow)">
        <circle className="sim-svg-actor-glow" r="34" />
        <path className="sim-svg-actor-core" d="M 0 -24 l 26 15 v 30 l -26 15 l -26 -15 v -30 z" />
        <path className="sim-svg-actor-cut" d="M -10 -4 h20 M 0 -14 v28" />
      </g>
    </svg>
  );
}

function SimulationLegend() {
  return (
    <details className="visual-legend simulation-legend" open>
      <summary>3D simulation legend</summary>
      <div className="legend-grid compact-legend">
        <div><span className="legend-swatch actor" /> Moving actor / active stage</div>
        <div><span className="legend-swatch telemetry" /> Lit telemetry/evidence beam</div>
        <div><span className="legend-swatch blind" /> Blind or unlit stage</div>
        <div><span className="legend-swatch blocked" /> Block or containment stops path</div>
        <div><span className="legend-swatch delay" /> Delay/friction, not a stop</div>
        <div><span className="legend-swatch accepted-risk" /> Accepted risk, no coverage</div>
      </div>
    </details>
  );
}

/**
 * Progressive fallback. No WebGL, no loss of meaning: the same timeline, drawn flat, with an
 * explicit pointer back to the authoritative view.
 */
function SimulationFallback({ scenario, events }: { scenario: ThreatScenario; events: SimulationEvent[] }) {
  const width = 100;

  return (
    <div className="threat-simulation fallback">
      <div className="sim-fallback-notice" role="status">
        <strong>3D Threat Simulation unavailable</strong>
        <p>
          3D is not supported in this environment because WebGL is unavailable or blocked. Try the 3D Threat Simulation in a
          modern browser with hardware acceleration and WebGL enabled, or switch back to the 2D Attack Chain Map above. The 2D
          map is the authoritative view and holds the same threat model.
        </p>
      </div>

      <SimulationLegend />

      <svg className="sim-fallback-chain" viewBox={`0 0 ${width * events.length} 120`} role="img" aria-label={`Flat simulation of ${scenario.title}`}>
        <line x1={40} y1={60} x2={width * events.length - 40} y2={60} className="fallback-rail" />
        {events.map((event, index) => {
          const x = 50 + index * width;
          return (
            <g key={event.stageId} className={`fallback-node ${event.posture} ${event.reached ? '' : 'beyond-stop'}`}>
              <circle cx={x} cy={60} r={event.lit ? 16 : 12} />
              <text x={x} y={98} textAnchor="middle">{event.stageLabel}</text>
              <text x={x} y={30} textAnchor="middle" className="fallback-order">{event.order}</text>
            </g>
          );
        })}
      </svg>

      <ol className="sim-timeline" aria-label="Simulation timeline">
        {events.map((event) => (
          <li key={event.stageId} className={`sim-step ${event.posture}`}>
            <span className="sim-step-head">
              <span className="stage-order">{event.order}</span>
              <strong>{event.stageLabel}</strong>
            </span>
            <span className={`posture-badge ${event.posture}`}>{postureLabels[event.posture]}</span>
            <em>{event.narration}</em>
          </li>
        ))}
      </ol>
    </div>
  );
}
