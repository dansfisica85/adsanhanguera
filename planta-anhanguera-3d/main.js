import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { CSS2DRenderer, CSS2DObject } from 'three/addons/renderers/CSS2DRenderer.js';
import { GLTFExporter } from 'three/addons/exporters/GLTFExporter.js';
import { CAMPUS, categories, rooms, mezzanineRooms, descriptionFor } from './src/layout.js';
import { haversineMeters, isInsideCampus } from './src/geolocation.js';

const $ = (selector) => document.querySelector(selector);
const canvas = $('#scene');
const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, powerPreference: 'high-performance' });
renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.75));
renderer.setSize(window.innerWidth, window.innerHeight);
renderer.shadowMap.enabled = true;
renderer.shadowMap.type = THREE.PCFShadowMap;
renderer.outputColorSpace = THREE.SRGBColorSpace;
renderer.toneMapping = THREE.ACESFilmicToneMapping;
renderer.toneMappingExposure = 1.12;

const labelRenderer = new CSS2DRenderer();
labelRenderer.setSize(window.innerWidth, window.innerHeight);
Object.assign(labelRenderer.domElement.style, { position: 'fixed', inset: '0', pointerEvents: 'none', zIndex: '4' });
$('#app').appendChild(labelRenderer.domElement);

const scene = new THREE.Scene();
scene.background = new THREE.Color(0x17130f);
scene.fog = new THREE.FogExp2(0x17130f, 0.0062);

const camera = new THREE.PerspectiveCamera(48, window.innerWidth / window.innerHeight, 0.08, 420);
const initialCameraPosition = () => window.innerWidth < 600
  ? new THREE.Vector3(104, 98, 128)
  : new THREE.Vector3(78, 72, 84);
camera.position.copy(initialCameraPosition());
const orbit = new OrbitControls(camera, renderer.domElement);
orbit.enableDamping = true;
orbit.dampingFactor = 0.075;
orbit.target.set(0, 0, 5);
orbit.minDistance = 12;
orbit.maxDistance = 185;
orbit.maxPolarAngle = Math.PI * 0.495;

const timer = new THREE.Timer();
const raycaster = new THREE.Raycaster();
const pointer = new THREE.Vector2();
const keys = Object.create(null);
const roomMeshes = [];
const wallMeshes = [];
const wallCollisionBoxes = [];
const labelObjects = [];

const modelRoot = new THREE.Group();
const groundRoot = new THREE.Group();
const roomRoot = new THREE.Group();
const mezzanineRoot = new THREE.Group();
const furnitureRoot = new THREE.Group();
const routeRoot = new THREE.Group();
modelRoot.name = 'Campus_Anhanguera_Sertaozinho';
roomRoot.name = 'Ambientes_Terreo';
mezzanineRoot.name = 'Mezanino_Administrativo';
furnitureRoot.name = 'Mobiliario_e_Vegetacao';
routeRoot.name = 'Rota_3D';
modelRoot.add(roomRoot, mezzanineRoot, furnitureRoot, routeRoot);
scene.add(modelRoot, groundRoot);

let activeMode = 'orbit';
let selectedRoom = null;
let planReference = null;
let walkYaw = Math.PI;
let walkPitch = 0;
let touchLook = null;
let campusInside = false;
let lastPosition = null;
let toastTimer = null;
let routeState = { points: [], distance: 0, travelled: 0, running: false, paused: false, room: null, marker: null };

const materials = {
  wall: new THREE.MeshStandardMaterial({ color: 0xf3e7db, roughness: 0.82, transparent: true, opacity: 0.88, side: THREE.DoubleSide }),
  wallTop: new THREE.MeshStandardMaterial({ color: 0xcdbfaf, roughness: 0.8 }),
  wood: new THREE.MeshStandardMaterial({ color: 0x8b5b38, roughness: 0.72 }),
  woodLight: new THREE.MeshStandardMaterial({ color: 0xc5976d, roughness: 0.75 }),
  chair: new THREE.MeshStandardMaterial({ color: 0x3d4852, roughness: 0.7 }),
  metal: new THREE.MeshStandardMaterial({ color: 0x8a9298, roughness: 0.4, metalness: 0.35 }),
  screen: new THREE.MeshStandardMaterial({ color: 0x17354d, emissive: 0x0b2131, emissiveIntensity: 0.35, roughness: 0.3 }),
  glass: new THREE.MeshPhysicalMaterial({ color: 0x9ed1e5, transparent: true, opacity: 0.34, roughness: 0.15, metalness: 0.05 }),
  green: new THREE.MeshStandardMaterial({ color: 0x527342, roughness: 0.95 }),
};

function meshBox(w, h, d, materialOrColor, name = '') {
  const material = typeof materialOrColor === 'number'
    ? new THREE.MeshStandardMaterial({ color: materialOrColor, roughness: 0.76 })
    : materialOrColor;
  const mesh = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), material);
  mesh.name = name;
  mesh.castShadow = true;
  mesh.receiveShadow = true;
  return mesh;
}

function meshCylinder(radius, height, material, segments = 12) {
  const mesh = new THREE.Mesh(new THREE.CylinderGeometry(radius, radius, height, segments), material);
  mesh.castShadow = true;
  mesh.receiveShadow = true;
  return mesh;
}

function addWall(group, w, h, d, x, y, z) {
  const mesh = meshBox(w, h, d, materials.wall, 'Parede');
  mesh.position.set(x, y, z);
  mesh.userData.wall = true;
  group.add(mesh);
  wallMeshes.push(mesh);
}

function addDesk(parent, x, z, rotation = 0, computer = false) {
  const group = new THREE.Group();
  group.position.set(x, 0.16, z);
  group.rotation.y = rotation;
  const top = meshBox(1.25, 0.10, 0.62, materials.woodLight);
  top.position.y = 0.72;
  const leg1 = meshBox(0.08, 0.7, 0.08, materials.metal);
  const leg2 = leg1.clone();
  leg1.position.set(-0.5, 0.35, 0);
  leg2.position.set(0.5, 0.35, 0);
  const chair = meshBox(0.48, 0.08, 0.48, materials.chair);
  chair.position.set(0, 0.48, 0.67);
  const chairBack = meshBox(0.48, 0.55, 0.08, materials.chair);
  chairBack.position.set(0, 0.72, 0.88);
  group.add(top, leg1, leg2, chair, chairBack);
  if (computer) {
    const monitor = meshBox(0.5, 0.34, 0.06, materials.screen);
    monitor.position.set(0, 1.03, -0.08);
    const stand = meshBox(0.07, 0.22, 0.07, materials.metal);
    stand.position.set(0, 0.88, -0.08);
    group.add(monitor, stand);
  }
  parent.add(group);
}

function addLabBench(parent, x, z, length = 2.6, rotation = 0) {
  const group = new THREE.Group();
  group.position.set(x, 0.16, z);
  group.rotation.y = rotation;
  const top = meshBox(length, 0.14, 0.85, new THREE.MeshStandardMaterial({ color: 0xe6e2d8, roughness: 0.55 }));
  top.position.y = 0.83;
  const cabinet = meshBox(length - 0.22, 0.68, 0.62, materials.woodLight);
  cabinet.position.y = 0.42;
  group.add(top, cabinet);
  parent.add(group);
}

function addPlant(parent, x, z, scale = 1) {
  const pot = meshCylinder(0.34 * scale, 0.48 * scale, new THREE.MeshStandardMaterial({ color: 0x8e4f2e, roughness: 0.85 }));
  pot.position.set(x, 0.24 * scale, z);
  const crown = new THREE.Mesh(new THREE.SphereGeometry(0.68 * scale, 12, 8), materials.green);
  crown.scale.y = 1.25;
  crown.position.set(x, 1.06 * scale, z);
  crown.castShadow = true;
  parent.add(pot, crown);
}

function addRoomFurniture(room, roomGroup, parentRoot = furnitureRoot) {
  const f = new THREE.Group();
  f.name = `Mobília — ${room.name}`;
  f.position.set(room.x, (room.y || 0), room.z);
  const usableW = Math.max(2, room.w - 1.4);
  const usableD = Math.max(2, room.d - 1.7);
  const isComputerLab = room.name.includes('Informática');

  if (room.category === 'sala' || isComputerLab) {
    const cols = Math.max(2, Math.min(4, Math.floor(usableW / 2.1)));
    const rowsCount = Math.max(2, Math.min(4, Math.floor(usableD / 2.1)));
    for (let rowIndex = 0; rowIndex < rowsCount; rowIndex += 1) {
      for (let column = 0; column < cols; column += 1) {
        addDesk(f, -usableW / 2 + 1 + column * (usableW / cols), -usableD / 2 + 1 + rowIndex * (usableD / rowsCount), 0, isComputerLab);
      }
    }
    const board = meshBox(Math.min(room.w - 1.2, 4), 1.2, 0.08, new THREE.MeshStandardMaterial({ color: 0x315447, roughness: 0.8 }));
    board.position.set(0, 1.8, -room.d / 2 + 0.24);
    f.add(board);
  } else if (room.name.includes('Biblioteca')) {
    [-room.w / 2 + 1.1, room.w / 2 - 1.1].forEach((x) => {
      for (let z = -room.d / 2 + 1.7; z < room.d / 2 - 1; z += 2.3) {
        const shelf = meshBox(0.68, 2.1, 1.75, materials.wood);
        shelf.position.set(x, 1.05, z);
        f.add(shelf);
      }
    });
    addDesk(f, -1.7, -1.6);
    addDesk(f, 1.7, -1.6);
    addDesk(f, 0, 1.6);
    addPlant(f, room.w / 2 - 1.3, room.d / 2 - 1.3, 0.75);
  } else if (room.name.includes('Cantina')) {
    for (const [x, z] of [[-2.2,-1.8],[2,-1.8],[-2.2,2],[2,2]]) {
      const table = meshCylinder(0.78, 0.08, materials.woodLight, 20);
      table.position.set(x, 0.76, z);
      f.add(table);
      for (let a = 0; a < 4; a += 1) {
        const chair = meshBox(0.42, 0.48, 0.42, materials.chair);
        chair.position.set(x + Math.cos(a * Math.PI / 2) * 1.15, 0.24, z + Math.sin(a * Math.PI / 2) * 1.15);
        f.add(chair);
      }
    }
    const counter = meshBox(room.w - 1.4, 1, 0.75, materials.wood);
    counter.position.set(0, 0.5, -room.d / 2 + 0.8);
    f.add(counter);
  } else if (room.name.includes('Psicologia')) {
    const sofaA = meshBox(2.8, 0.65, 0.85, materials.chair);
    sofaA.position.set(-2.5, 0.42, -room.d / 2 + 1.4);
    const sofaB = sofaA.clone();
    sofaB.rotation.y = Math.PI / 2;
    sofaB.position.set(room.w / 2 - 1.2, 0.42, 1);
    f.add(sofaA, sofaB);
    addDesk(f, -1.3, 2.7);
    addPlant(f, 3.8, -4.5, 0.8);
  } else if (room.category === 'laboratorio') {
    const rowsCount = Math.max(2, Math.min(4, Math.floor(usableD / 3)));
    for (let index = 0; index < rowsCount; index += 1) {
      addLabBench(f, 0, -usableD / 2 + 1.1 + index * (usableD / rowsCount), Math.min(usableW - 0.6, 5.2));
    }
    const sink = meshBox(1.7, 0.9, 0.72, materials.metal);
    sink.position.set(-room.w / 2 + 1.2, 0.45, -room.d / 2 + 0.7);
    f.add(sink);
  } else if (room.category === 'sanitarios') {
    const count = Math.max(2, Math.min(4, Math.floor(room.w / 2)));
    for (let index = 0; index < count; index += 1) {
      const stall = meshBox(1.15, 1.8, 0.08, materials.wallTop);
      stall.position.set(-room.w / 2 + 1 + index * 1.45, 0.9, -0.5);
      const toilet = meshBox(0.55, 0.42, 0.72, 0xf4f4f0);
      toilet.position.set(stall.position.x, 0.21, -room.d / 2 + 0.85);
      f.add(stall, toilet);
    }
    const sink = meshBox(Math.min(3.5, room.w - 1.5), 0.78, 0.55, 0xe7e9e7);
    sink.position.set(0, 0.39, room.d / 2 - 0.7);
    f.add(sink);
  } else if (room.category === 'administrativo') {
    addDesk(f, 0, 0, 0, room.name.includes('CIEE'));
    if (room.w > 8) addDesk(f, 3, 0);
    addPlant(f, room.w / 2 - 0.8, -room.d / 2 + 0.9, 0.65);
  } else {
    const shelfCount = Math.max(1, Math.floor(room.w / 2.5));
    for (let index = 0; index < shelfCount; index += 1) {
      const shelf = meshBox(1.3, 1.9, 0.55, materials.metal);
      shelf.position.set(-room.w / 2 + 1.1 + index * 2, 0.95, -room.d / 2 + 0.65);
      f.add(shelf);
    }
  }
  parentRoot.add(f);
  roomGroup.userData.furniture = f;
}

function buildRoom(room, parent) {
  const cfg = categories[room.category] || categories.sala;
  const group = new THREE.Group();
  group.name = room.name;
  group.position.set(room.x, room.y || 0, room.z);
  group.userData.room = room;

  const floorMaterial = new THREE.MeshStandardMaterial({ color: cfg.color, roughness: 0.86 });
  const floor = meshBox(room.w, 0.16, room.d, floorMaterial, `Piso — ${room.name}`);
  floor.position.y = 0.08;
  floor.userData.room = room;
  floor.userData.pickable = true;
  group.add(floor);
  roomMeshes.push(floor);

  const border = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.BoxGeometry(room.w, 0.19, room.d)), new THREE.LineBasicMaterial({ color: 0x4d3323, transparent: true, opacity: 0.72 }));
  border.position.y = 0.1;
  group.add(border);

  const thickness = 0.17;
  const wallY = room.h / 2;
  const doorWidth = Math.min(1.35, room.w * 0.3);
  const frontSegment = (room.w - doorWidth) / 2;
  addWall(group, frontSegment, room.h, thickness, -(room.w + doorWidth) / 4, wallY, room.d / 2);
  addWall(group, frontSegment, room.h, thickness, (room.w + doorWidth) / 4, wallY, room.d / 2);
  addWall(group, room.w, room.h, thickness, 0, wallY, -room.d / 2);
  addWall(group, thickness, room.h, room.d, -room.w / 2, wallY, 0);
  addWall(group, thickness, room.h, room.d, room.w / 2, wallY, 0);

  const door = meshBox(doorWidth - 0.08, 2.25, 0.07, materials.wood, 'Porta');
  door.position.set(-doorWidth / 2 + 0.04, 1.12, room.d / 2 + 0.02);
  door.rotation.y = -Math.PI / 2.9;
  group.add(door);
  const windowPanel = meshBox(Math.max(1.2, room.w * 0.42), 1.05, 0.04, materials.glass, 'Janela');
  windowPanel.position.set(0, 1.92, -room.d / 2 - 0.02);
  group.add(windowPanel);

  const label = document.createElement('div');
  label.className = 'room-label';
  label.innerHTML = `<span class="label-code">${room.code || '•'}</span><span class="label-name">${room.name}</span>`;
  const labelObject = new CSS2DObject(label);
  labelObject.position.set(0, 0.5, 0);
  labelObject.userData.roomLabel = true;
  labelObject.userData.room = room;
  group.add(labelObject);
  labelObjects.push(labelObject);

  parent.add(group);
  addRoomFurniture(room, group);
}

function addTree(x, z, scale = 1) {
  const trunk = meshCylinder(0.22 * scale, 1.7 * scale, new THREE.MeshStandardMaterial({ color: 0x70462f, roughness: 0.94 }));
  trunk.position.set(x, 0.85 * scale, z);
  const crown = new THREE.Mesh(new THREE.IcosahedronGeometry(1.15 * scale, 1), materials.green);
  crown.position.set(x, 2.15 * scale, z);
  crown.castShadow = true;
  groundRoot.add(trunk, crown);
}

function addSiteElements() {
  groundRoot.clear();
  const base = meshBox(122, 0.42, 89, 0x73675d, 'Base do campus');
  base.position.set(0, -0.32, 4);
  groundRoot.add(base);
  const pavement = meshBox(118, 0.08, 8, 0xaaa198, 'Calçada pública');
  pavement.position.set(0, -0.04, 47.5);
  groundRoot.add(pavement);
  const parking = meshBox(31, 0.1, 19, 0x3b3c3e, 'Estacionamento');
  parking.position.set(-30, -0.04, 38.5);
  groundRoot.add(parking);
  for (let index = 0; index < 6; index += 1) {
    const line = meshBox(0.11, 0.018, 15, 0xe9b93e);
    line.position.set(-44 + index * 5.6, 0.02, 38.5);
    groundRoot.add(line);
  }
  const accessible = meshBox(4.8, 0.025, 0.15, 0x4f94cb);
  accessible.position.set(-17, 0.025, 44);
  groundRoot.add(accessible);

  const gardens = [
    { x: 23, z: -12, w: 30, d: 8 },
    { x: 12, z: 40, w: 15, d: 9 },
    { x: 37, z: 41, w: 18, d: 8 },
  ];
  for (const gardenData of gardens) {
    const garden = meshBox(gardenData.w, 0.12, gardenData.d, 0x426437, 'Jardim');
    garden.position.set(gardenData.x, -0.01, gardenData.z);
    groundRoot.add(garden);
    const treeCount = Math.max(2, Math.floor(gardenData.w / 7));
    for (let index = 0; index < treeCount; index += 1) {
      addTree(gardenData.x - gardenData.w / 2 + 2.8 + index * 6, gardenData.z, 0.8 + (index % 2) * 0.15);
    }
  }
  for (let index = 0; index < 10; index += 1) addTree(-56 + index * 12, 51, 0.7);

  const entrancePath = meshBox(10, 0.09, 10, 0xafa498, 'Entrada principal');
  entrancePath.position.set(CAMPUS.entrance.x, 0, CAMPUS.entrance.z);
  groundRoot.add(entrancePath);
  const gateLeft = meshBox(0.38, 3.1, 0.38, materials.metal, 'Portal da entrada');
  gateLeft.position.set(21.8, 1.55, 43.5);
  const gateRight = gateLeft.clone();
  gateRight.position.x = 28.2;
  const gateTop = meshBox(6.8, 0.45, 0.45, materials.metal, 'Portal da entrada');
  gateTop.position.set(25, 3, 43.5);
  groundRoot.add(gateLeft, gateRight, gateTop);

  const texture = new THREE.TextureLoader().load('/assets/planta-atual-referencia-web.jpg');
  texture.colorSpace = THREE.SRGBColorSpace;
  planReference = new THREE.Mesh(new THREE.PlaneGeometry(116, 84), new THREE.MeshBasicMaterial({ map: texture, transparent: true, opacity: 0.42, side: THREE.DoubleSide, depthWrite: false }));
  planReference.rotation.x = -Math.PI / 2;
  planReference.position.set(0, 0.04, 3);
  planReference.name = 'Planta de referência';
  planReference.visible = false;
  groundRoot.add(planReference);
}

function addLights() {
  scene.add(new THREE.HemisphereLight(0xfff2dd, 0x4c3728, 2.05));
  const sun = new THREE.DirectionalLight(0xffe1bd, 3.1);
  sun.position.set(-42, 78, 48);
  sun.castShadow = true;
  sun.shadow.mapSize.set(2048, 2048);
  Object.assign(sun.shadow.camera, { left: -90, right: 90, top: 90, bottom: -90, near: 1, far: 190 });
  scene.add(sun);
  const fill = new THREE.DirectionalLight(0x8dbfe0, 0.75);
  fill.position.set(55, 32, -45);
  scene.add(fill);
}

function clearGroup(group) {
  while (group.children.length) group.remove(group.children[0]);
}

function rebuildModel() {
  clearGroup(roomRoot);
  clearGroup(mezzanineRoot);
  clearGroup(furnitureRoot);
  clearGroup(routeRoot);
  roomMeshes.length = 0;
  wallMeshes.length = 0;
  labelObjects.length = 0;
  rooms.forEach((room) => buildRoom(room, roomRoot));
  mezzanineRooms.forEach((room) => buildRoom(room, mezzanineRoot));
  const slab = meshBox(29, 0.28, 15, 0xd2c5b7, 'Laje do mezanino');
  slab.position.set(25, 4.05, 24.6);
  mezzanineRoot.add(slab);
  scene.updateMatrixWorld(true);
  wallCollisionBoxes.length = 0;
  wallMeshes.forEach((wall) => wallCollisionBoxes.push(new THREE.Box3().setFromObject(wall)));
  refreshRoomOptions();
  drawMinimap();
}

function refreshRoomOptions() {
  const options = $('#roomOptions');
  options.replaceChildren();
  [...rooms, ...mezzanineRooms].sort((a, b) => a.name.localeCompare(b.name, 'pt-BR', { numeric: true })).forEach((room) => {
    const option = document.createElement('option');
    option.value = room.name;
    option.label = `${room.code || ''} · ${categories[room.category]?.label || ''}`;
    options.appendChild(option);
  });
}

function findRoomByName(name) {
  const normalized = name.trim().toLocaleLowerCase('pt-BR');
  return [...rooms, ...mezzanineRooms].find((room) => room.name.toLocaleLowerCase('pt-BR') === normalized)
    || [...rooms, ...mezzanineRooms].find((room) => room.name.toLocaleLowerCase('pt-BR').includes(normalized));
}

function roomFurnitureSummary(room) {
  if (room.category === 'sala') return 'Elementos: carteiras, cadeiras, mesa docente e quadro.';
  if (room.name.includes('Informática')) return 'Elementos: computadores, mesas, cadeiras e quadro.';
  if (room.name.includes('Biblioteca')) return 'Elementos: estantes, acervo, mesas de estudo, cadeiras e plantas.';
  if (room.name.includes('Cantina')) return 'Elementos: balcão, mesas e cadeiras.';
  if (room.name.includes('Psicologia')) return 'Elementos: mesas, cadeiras, sofás de atendimento e plantas.';
  if (room.category === 'laboratorio') return 'Elementos: bancadas técnicas, armários e ponto de apoio.';
  if (room.category === 'sanitarios') return 'Elementos: cabines, louças e bancada de lavatórios.';
  if (room.category === 'administrativo') return 'Elementos: mesas de atendimento, cadeiras e plantas.';
  return 'Elementos: estantes e armários de apoio.';
}

function showRoomInfo(room) {
  selectedRoom = room;
  $('#infoNumber').textContent = room.code || '—';
  $('#infoCategory').textContent = categories[room.category]?.label || room.category;
  $('#infoTitle').textContent = room.name;
  $('#infoDetails').textContent = descriptionFor(room);
  $('#infoFurniture').textContent = roomFurnitureSummary(room);
  $('#infoCard').classList.remove('hidden');
  $('#roomSearch').value = room.name;
}

function focusRoom(room) {
  exitWalkMode();
  activeMode = 'orbit';
  setActiveModeButton('isometricBtn');
  orbit.enabled = true;
  const height = room.y || 0;
  orbit.target.set(room.x, height + 0.7, room.z);
  camera.position.set(room.x + Math.max(10, room.w * 1.2), height + 11, room.z + Math.max(10, room.d * 1.1));
  camera.lookAt(orbit.target);
  orbit.update();
  showRoomInfo(room);
  $('#statusText').textContent = `${room.code || ''} ${room.name} · ${categories[room.category]?.label || ''}`.trim();
}

function setActiveModeButton(id) {
  ['isometricBtn', 'topBtn', 'walkBtn'].forEach((buttonId) => $(`#${buttonId}`).classList.toggle('active', buttonId === id));
}

function setMode(mode) {
  routeState.running = false;
  $('#pauseRouteBtn').classList.add('hidden');
  if (mode === 'top') {
    exitWalkMode();
    activeMode = 'top';
    orbit.enabled = true;
    orbit.target.set(0, 0, 4);
    camera.position.set(0, 126, 4.01);
    camera.up.set(0, 0, -1);
    camera.lookAt(0, 0, 4);
    orbit.update();
    setActiveModeButton('topBtn');
    $('#modeHint').textContent = 'Vista superior: arraste para deslocar e role para aproximar.';
  } else if (mode === 'walk') {
    activeMode = 'walk';
    orbit.enabled = false;
    camera.up.set(0, 1, 0);
    camera.position.set(CAMPUS.entrance.x, 1.68, CAMPUS.entrance.z);
    walkYaw = Math.PI;
    walkPitch = 0;
    updateWalkRotation();
    $('#walkOverlay').classList.remove('hidden');
    setActiveModeButton('walkBtn');
    $('#modeHint').textContent = 'Use WASD/setas. No celular, use o controle circular e arraste para olhar.';
    $('#statusText').textContent = 'Modo caminhar · entrada principal';
  } else {
    exitWalkMode();
    activeMode = 'orbit';
    orbit.enabled = true;
    camera.up.set(0, 1, 0);
    setActiveModeButton('isometricBtn');
    $('#modeHint').textContent = 'Arraste para girar, role para aproximar e toque em um ambiente.';
  }
}

function exitWalkMode() {
  if (document.pointerLockElement === canvas) document.exitPointerLock();
  $('#walkOverlay').classList.add('hidden');
  if (activeMode === 'walk') activeMode = 'orbit';
  camera.up.set(0, 1, 0);
}

function updateWalkRotation() {
  camera.rotation.order = 'YXZ';
  camera.rotation.y = walkYaw;
  camera.rotation.x = walkPitch;
}

function isWalkPositionAllowed(position) {
  if (position.x < -59 || position.x > 59 || position.z < -38 || position.z > 48) return false;
  const visitor = new THREE.Box3(
    new THREE.Vector3(position.x - 0.28, 0.2, position.z - 0.28),
    new THREE.Vector3(position.x + 0.28, 2.05, position.z + 0.28),
  );
  return !wallCollisionBoxes.some((wallBox) => visitor.intersectsBox(wallBox));
}

function moveWalk(delta) {
  if (activeMode !== 'walk') return;
  const forwardAmount = (keys.KeyW || keys.ArrowUp || keys.forward ? 1 : 0) - (keys.KeyS || keys.ArrowDown || keys.back ? 1 : 0);
  const sideAmount = (keys.KeyD || keys.ArrowRight || keys.right ? 1 : 0) - (keys.KeyA || keys.ArrowLeft || keys.left ? 1 : 0);
  if (!forwardAmount && !sideAmount) return;
  const speed = (keys.ShiftLeft || keys.ShiftRight ? 8.5 : 4.4) * delta;
  const forward = new THREE.Vector3(-Math.sin(walkYaw), 0, -Math.cos(walkYaw));
  const right = new THREE.Vector3(Math.cos(walkYaw), 0, -Math.sin(walkYaw));
  const movement = forward.multiplyScalar(forwardAmount).add(right.multiplyScalar(sideAmount)).normalize().multiplyScalar(speed);
  const next = camera.position.clone().add(movement);
  next.y = 1.68;
  if (isWalkPositionAllowed(next)) camera.position.copy(next);
}

function simplifyRoute(points) {
  const result = [];
  for (const point of points) {
    const current = new THREE.Vector3(point[0], 0.27, point[1]);
    const previous = result[result.length - 1];
    if (!previous || previous.distanceTo(current) > 0.2) result.push(current);
  }
  return result.filter((point, index, list) => {
    if (index === 0 || index === list.length - 1) return true;
    const a = point.clone().sub(list[index - 1]).normalize();
    const b = list[index + 1].clone().sub(point).normalize();
    return a.distanceTo(b) > 0.01;
  });
}

function routePointsFor(room) {
  const targetZ = room.z + room.d / 2 + 0.55;
  const points = [[CAMPUS.entrance.x, CAMPUS.entrance.z], [25, 38], [8, 38]];
  if (room.y > 0) {
    points.push([8, 32], [13, 32], [13, targetZ], [room.x, targetZ]);
  } else if (room.x > 40) {
    points.push([56, 38], [56, targetZ], [room.x, targetZ]);
  } else if (room.x > 8) {
    points.push([8, 13], [8, targetZ], [room.x, targetZ]);
  } else if (room.x < -18) {
    points.push([-18, 38], [-18, 13], [-18, targetZ], [room.x, targetZ]);
  } else {
    points.push([8, targetZ], [room.x, targetZ]);
  }
  return simplifyRoute(points);
}

function buildRouteGeometry(points) {
  clearGroup(routeRoot);
  const routeMaterial = new THREE.MeshStandardMaterial({ color: 0xff7a1a, emissive: 0xff5a00, emissiveIntensity: 1.7, roughness: 0.35 });
  for (let index = 0; index < points.length - 1; index += 1) {
    const start = points[index];
    const end = points[index + 1];
    const distance = start.distanceTo(end);
    const segment = meshCylinder(0.16, distance, routeMaterial, 12);
    segment.position.copy(start).add(end).multiplyScalar(0.5);
    segment.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), end.clone().sub(start).normalize());
    routeRoot.add(segment);
    const arrow = new THREE.Mesh(new THREE.ConeGeometry(0.48, 1.05, 12), routeMaterial);
    arrow.position.copy(end).setY(0.55);
    arrow.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), end.clone().sub(start).normalize());
    routeRoot.add(arrow);
  }
  const marker = new THREE.Mesh(new THREE.SphereGeometry(0.48, 18, 12), new THREE.MeshStandardMaterial({ color: 0xffffff, emissive: 0xff6b18, emissiveIntensity: 2.5 }));
  marker.position.copy(points[0]).setY(0.72);
  routeRoot.add(marker);
  routeState.marker = marker;
}

function totalRouteDistance(points) {
  let total = 0;
  for (let index = 0; index < points.length - 1; index += 1) total += points[index].distanceTo(points[index + 1]);
  return total;
}

function pointOnRoute(points, distance) {
  let remaining = distance;
  for (let index = 0; index < points.length - 1; index += 1) {
    const segmentLength = points[index].distanceTo(points[index + 1]);
    if (remaining <= segmentLength) {
      const t = segmentLength ? remaining / segmentLength : 0;
      return { point: points[index].clone().lerp(points[index + 1], t), direction: points[index + 1].clone().sub(points[index]).normalize(), segment: index };
    }
    remaining -= segmentLength;
  }
  const last = points.at(-1).clone();
  return { point: last, direction: last.clone().sub(points.at(-2)).normalize(), segment: points.length - 2 };
}

function startRoute(room, demo = false) {
  if (!room) {
    notify('Escolha primeiro um ambiente válido.');
    return;
  }
  if (!campusInside && !demo) {
    notify('Autorize a localização e confirme que você está dentro do campus.');
    return;
  }
  exitWalkMode();
  orbit.enabled = false;
  activeMode = 'route';
  const points = routePointsFor(room);
  buildRouteGeometry(points);
  routeRoot.visible = $('#routeToggle').checked;
  routeState = {
    ...routeState,
    points,
    distance: totalRouteDistance(points),
    travelled: 0,
    running: true,
    paused: false,
    room,
  };
  $('#routeInstruction').textContent = `${demo ? 'Simulação' : 'Rota iniciada'}: Entrada principal → ${room.name}. Siga a linha laranja.`;
  $('#routeInstruction').classList.remove('hidden');
  $('#pauseRouteBtn').textContent = 'Pausar percurso';
  $('#pauseRouteBtn').classList.remove('hidden');
  $('#mapLegend').textContent = room.name;
  $('#statusText').textContent = `Guiando até ${room.name}`;
  camera.up.set(0, 1, 0);
  showRoomInfo(room);
  closeSidebarOnMobile();
}

function updateRoute(delta) {
  if (!routeState.running || routeState.paused || !routeState.points.length) return;
  routeState.travelled = Math.min(routeState.distance, routeState.travelled + delta * 5.4);
  const sample = pointOnRoute(routeState.points, routeState.travelled);
  routeState.marker.position.copy(sample.point).setY(0.72 + Math.sin(routeState.travelled * 3) * 0.12);
  const targetCamera = sample.point.clone().addScaledVector(sample.direction, -6.2).add(new THREE.Vector3(0, 4.6, 0));
  camera.position.lerp(targetCamera, Math.min(1, delta * 2.6));
  camera.lookAt(sample.point.clone().addScaledVector(sample.direction, 3.3).setY(1.1));
  const remaining = Math.max(0, Math.round(routeState.distance - routeState.travelled));
  $('#routeInstruction').textContent = remaining > 0
    ? `${remaining} m aproximados · siga em frente pela linha laranja até ${routeState.room.name}.`
    : `Você chegou a ${routeState.room.name}.`;
  if (routeState.travelled >= routeState.distance) {
    routeState.running = false;
    $('#pauseRouteBtn').classList.add('hidden');
    $('#statusText').textContent = `Destino alcançado · ${routeState.room.name}`;
    notify(`Chegada: ${routeState.room.name}`);
  }
}

function updateLocation(position) {
  const coords = { lat: position.coords.latitude, lng: position.coords.longitude };
  const distance = haversineMeters(CAMPUS.center, coords);
  const accuracy = Math.round(position.coords.accuracy || 0);
  campusInside = isInsideCampus(coords, CAMPUS.center, CAMPUS.geofenceRadiusMeters);
  lastPosition = { ...coords, distance, accuracy };
  const status = $('#locationStatus');
  status.dataset.state = campusInside ? 'inside' : 'outside';
  status.textContent = campusInside
    ? `Dentro do campus · precisão estimada de ${accuracy} m. As rotas começam na Entrada Principal.`
    : `Você parece estar fora do campus (${Math.round(distance)} m do centro, precisão de ${accuracy} m).`;
  $('#routeBtn').disabled = !campusInside;
  $('#locationBtn').textContent = campusInside ? 'Localização confirmada' : 'Atualizar localização';
  drawMinimap();
}

function locationError(error) {
  campusInside = false;
  $('#routeBtn').disabled = true;
  const messages = {
    1: 'Permissão de localização negada. Você ainda pode simular a rota pela entrada.',
    2: 'Não foi possível determinar sua posição. Verifique o GPS ou a rede.',
    3: 'A localização demorou demais. Tente novamente.',
  };
  const status = $('#locationStatus');
  status.dataset.state = 'error';
  status.textContent = messages[error.code] || 'Falha ao obter a localização.';
}

function requestLocation() {
  if (!window.isSecureContext && location.hostname !== 'localhost') {
    locationError({ code: 2 });
    $('#locationStatus').textContent = 'A localização exige HTTPS ou localhost.';
    return;
  }
  if (!navigator.geolocation) {
    locationError({ code: 2 });
    $('#locationStatus').textContent = 'Este navegador não oferece geolocalização.';
    return;
  }
  $('#locationStatus').dataset.state = 'idle';
  $('#locationStatus').textContent = 'Obtendo sua posição com segurança…';
  navigator.geolocation.getCurrentPosition(updateLocation, locationError, { enableHighAccuracy: true, timeout: 12000, maximumAge: 30000 });
}

function drawMinimap() {
  const map = $('#minimap');
  const context = map.getContext('2d');
  const bounds = { minX: -61, maxX: 61, minZ: -39, maxZ: 49 };
  const sx = map.width / (bounds.maxX - bounds.minX);
  const sz = map.height / (bounds.maxZ - bounds.minZ);
  const px = (x) => (x - bounds.minX) * sx;
  const pz = (z) => (z - bounds.minZ) * sz;
  context.clearRect(0, 0, map.width, map.height);
  context.fillStyle = '#eee7dd';
  context.fillRect(0, 0, map.width, map.height);
  for (const room of rooms) {
    context.fillStyle = categories[room.category]?.floor || '#bbb';
    context.globalAlpha = selectedRoom === room ? 1 : 0.68;
    context.fillRect(px(room.x - room.w / 2), pz(room.z - room.d / 2), room.w * sx, room.d * sz);
    context.strokeStyle = selectedRoom === room ? '#c53e23' : '#6f5c4b';
    context.lineWidth = selectedRoom === room ? 2.2 : 0.7;
    context.strokeRect(px(room.x - room.w / 2), pz(room.z - room.d / 2), room.w * sx, room.d * sz);
  }
  context.globalAlpha = 1;
  if (routeState.points.length && routeRoot.visible) {
    context.strokeStyle = '#ff5b18';
    context.lineWidth = 3;
    context.lineJoin = 'round';
    context.beginPath();
    routeState.points.forEach((point, index) => index ? context.lineTo(px(point.x), pz(point.z)) : context.moveTo(px(point.x), pz(point.z)));
    context.stroke();
  }
  const dot = activeMode === 'walk' ? camera.position : new THREE.Vector3(CAMPUS.entrance.x, 0, CAMPUS.entrance.z);
  context.fillStyle = campusInside || activeMode === 'walk' ? '#1768d5' : '#f47b20';
  context.beginPath();
  context.arc(px(dot.x), pz(dot.z), 4.5, 0, Math.PI * 2);
  context.fill();
  context.strokeStyle = '#fff';
  context.lineWidth = 1.5;
  context.stroke();
}

function notify(message) {
  const toast = $('#toast');
  toast.textContent = message;
  toast.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.add('hidden'), 3200);
}

function closeSidebarOnMobile() {
  if (window.matchMedia('(max-width: 800px)').matches) {
    $('#sidebar').classList.remove('open');
    $('#menuToggle').setAttribute('aria-expanded', 'false');
  }
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

renderer.domElement.addEventListener('click', (event) => {
  if (activeMode === 'walk') {
    if (window.matchMedia('(pointer:fine)').matches && document.pointerLockElement !== canvas) canvas.requestPointerLock?.();
    return;
  }
  if (event.target !== renderer.domElement || activeMode === 'route') return;
  pointer.x = (event.clientX / window.innerWidth) * 2 - 1;
  pointer.y = -(event.clientY / window.innerHeight) * 2 + 1;
  raycaster.setFromCamera(pointer, camera);
  const hit = raycaster.intersectObjects(roomMeshes, false)[0];
  if (hit?.object.userData.room) {
    showRoomInfo(hit.object.userData.room);
    drawMinimap();
  }
});

window.addEventListener('keydown', (event) => {
  keys[event.code] = true;
  if (event.code === 'Escape' && activeMode === 'walk') setMode('orbit');
});
window.addEventListener('keyup', (event) => { keys[event.code] = false; });
document.addEventListener('mousemove', (event) => {
  if (activeMode !== 'walk' || document.pointerLockElement !== canvas) return;
  walkYaw -= event.movementX * 0.0022;
  walkPitch = THREE.MathUtils.clamp(walkPitch - event.movementY * 0.0022, -1.28, 1.28);
  updateWalkRotation();
});
canvas.addEventListener('pointerdown', (event) => {
  if (activeMode === 'walk' && event.pointerType !== 'mouse') touchLook = { id: event.pointerId, x: event.clientX, y: event.clientY };
});
canvas.addEventListener('pointermove', (event) => {
  if (!touchLook || touchLook.id !== event.pointerId || activeMode !== 'walk') return;
  walkYaw -= (event.clientX - touchLook.x) * 0.007;
  walkPitch = THREE.MathUtils.clamp(walkPitch - (event.clientY - touchLook.y) * 0.007, -1.28, 1.28);
  touchLook.x = event.clientX;
  touchLook.y = event.clientY;
  updateWalkRotation();
});
window.addEventListener('pointerup', (event) => { if (touchLook?.id === event.pointerId) touchLook = null; });

document.querySelectorAll('[data-move]').forEach((button) => {
  const direction = button.dataset.move;
  const start = (event) => { event.preventDefault(); keys[direction] = true; };
  const stop = (event) => { event.preventDefault(); keys[direction] = false; };
  button.addEventListener('pointerdown', start);
  button.addEventListener('pointerup', stop);
  button.addEventListener('pointercancel', stop);
  button.addEventListener('pointerleave', stop);
});

$('#isometricBtn').addEventListener('click', () => {
  setMode('orbit');
  camera.position.copy(initialCameraPosition());
  orbit.target.set(0, 0, 5);
  orbit.update();
});
$('#topBtn').addEventListener('click', () => setMode('top'));
$('#walkBtn').addEventListener('click', () => setMode('walk'));
$('#resetBtn').addEventListener('click', () => {
  setMode('orbit');
  camera.position.copy(initialCameraPosition());
  orbit.target.set(0, 0, 5);
  orbit.update();
  $('#infoCard').classList.add('hidden');
  $('#routeInstruction').classList.add('hidden');
  clearGroup(routeRoot);
  routeState = { points: [], distance: 0, travelled: 0, running: false, paused: false, room: null, marker: null };
  $('#mapLegend').textContent = 'Entrada';
});
$('#focusBtn').addEventListener('click', () => {
  const room = findRoomByName($('#roomSearch').value);
  if (room) focusRoom(room); else notify('Ambiente não encontrado. Selecione uma opção da lista.');
  closeSidebarOnMobile();
});
$('#roomSearch').addEventListener('keydown', (event) => { if (event.key === 'Enter') $('#focusBtn').click(); });
$('#closeInfo').addEventListener('click', () => $('#infoCard').classList.add('hidden'));
$('#routeFromInfoBtn').addEventListener('click', () => {
  if (!selectedRoom) return;
  $('#roomSearch').value = selectedRoom.name;
  if (campusInside) startRoute(selectedRoom); else notify('Destino definido. Confirme sua localização ou use a simulação.');
});
$('#locationBtn').addEventListener('click', requestLocation);
$('#routeBtn').addEventListener('click', () => startRoute(findRoomByName($('#roomSearch').value)));
$('#demoRouteBtn').addEventListener('click', () => startRoute(findRoomByName($('#roomSearch').value), true));
$('#pauseRouteBtn').addEventListener('click', () => {
  routeState.paused = !routeState.paused;
  $('#pauseRouteBtn').textContent = routeState.paused ? 'Continuar percurso' : 'Pausar percurso';
});
$('#wallsToggle').addEventListener('change', (event) => wallMeshes.forEach((wall) => { wall.visible = event.target.checked; }));
$('#labelsToggle').addEventListener('change', (event) => labelObjects.forEach((label) => { label.visible = event.target.checked; }));
$('#furnitureToggle').addEventListener('change', (event) => { furnitureRoot.visible = event.target.checked; });
$('#planToggle').addEventListener('change', (event) => { if (planReference) planReference.visible = event.target.checked; });
$('#mezzToggle').addEventListener('change', (event) => { mezzanineRoot.visible = event.target.checked; });
$('#routeToggle').addEventListener('change', (event) => { routeRoot.visible = event.target.checked; drawMinimap(); });
$('#menuToggle').addEventListener('click', () => {
  const open = $('#sidebar').classList.toggle('open');
  $('#menuToggle').setAttribute('aria-expanded', String(open));
});

$('#saveJsonBtn').addEventListener('click', () => {
  const payload = {
    metadata: { title: 'Campus 3D — Anhanguera Sertãozinho', address: CAMPUS.address, scale: 'visual aproximada', updated: new Date().toISOString() },
    campus: CAMPUS,
    rooms,
    mezzanineRooms,
  };
  downloadBlob(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }), 'campus-anhanguera-sertaozinho-layout.json');
});

$('#loadJsonInput').addEventListener('change', async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  try {
    const data = JSON.parse(await file.text());
    if (!Array.isArray(data.rooms)) throw new Error('JSON sem lista de ambientes');
    rooms.splice(0, rooms.length, ...data.rooms);
    mezzanineRooms.splice(0, mezzanineRooms.length, ...(data.mezzanineRooms || []));
    rebuildModel();
    notify('Layout atualizado pelo JSON.');
  } catch (error) {
    notify(`Erro ao carregar JSON: ${error.message}`);
  }
});

$('#exportGlbBtn').addEventListener('click', () => {
  const exporter = new GLTFExporter();
  const exportRoot = modelRoot.clone(true);
  const remove = [];
  exportRoot.traverse((object) => { if (object.userData?.roomLabel || object.name === 'Rota_3D') remove.push(object); });
  remove.forEach((object) => object.parent?.remove(object));
  exporter.parse(exportRoot, (result) => {
    downloadBlob(new Blob([result], { type: 'model/gltf-binary' }), 'campus-anhanguera-sertaozinho-3d.glb');
    notify('Modelo GLB exportado.');
  }, (error) => notify(`Falha ao exportar: ${error.message}`), { binary: true, onlyVisible: true });
});

function onResize() {
  camera.aspect = window.innerWidth / window.innerHeight;
  camera.updateProjectionMatrix();
  renderer.setSize(window.innerWidth, window.innerHeight);
  labelRenderer.setSize(window.innerWidth, window.innerHeight);
}
window.addEventListener('resize', onResize);

function animate() {
  requestAnimationFrame(animate);
  timer.update();
  const delta = Math.min(timer.getDelta(), 0.05);
  if (activeMode === 'orbit' || activeMode === 'top') orbit.update();
  moveWalk(delta);
  updateRoute(delta);
  labelObjects.forEach((label) => {
    const room = label.userData.room;
    const distance = camera.position.distanceTo(new THREE.Vector3(room.x, (room.y || 0) + 0.5, room.z));
    label.element?.classList.toggle('far', distance > 66 && selectedRoom !== room);
  });
  if (activeMode === 'walk' || activeMode === 'route') drawMinimap();
  renderer.render(scene, camera);
  labelRenderer.render(scene, camera);
}

addLights();
addSiteElements();
rebuildModel();
$('#statusText').textContent = `${rooms.length + mezzanineRooms.length} ambientes · mobília, plantas e rotas carregadas`;
$('#locationStatus').title = CAMPUS.address;
if (navigator.permissions?.query) {
  navigator.permissions.query({ name: 'geolocation' }).then((permission) => {
    if (permission.state === 'granted') requestLocation();
  }).catch(() => {});
}
animate();
