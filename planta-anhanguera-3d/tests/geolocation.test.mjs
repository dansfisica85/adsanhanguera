import assert from 'node:assert/strict';
import { haversineMeters, isInsideCampus } from '../src/geolocation.js';

const campus = { lat: -21.14486, lng: -47.98716 };
assert.equal(Math.round(haversineMeters(campus, campus)), 0);
assert.equal(isInsideCampus({ lat: -21.1444, lng: -47.9872 }, campus, 180), true);
assert.equal(isInsideCampus({ lat: -21.1400, lng: -47.9800 }, campus, 180), false);
console.log('Geofence: 3 verificações aprovadas.');
