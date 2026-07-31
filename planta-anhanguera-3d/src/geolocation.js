export function haversineMeters(a, b) {
  const earthRadius = 6371000;
  const radians = (degrees) => degrees * Math.PI / 180;
  const dLat = radians(b.lat - a.lat);
  const dLng = radians(b.lng - a.lng);
  const h = Math.sin(dLat / 2) ** 2
    + Math.cos(radians(a.lat)) * Math.cos(radians(b.lat)) * Math.sin(dLng / 2) ** 2;
  return 2 * earthRadius * Math.atan2(Math.sqrt(h), Math.sqrt(1 - h));
}

export function isInsideCampus(position, campusCenter, radiusMeters) {
  return haversineMeters(campusCenter, position) <= radiusMeters;
}
