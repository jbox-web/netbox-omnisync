//! What `--raphinerie` shows on a terminal: a power station across the river
//! at dusk, a pig adrift between its chimneys, and the night falling on them.
//!
//! The plant is described in volumes (boxes, cylinders, ellipsoids) and each
//! picture is ray-traced, the reflection in the river included. A character
//! cell shows four samples (the quadrant characters `▘▝▀▖▌▞▛…`) in two
//! colours, so the picture needs a terminal that takes 24-bit colours.
//! Nothing here is used by a run.

use std::io::Write;
use std::time::Duration;

/// A colour as a terminal takes it: red, green, blue.
pub type Rgb = [u8; 3];

/// A colour while it is computed.
type Colour = [f64; 3];
type Vector = [f64; 3];

/// Seconds the animation lasts: from sunset to night.
pub const DURATION: f64 = 12.0;

/// Pictures per second, and how many are played.
pub const FRAME_RATE: u32 = 12;
pub const FRAMES: u32 = 168;

/// Seconds the picture takes to appear.
const FADE_IN: f64 = 1.0;

/// Seconds the whole animation lasts, its end included.
pub const END: f64 = 14.0;

/// The widest picture drawn, in columns, and its rows for a column.
const MAX_COLUMNS: usize = 150;
const ROWS_PER_COLUMN: f64 = 0.28;

/// The narrowest picture drawn: under it the pig has too few points to keep its shape.
const MIN_COLUMNS: usize = 100;

/// Lines of the terminal left free under the picture.
const MARGIN: usize = 3;

const BRICK: Colour = [150.0, 70.0, 44.0];
const CREAM: Colour = [236.0, 228.0, 208.0];
const ROOF: Colour = [70.0, 44.0, 40.0];
const PIG: Colour = [255.0, 140.0, 198.0];
const INK: Colour = [20.0, 16.0, 22.0];

/// Where the plant is looked at from: the other bank, upstream.
const CAMERA: Vector = [-135.0, 16.0, -205.0];
const TARGET: Vector = [2.0, 50.0, 32.0];
const FIELD: f64 = 0.33;

/// The corners of the plant, where its towers and chimneys stand.
const TOWERS: [(f64, f64); 4] = [(-74.0, 6.0), (74.0, 6.0), (-74.0, 58.0), (74.0, 58.0)];

/// Where a chimney starts and ends, and its radius.
const CHIMNEY_BASE: f64 = 56.0;
const CHIMNEY_TOP: f64 = 106.0;
const CHIMNEY_RADIUS: f64 = 5.0;

#[derive(Clone, Copy, PartialEq)]
enum Material {
    Hall,
    Attic,
    Annex,
    Tower,
    Pedestal,
    Quay,
}

/// A box: its two opposite corners.
struct Block {
    low: Vector,
    high: Vector,
    material: Material,
}

fn mix(from: Colour, to: Colour, amount: f64) -> Colour {
    let amount = amount.clamp(0.0, 1.0);
    [from[0] + (to[0] - from[0]) * amount, from[1] + (to[1] - from[1]) * amount, from[2] + (to[2] - from[2]) * amount]
}

fn smooth(from: f64, to: f64, value: f64) -> f64 {
    let t = ((value - from) / (to - from)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

/// A number in [0, 1] that only depends on the two it is given.
fn hash(x: f64, y: f64) -> f64 {
    let (x, y) = (x.floor() as i64, y.floor() as i64);
    let mut n = (x.wrapping_mul(374_761_393).wrapping_add(y.wrapping_mul(668_265_263)) & 0xFFFF_FFFF) as u64;
    n = ((n ^ (n >> 13)).wrapping_mul(1_274_126_177)) & 0xFFFF_FFFF;
    ((n ^ (n >> 16)) & 0xFFFF) as f64 / 65535.0
}

/// Smooth noise, and three layers of it.
fn noise(x: f64, y: f64) -> f64 {
    let (xi, yi) = (x.floor(), y.floor());
    let (fx, fy) = (x - xi, y - yi);
    let (fx, fy) = (fx * fx * (3.0 - 2.0 * fx), fy * fy * (3.0 - 2.0 * fy));
    let (a, b, c, d) = (hash(xi, yi), hash(xi + 1.0, yi), hash(xi, yi + 1.0), hash(xi + 1.0, yi + 1.0));
    a + (b - a) * fx + (c - a) * fy + (a - b - c + d) * fx * fy
}

fn clouds(x: f64, y: f64) -> f64 {
    noise(x, y) * 0.55 + noise(x * 2.1, y * 2.1) * 0.3 + noise(x * 4.3, y * 4.3) * 0.15
}

fn sub(a: Vector, b: Vector) -> Vector {
    [a[0] - b[0], a[1] - b[1], a[2] - b[2]]
}

fn dot(a: Vector, b: Vector) -> f64 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

fn cross(a: Vector, b: Vector) -> Vector {
    [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]]
}

fn unit(a: Vector) -> Vector {
    let length = dot(a, a).sqrt();
    [a[0] / length, a[1] / length, a[2] / length]
}

fn along(origin: Vector, direction: Vector, distance: f64) -> Vector {
    [origin[0] + direction[0] * distance, origin[1] + direction[1] * distance, origin[2] + direction[2] * distance]
}

/// The camera: where it looks, and its right and up.
struct View {
    forward: Vector,
    right: Vector,
    up: Vector,
}

impl View {
    fn new() -> Self {
        let forward = unit(sub(TARGET, CAMERA));
        let right = unit(cross([0.0, 1.0, 0.0], forward));
        View { forward, right, up: cross(forward, right) }
    }

    /// The ray through a point of the picture: `x` and `y` from -1 to 1.
    fn ray(&self, x: f64, y: f64, aspect: f64) -> Vector {
        let (across, above) = (x * FIELD * aspect, y * FIELD);
        unit([
            self.forward[0] + self.right[0] * across + self.up[0] * above,
            self.forward[1] + self.right[1] * across + self.up[1] * above,
            self.forward[2] + self.right[2] * across + self.up[2] * above,
        ])
    }

    /// Where a point of the scene falls in the picture, and how far it is.
    fn project(&self, point: Vector, aspect: f64) -> (f64, f64, f64) {
        let to = sub(point, CAMERA);
        let depth = dot(to, self.forward);
        (dot(to, self.right) / (depth * FIELD * aspect), dot(to, self.up) / (depth * FIELD), depth)
    }
}

/// The plant: the hall, its attic, the annex on the quay, a tower with its
/// steps at each corner, and the quay.
fn blocks() -> Vec<Block> {
    let block = |x: (f64, f64), y: (f64, f64), z: (f64, f64), material| Block {
        low: [x.0, y.0, z.0],
        high: [x.1, y.1, z.1],
        material,
    };
    let mut blocks = vec![
        block((-74.0, 74.0), (0.0, 34.0), (10.0, 54.0), Material::Hall),
        block((-50.0, 50.0), (34.0, 42.0), (18.0, 46.0), Material::Attic),
        block((-60.0, 60.0), (0.0, 20.0), (2.0, 10.0), Material::Annex),
        block((-120.0, 120.0), (0.0, 3.0), (-3.0, 0.0), Material::Quay),
    ];
    for (x, z) in TOWERS {
        blocks.push(block((x - 11.0, x + 11.0), (0.0, 46.0), (z - 11.0, z + 11.0), Material::Tower));
        blocks.push(block((x - 8.0, x + 8.0), (46.0, 50.0), (z - 8.0, z + 8.0), Material::Tower));
        blocks.push(block((x - 6.0, x + 6.0), (50.0, CHIMNEY_BASE), (z - 6.0, z + 6.0), Material::Pedestal));
    }
    blocks
}

/// Where a ray enters a box, and the face it enters by.
fn hit_block(origin: Vector, direction: Vector, block: &Block) -> Option<(f64, Vector)> {
    let (mut near, mut far, mut axis) = (f64::NEG_INFINITY, f64::INFINITY, 0);
    for i in 0..3 {
        if direction[i].abs() < 1e-9 {
            if origin[i] < block.low[i] || origin[i] > block.high[i] {
                return None;
            }
            continue;
        }
        let (mut first, mut second) =
            ((block.low[i] - origin[i]) / direction[i], (block.high[i] - origin[i]) / direction[i]);
        if first > second {
            std::mem::swap(&mut first, &mut second);
        }
        if first > near {
            near = first;
            axis = i;
        }
        far = far.min(second);
        if near > far {
            return None;
        }
    }
    if near < 1e-4 {
        return None;
    }
    let mut normal = [0.0; 3];
    normal[axis] = if direction[axis] > 0.0 { -1.0 } else { 1.0 };
    Some((near, normal))
}

/// Where a ray meets a chimney: the distance, the normal and the height
/// along the shaft, from 0 to 1.
fn hit_chimney(origin: Vector, direction: Vector, centre: (f64, f64)) -> Option<(f64, Vector, f64)> {
    let (ox, oz) = (origin[0] - centre.0, origin[2] - centre.1);
    let a = direction[0] * direction[0] + direction[2] * direction[2];
    let b = 2.0 * (ox * direction[0] + oz * direction[2]);
    let c = ox * ox + oz * oz - CHIMNEY_RADIUS * CHIMNEY_RADIUS;
    let discriminant = b * b - 4.0 * a * c;
    if discriminant < 0.0 || a < 1e-9 {
        return None;
    }
    let distance = (-b - discriminant.sqrt()) / (2.0 * a);
    let height = origin[1] + direction[1] * distance;
    if distance < 1e-4 || !(CHIMNEY_BASE..=CHIMNEY_TOP).contains(&height) {
        return None;
    }
    let normal = unit([ox + direction[0] * distance, 0.0, oz + direction[2] * distance]);
    Some((distance, normal, (height - CHIMNEY_BASE) / (CHIMNEY_TOP - CHIMNEY_BASE)))
}

/// Where a ray meets an ellipsoid: the distance and the normal.
fn hit_ellipsoid(origin: Vector, direction: Vector, centre: Vector, radii: Vector) -> Option<(f64, Vector)> {
    let o =
        [(origin[0] - centre[0]) / radii[0], (origin[1] - centre[1]) / radii[1], (origin[2] - centre[2]) / radii[2]];
    let d = [direction[0] / radii[0], direction[1] / radii[1], direction[2] / radii[2]];
    let (a, b, c) = (dot(d, d), 2.0 * dot(o, d), dot(o, o) - 1.0);
    let discriminant = b * b - 4.0 * a * c;
    if discriminant < 0.0 {
        return None;
    }
    let distance = (-b - discriminant.sqrt()) / (2.0 * a);
    if distance < 1e-4 {
        return None;
    }
    let at = along(o, d, distance);
    Some((distance, unit([at[0] / radii[0], at[1] / radii[1], at[2] / radii[2]])))
}

/// Where the pig is `seconds` into the animation: it drifts between the two
/// pairs of chimneys, and bobs.
pub fn pig_at(seconds: f64) -> [f64; 3] {
    [(seconds * 0.5).sin() * 26.0 - 2.0, 84.0 + (seconds * 1.3).sin() * 3.0, 32.0]
}

/// The pig: body, head, snout, four legs and an ear, each an ellipsoid.
fn pig(seconds: f64) -> [(Vector, Vector); 8] {
    const SCALE: f64 = 1.55;
    const PARTS: [(Vector, Vector); 8] = [
        ([0.0, 0.0, 0.0], [13.0, 7.0, 7.0]),
        ([12.0, 1.0, 0.0], [5.5, 5.0, 5.0]),
        ([17.0, 0.2, 0.0], [2.6, 2.4, 2.4]),
        ([-6.0, -7.0, -3.0], [1.8, 3.6, 1.8]),
        ([5.0, -7.0, -3.0], [1.8, 3.6, 1.8]),
        ([-6.0, -7.0, 3.0], [1.8, 3.6, 1.8]),
        ([5.0, -7.0, 3.0], [1.8, 3.6, 1.8]),
        ([11.0, 6.0, -2.0], [1.6, 2.6, 1.2]),
    ];
    let centre = pig_at(seconds);
    PARTS.map(|(offset, radii)| {
        (
            [centre[0] + offset[0] * SCALE, centre[1] + offset[1] * SCALE, centre[2] + offset[2] * SCALE],
            [radii[0] * SCALE, radii[1] * SCALE, radii[2] * SCALE],
        )
    })
}

/// How much of the picture shows `seconds` into the animation, from 0 to 1.
pub fn fade_at(seconds: f64) -> f64 {
    // A second to come out of the dark; after the night has fallen, the rest of the time to go back to it.
    (seconds / FADE_IN).min((END - seconds) / (END - DURATION)).clamp(0.0, 1.0)
}

/// How far the night has fallen `seconds` into the animation, from 0 to 1.
pub fn night_at(seconds: f64) -> f64 {
    smooth(0.25, 0.95, seconds / DURATION)
}

/// The sky in a direction: dusk turning to night, the last of the sun, two
/// layers of clouds that drift at their own speed, then the stars.
fn sky(direction: Vector, seconds: f64, night: f64) -> Colour {
    let elevation = direction[1].max(0.0);
    let top = mix([30.0, 38.0, 84.0], [6.0, 8.0, 26.0], night);
    let middle = mix([120.0, 84.0, 126.0], [30.0, 26.0, 62.0], night);
    let low = mix([250.0, 150.0, 84.0], [120.0, 60.0, 70.0], night);
    let mut colour = mix(low, middle, smooth(0.0, 0.22, elevation));
    colour = mix(colour, top, smooth(0.15, 0.7, elevation));
    let azimuth = direction[0].atan2(direction[2]);
    let sun = (-(azimuth - 0.62).powi(2) * 9.0 - elevation.powi(2) * 50.0).exp() * (1.0 - night * 0.75);
    colour = mix(colour, [255.0, 222.0, 150.0], sun * 0.9);
    for (scale, speed, amount, tint) in
        [(3.2, 0.012, 0.55, [86.0, 60.0, 92.0]), (6.5, 0.03, 0.35, [255.0, 170.0, 120.0])]
    {
        let density = clouds(azimuth * scale + seconds * speed * scale, elevation * scale * 4.0 + scale);
        let cover = smooth(0.52, 0.78, density) * smooth(0.02, 0.12, elevation) * (1.0 - smooth(0.45, 0.8, elevation));
        colour = mix(colour, mix(tint, [20.0, 18.0, 40.0], night), cover * amount);
    }
    if night > 0.05 && elevation > 0.08 {
        let (x, y) = ((azimuth * 180.0).floor(), (elevation * 280.0).floor());
        if hash(x, y) > 0.992 {
            colour = mix(colour, [255.0, 250.0, 230.0], night * (0.5 + 0.5 * (seconds * 3.0 + x).sin()));
        }
    }
    colour
}

/// What a ray sees. `mirrored` is the ray the river sends back: it does not
/// bounce again.
fn trace(origin: Vector, direction: Vector, seconds: f64, night: f64, scene: &[Block], mirrored: bool) -> Colour {
    enum Seen {
        Block(Material),
        Chimney(f64),
        Pig(usize),
        Ground,
    }
    let light = unit([-0.55, 0.5, -0.65]);
    let mut nearest: Option<(f64, Vector, Seen)> = None;
    let mut keep = |distance: f64, normal: Vector, seen: Seen| {
        if nearest.as_ref().is_none_or(|(best, _, _)| distance < *best) {
            nearest = Some((distance, normal, seen));
        }
    };
    for block in scene {
        if let Some((distance, normal)) = hit_block(origin, direction, block) {
            keep(distance, normal, Seen::Block(block.material));
        }
    }
    for centre in TOWERS {
        if let Some((distance, normal, height)) = hit_chimney(origin, direction, centre) {
            keep(distance, normal, Seen::Chimney(height));
        }
    }
    let parts = pig(seconds);
    for (index, (centre, radii)) in parts.iter().enumerate() {
        if let Some((distance, normal)) = hit_ellipsoid(origin, direction, *centre, *radii) {
            keep(distance, normal, Seen::Pig(index));
        }
    }
    // The ground, and in front of the quay the river.
    if direction[1] < -1e-6 {
        let distance = -origin[1] / direction[1];
        if distance > 1e-4 && nearest.as_ref().is_none_or(|(best, _, _)| distance < *best) {
            let at = along(origin, direction, distance);
            if at[2] >= -3.0 {
                nearest = Some((distance, [0.0, 1.0, 0.0], Seen::Ground));
            } else {
                let water = mix([34.0, 58.0, 104.0], [10.0, 16.0, 40.0], night);
                if mirrored {
                    return water;
                }
                let ripple =
                    (at[0] * 0.11 + seconds * 1.6).sin() * 0.012 + (at[2] * 0.21 - seconds * 1.1).sin() * 0.012;
                let back = unit([direction[0] + ripple, -direction[1], direction[2] + ripple * 0.5]);
                let mut colour = mix(water, trace(at, back, seconds, night, scene, true), 0.55);
                if noise(at[0] * 0.35 + seconds * 1.2, at[2] * 0.12) > 0.9 {
                    colour = mix(colour, [255.0, 226.0, 180.0], 0.3 * (1.0 - night * 0.6));
                }
                return colour;
            }
        }
    }
    let Some((distance, normal, seen)) = nearest else {
        return sky(direction, seconds, night);
    };
    let at = along(origin, direction, distance);
    let facing = dot(normal, light).max(0.0);
    let lit = 0.62 - night * 0.3 + 0.6 * facing * (1.0 - night * 0.6);
    match seen {
        Seen::Ground => mix([40.0, 30.0, 34.0], [12.0, 10.0, 16.0], night),
        Seen::Pig(part) => {
            let mut colour = if part == 2 { [255.0, 110.0, 170.0] } else { PIG };
            // The eye, on the side of the head that faces the river.
            if part == 1 {
                let (dx, dy) = (at[0] - (parts[1].0[0] + 3.6), at[1] - (parts[1].0[1] + 2.4));
                if dx * dx + dy * dy < 2.2 && normal[2] < 0.0 {
                    colour = INK;
                }
            }
            let glow = 0.62 + 0.5 * facing + normal[1].max(0.0) * 0.35 - night * 0.15;
            [(colour[0] * glow).min(255.0), (colour[1] * glow).min(255.0), (colour[2] * glow).min(255.0)]
        }
        Seen::Chimney(height) => {
            let flutes = 0.94 + 0.06 * (normal[0].atan2(normal[2]) * 12.0).sin();
            let glow = (0.62 + 0.42 * (normal[0] * light[0] + normal[2] * light[2]).max(0.0)) * flutes - night * 0.3;
            let band = if height > 0.93 || (0.12..0.15).contains(&height) { 0.8 } else { 1.0 };
            [CREAM[0] * glow * band, CREAM[1] * glow * band, CREAM[2] * glow * band].map(|part| part.min(255.0))
        }
        Seen::Block(Material::Quay) => mix([44.0, 34.0, 38.0], [14.0, 12.0, 18.0], night),
        Seen::Block(material) => {
            let across = if normal[2].abs() > 0.5 { at[0] } else { at[2] };
            let (base, grain) = if normal[1].abs() > 0.5 {
                (ROOF, 1.0)
            } else if material == Material::Pedestal {
                ([206.0, 196.0, 176.0], 1.0)
            } else {
                (BRICK, 0.96 + 0.08 * hash(across * 0.6, at[1] * 0.8))
            };
            let wall = [base[0] * lit * grain, base[1] * lit * grain, base[2] * lit * grain];
            // The windows of a wall: how wide a bay is, how much of it is glass, from where to where.
            let bays = match material {
                Material::Tower => Some((22.0, 0.14, 8.0, 40.0, 1.0)),
                Material::Attic => Some((9.0, 0.3, 35.5, 40.5, 2.0)),
                Material::Annex => Some((7.5, 0.34, 4.0, 17.0, 3.0)),
                Material::Hall => Some((8.0, 0.3, 22.0, 31.0, 4.0)),
                Material::Pedestal | Material::Quay => None,
            };
            let Some((bay, glass, from, to, seed)) = bays.filter(|_| normal[1].abs() < 0.5) else {
                return wall;
            };
            let within = (across / bay).rem_euclid(1.0);
            if (within - 0.5).abs() >= glass || at[1] <= from || at[1] >= to {
                return wall;
            }
            // Each window lights up at its own moment as the night falls.
            let index = (across / bay).floor();
            let on = smooth(0.0, 1.0, night * 1.5 + 0.25 - hash(index + 77.0, seed) * 0.9);
            let flicker = 0.85 + 0.15 * (seconds * 2.3 + index).sin();
            let window = mix([40.0, 28.0, 32.0], [255.0, 208.0, 104.0], on * flicker);
            let mullion = ((at[1] - from) * 0.55).floor().rem_euclid(3.0) == 2.0;
            if mullion { mix(window, [60.0, 34.0, 30.0], 0.6) } else { window }
        }
    }
}

/// The picture `seconds` into the animation, for a text of `columns` by
/// `rows`: two samples a column, two a row.
pub fn picture(columns: usize, rows: usize, seconds: f64) -> Vec<Vec<Rgb>> {
    let (width, height) = (columns * 2, rows * 2);
    // A character is twice as tall as it is wide.
    let aspect = columns as f64 / (rows as f64 * 2.0);
    let (view, scene, night) = (View::new(), blocks(), night_at(seconds));
    let mut pixels: Vec<Vec<Colour>> = (0..height)
        .map(|row| {
            let y = 1.0 - (row as f64 + 0.5) / height as f64 * 2.0;
            (0..width)
                .map(|column| {
                    let x = (column as f64 + 0.5) / width as f64 * 2.0 - 1.0;
                    trace(CAMERA, view.ray(x, y, aspect), seconds, night, &scene, false)
                })
                .collect()
        })
        .collect();
    let (wide, high) = (width as f64, height as f64);
    let mut blend = |x: f64, y: f64, colour: Colour, amount: f64| {
        if x >= 0.0 && y >= 0.0 && (x as usize) < width && (y as usize) < height {
            let pixel = &mut pixels[y as usize][x as usize];
            *pixel = mix(*pixel, colour, amount);
        }
    };
    let place = |point: Vector| {
        let (x, y, depth) = view.project(point, aspect);
        ((x + 1.0) / 2.0 * wide, (1.0 - y) / 2.0 * high, depth)
    };
    // The smoke: puffs that rise from each chimney, then leave with the wind.
    let smoke = mix([222.0, 214.0, 210.0], [70.0, 66.0, 86.0], night);
    for (stack, (x, z)) in TOWERS.into_iter().enumerate() {
        let stack = stack as f64;
        for puff in 0..26 {
            let age = (f64::from(puff) + seconds * 4.0 + stack * 5.0).rem_euclid(26.0);
            let at = [
                x + age * 3.4 + (age * 0.5 + stack).sin() * 2.5,
                CHIMNEY_TOP + 2.0 + age * 0.9 + (age * 0.7 + stack * 2.0).sin() * 2.0,
                z,
            ];
            let (centre_x, centre_y, depth) = place(at);
            let across = ((2.2 + age * 0.42) * wide / (depth * FIELD * aspect)).max(0.6);
            let above = (across * high / wide * aspect).max(0.6);
            let thickness = (0.5 - age * 0.019).max(0.0);
            let reach = across.ceil() as i64 + 1;
            for dy in -reach..=reach {
                for dx in -reach..=reach {
                    let inside = (dx as f64 / across).powi(2) + (dy as f64 / above).powi(2);
                    if inside < 1.0 {
                        blend(
                            centre_x.floor() + dx as f64,
                            centre_y.floor() + dy as f64,
                            smoke,
                            thickness * (1.0 - inside),
                        );
                    }
                }
            }
        }
    }
    // The cable that holds the pig to the roof.
    let pig = pig_at(seconds);
    let (from, to) = (place([pig[0], pig[1] - 10.0, pig[2]]), place([0.0, 42.0, 32.0]));
    let steps = (from.0 - to.0).abs().max((from.1 - to.1).abs()).ceil().max(1.0);
    for step in 0..=steps as usize {
        let along = step as f64 / steps;
        blend(from.0 + (to.0 - from.0) * along, from.1 + (to.1 - from.1) * along, INK, 0.55);
    }
    // A few birds on their way home.
    for bird in 0..5 {
        let bird = f64::from(bird);
        let x = ((seconds * 0.045 + bird * 0.17 + hash(bird, 3.0) * 0.2).rem_euclid(1.2) - 0.1) * wide;
        let y = (0.16 + hash(bird, 9.0) * 0.2) * high + (seconds * 1.4 + bird).sin() * 1.5;
        let wings = if (seconds * 9.0 + bird * 2.0).sin() > 0.0 { 1.0 } else { 0.0 };
        for (dx, dy) in [(-2.0, -wings), (-1.0, 0.0), (0.0, 1.0 - wings), (1.0, 0.0), (2.0, -wings)] {
            blend(x.floor() + dx, y.floor() + dy, [24.0, 18.0, 30.0], 0.8);
        }
    }
    let shown = fade_at(seconds);
    pixels
        .into_iter()
        .map(|row| {
            row.into_iter().map(|colour| colour.map(|part| (part * shown).clamp(0.0, 255.0).round() as u8)).collect()
        })
        .collect()
}

/// The quadrant character for each set of samples drawn in the foreground
/// colour: bit 0 is the upper left one, 1 the upper right, 2 the lower left,
/// 3 the lower right.
const QUADRANTS: [char; 16] = [' ', '▘', '▝', '▀', '▖', '▌', '▞', '▛', '▗', '▚', '▐', '▜', '▄', '▙', '▟', '█'];

/// How far apart, squared, two samples of a cell must be for the cell to be
/// split in two colours: sixteen on each of red, green and blue.
const SEAM: i32 = 3 * 16 * 16;

fn distance(a: Rgb, b: Rgb) -> i32 {
    (0..3).map(|part| (i32::from(a[part]) - i32::from(b[part])).pow(2)).sum()
}

fn average(colours: &[Rgb]) -> Rgb {
    let count = colours.len().max(1) as u32;
    [0, 1, 2].map(|part| (colours.iter().map(|colour| u32::from(colour[part])).sum::<u32>() / count) as u8)
}

/// A picture as text: a character per four samples, drawn in the two colours
/// that tell them best, and the colours reset at the end of each line.
pub fn render(pixels: &[Vec<Rgb>]) -> String {
    let mut text = String::new();
    for pair in pixels.chunks_exact(2) {
        let mut last: Option<(Rgb, Rgb)> = None;
        for column in (0..pair[0].len().saturating_sub(1)).step_by(2) {
            let samples = [pair[0][column], pair[0][column + 1], pair[1][column], pair[1][column + 1]];
            // The two samples furthest apart give the two colours of the cell.
            let (mut first, mut second, mut apart) = (0, 0, 0);
            for a in 0..4 {
                for b in a + 1..4 {
                    if distance(samples[a], samples[b]) > apart {
                        (first, second, apart) = (a, b, distance(samples[a], samples[b]));
                    }
                }
            }
            // Too close to tell apart: one colour, and no seam.
            if apart < SEAM {
                apart = 0;
            }
            let mut mask = 0;
            let (mut front, mut back) = (Vec::new(), Vec::new());
            for (index, sample) in samples.into_iter().enumerate() {
                if apart > 0 && distance(sample, samples[first]) <= distance(sample, samples[second]) {
                    mask |= 1 << index;
                    front.push(sample);
                } else {
                    back.push(sample);
                }
            }
            let colours = (average(if front.is_empty() { &back } else { &front }), average(&back));
            if last != Some(colours) {
                let (fore, behind) = colours;
                text.push_str(&format!(
                    "\u{1b}[38;2;{};{};{};48;2;{};{};{}m",
                    fore[0], fore[1], fore[2], behind[0], behind[1], behind[2]
                ));
                last = Some(colours);
            }
            text.push(QUADRANTS[mask]);
        }
        text.push_str("\u{1b}[0m\n");
    }
    text
}

/// The size of the picture for a terminal of `columns` by `rows`: as wide as
/// it can be, within its proportions and the height left. None when that is
/// too small for the picture to be worth showing.
pub fn fit(columns: usize, rows: usize) -> Option<(usize, usize)> {
    let wide = columns.min(MAX_COLUMNS);
    let high = (wide as f64 * ROWS_PER_COLUMN).round() as usize;
    let room = rows.saturating_sub(MARGIN).max(1);
    let (wide, high) =
        if high <= room { (wide, high.max(1)) } else { ((room as f64 / ROWS_PER_COLUMN).round() as usize, room) };
    (wide >= MIN_COLUMNS).then_some((wide, high))
}

/// Plays `frames` pictures of `columns` by `rows` on `out`, `delay` apart,
/// each drawn over the last; the cursor is hidden meanwhile and shown again
/// at the end.
pub async fn play(out: &mut impl Write, columns: usize, rows: usize, frames: u32, delay: Duration) {
    let _ = write!(out, "\u{1b}[?25l");
    for index in 0..frames {
        let seconds = f64::from(index) / f64::from(FRAME_RATE);
        let back = if index == 0 { String::new() } else { format!("\u{1b}[{rows}A") };
        let drawn = write!(out, "{back}{}", render(&picture(columns, rows, seconds))).and_then(|()| out.flush());
        if drawn.is_err() {
            break;
        }
        tokio::time::sleep(delay).await;
    }
    // The picture went back to the dark: its lines are given back to the terminal.
    if frames > 0 {
        let _ = write!(out, "\u{1b}[{rows}A\u{1b}[J");
    }
    show_cursor(out);
}

/// Shows the cursor again: also what an interrupted animation owes the terminal.
pub fn show_cursor(out: &mut impl Write) {
    let _ = write!(out, "\u{1b}[?25h").and_then(|()| out.flush());
}

#[cfg(test)]
mod tests {
    use std::f64::consts::TAU as TURN;

    use super::*;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn a_ray_enters_a_box_by_the_face_it_meets_first() {
        let cube = Block { low: [-1.0, -1.0, -1.0], high: [1.0, 1.0, 1.0], material: Material::Hall };
        let (distance, normal) = hit_block([0.0, 0.0, -10.0], [0.0, 0.0, 1.0], &cube).expect("hit");
        assert!(close(distance, 9.0));
        assert_eq!(normal, [0.0, 0.0, -1.0]);
        // Beside it, and away from it: nothing.
        assert!(hit_block([5.0, 0.0, -10.0], [0.0, 0.0, 1.0], &cube).is_none());
        assert!(hit_block([0.0, 0.0, -10.0], [0.0, 0.0, -1.0], &cube).is_none());
    }

    #[test]
    fn a_ray_meets_an_ellipsoid_on_its_near_side() {
        let (distance, normal) =
            hit_ellipsoid([0.0, 0.0, -10.0], [0.0, 0.0, 1.0], [0.0; 3], [2.0, 1.0, 3.0]).expect("hit");
        assert!(close(distance, 7.0));
        assert!(close(normal[2], -1.0));
        assert!(hit_ellipsoid([0.0, 5.0, -10.0], [0.0, 0.0, 1.0], [0.0; 3], [2.0, 1.0, 3.0]).is_none());
    }

    #[test]
    fn a_ray_meets_a_chimney_between_its_base_and_its_top() {
        // Level, halfway up the shaft, straight at its axis.
        let middle = (CHIMNEY_BASE + CHIMNEY_TOP) / 2.0;
        let (distance, normal, height) = hit_chimney([0.0, middle, -100.0], [0.0, 0.0, 1.0], (0.0, 0.0)).expect("hit");
        assert!(close(distance, 100.0 - CHIMNEY_RADIUS));
        assert!(close(normal[2], -1.0));
        assert!(close(height, 0.5));
        // Under the base there is the tower, not the chimney.
        assert!(hit_chimney([0.0, 10.0, -100.0], [0.0, 0.0, 1.0], (0.0, 0.0)).is_none());
    }

    #[test]
    fn what_the_camera_looks_at_is_in_the_middle_of_the_picture() {
        let (x, y, depth) = View::new().project(TARGET, 1.78);
        assert!(close(x, 0.0) && close(y, 0.0), "{x} {y}");
        assert!(depth > 0.0);
    }

    #[test]
    fn the_pig_drifts_from_one_pair_of_chimneys_to_the_other() {
        let view = View::new();
        // A quarter of its swing puts it 26 to the right of its middle, three quarters 26 to the left.
        let quarter = TURN / 4.0 / 0.5;
        assert!(close(pig_at(quarter)[0], 24.0));
        assert!(close(pig_at(quarter * 3.0)[0], -28.0));
        let right = view.project(pig_at(quarter), 1.78).0;
        let left = view.project(pig_at(quarter * 3.0), 1.78).0;
        assert!(left < right, "{left} {right}");
        // Always above the roof and under the top of the chimneys.
        for tenth in 0..120 {
            let height = pig_at(f64::from(tenth) / 10.0)[1];
            assert!((60.0..CHIMNEY_TOP).contains(&height), "{height}");
        }
    }

    #[test]
    fn the_night_falls_over_the_animation() {
        assert!(close(night_at(0.0), 0.0));
        assert!(close(night_at(DURATION), 1.0));
        assert!(night_at(4.0) < night_at(8.0));
    }

    #[test]
    fn the_picture_comes_out_of_the_dark_and_goes_back_to_it() {
        // A second to appear, the whole fall of the night in full, two seconds to fade.
        assert!(close(fade_at(0.0), 0.0));
        assert!(close(fade_at(1.0), 1.0));
        assert!(close(fade_at(DURATION), 1.0));
        assert!(close(fade_at(DURATION + 1.0), 0.5));
        assert!(close(fade_at(END), 0.0));
        assert!(picture(8, 3, END).iter().flatten().all(|pixel| *pixel == [0, 0, 0]));
        assert!(picture(8, 3, 6.0).iter().flatten().any(|pixel| *pixel != [0, 0, 0]));
        // The pictures played cover the whole of it, at twelve a second.
        assert_eq!(f64::from(FRAMES) / f64::from(FRAME_RATE), END);
    }

    #[test]
    fn a_picture_has_two_samples_a_column_and_two_a_row() {
        let pixels = picture(20, 6, 0.0);
        assert_eq!(pixels.len(), 12);
        assert!(pixels.iter().all(|row| row.len() == 40));
    }

    #[test]
    fn the_sky_is_blue_overhead_and_warm_on_the_horizon_at_dusk() {
        let overhead = sky([0.0, 1.0, 0.0], 0.0, 0.0);
        assert!(overhead[2] > overhead[0], "{overhead:?}");
        // Level, away from the sun and under the clouds.
        let horizon = sky(unit([-1.0, 0.001, 0.2]), 0.0, 0.0);
        assert!(horizon[0] > horizon[2], "{horizon:?}");
        // Once the night has fallen the same horizon is darker.
        let later = sky(unit([-1.0, 0.001, 0.2]), DURATION, 1.0);
        assert!(later[0] < horizon[0], "{later:?}");
    }

    #[test]
    fn four_samples_alike_are_one_colour() {
        let grey = [90, 90, 90];
        assert_eq!(render(&[vec![grey, grey], vec![grey, grey]]), "\u{1b}[38;2;90;90;90;48;2;90;90;90m \u{1b}[0m\n");
    }

    #[test]
    fn samples_almost_alike_are_one_colour_too() {
        // A glyph that splits a cell leaves a seam on the screen: a soft gradient (the sky, the
        // smoke) is drawn as plain cells, each of the average of its samples.
        let (darker, lighter) = ([90, 90, 90], [96, 96, 96]);
        assert_eq!(
            render(&[vec![darker, darker], vec![lighter, lighter]]),
            "\u{1b}[38;2;93;93;93;48;2;93;93;93m \u{1b}[0m\n"
        );
        // A real edge is still drawn.
        let edge = [130, 130, 130];
        assert_eq!(
            render(&[vec![darker, darker], vec![edge, edge]]),
            "\u{1b}[38;2;90;90;90;48;2;130;130;130m▀\u{1b}[0m\n"
        );
    }

    #[test]
    fn a_cell_is_drawn_in_the_two_colours_that_tell_its_samples() {
        let (white, black) = ([255, 255, 255], [0, 0, 0]);
        // White over black: the upper half block, white on black.
        assert_eq!(
            render(&[vec![white, white], vec![black, black]]),
            "\u{1b}[38;2;255;255;255;48;2;0;0;0m▀\u{1b}[0m\n"
        );
        // White beside black: the left half block.
        assert_eq!(
            render(&[vec![white, black], vec![white, black]]),
            "\u{1b}[38;2;255;255;255;48;2;0;0;0m▌\u{1b}[0m\n"
        );
        // One corner alone.
        assert_eq!(
            render(&[vec![black, black], vec![black, white]]),
            "\u{1b}[38;2;0;0;0;48;2;255;255;255m▛\u{1b}[0m\n"
        );
    }

    #[test]
    fn a_colour_already_set_is_not_set_again() {
        let (white, black) = ([255, 255, 255], [0, 0, 0]);
        let text = render(&[vec![white, white, white, white], vec![black, black, black, black]]);
        assert_eq!(text, "\u{1b}[38;2;255;255;255;48;2;0;0;0m▀▀\u{1b}[0m\n");
    }

    #[test]
    fn a_picture_is_a_line_of_text_per_row_and_a_character_per_column() {
        let text = render(&picture(24, 7, 3.0));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 7);
        for line in lines {
            assert_eq!(line.chars().filter(|character| QUADRANTS.contains(character)).count(), 24, "{line:?}");
            assert!(line.ends_with("\u{1b}[0m"), "{line:?}");
        }
    }

    #[test]
    fn the_picture_fits_the_terminal_within_its_proportions() {
        // Wide and tall: as wide as a picture gets, 28 rows a hundred columns.
        assert_eq!(fit(200, 60), Some((150, 42)));
        // The width decides…
        assert_eq!(fit(100, 60), Some((100, 28)));
        // …unless the height runs out: three lines stay free under the picture.
        assert_eq!(fit(160, 36), Some((118, 33)));
    }

    #[test]
    fn a_terminal_too_small_for_the_pig_gets_no_picture() {
        // Under a hundred columns the pig is a blur: the plain drawing is shown instead.
        assert_eq!(fit(99, 60), None);
        assert_eq!(fit(80, 24), None);
        // Wide enough, but so low that the picture would be narrower than a hundred columns.
        assert_eq!(fit(140, 24), None);
    }

    #[tokio::test]
    async fn the_pictures_are_drawn_over_one_another_with_the_cursor_hidden() {
        let mut out: Vec<u8> = Vec::new();
        play(&mut out, 16, 5, 3, Duration::ZERO).await;
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("\u{1b}[?25l"), "the cursor is hidden first");
        // At the end the picture is taken away, so that only the line of the tool is left, and the cursor is back.
        assert!(text.ends_with("\u{1b}[5A\u{1b}[J\u{1b}[?25h"), "{:?}", &text[text.len() - 40..]);
        // Three pictures: the second and the third each go back up five lines, and so does the end.
        assert_eq!(text.matches("\u{1b}[5A").count(), 3);
        assert_eq!(text.matches("\u{1b}[0m\n").count(), 15);
    }
}
