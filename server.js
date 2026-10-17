// agri-app/backend/server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Static for uploaded images
app.use('/uploads', express.static('uploads'));

// ---- DB CONNECT ----
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('Mongo connected'))
  .catch((err) => console.error('Mongo error', err));

// ---- MULTER (profile photo upload) ----
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // make sure uploads/ exists
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, req.user.id + '-' + Date.now() + ext);
  },
});
const upload = multer({ storage });

// ---- SCHEMAS ----
const userSchema = new mongoose.Schema({
  role: { type: String, enum: ['owner', 'customer'], required: true },

  // LOGIN PHONE (fixed)
  phone: { type: String, unique: true, required: true },

  // PROFILE FIELDS (register time, permanent)
  name: { type: String, required: true },
  contactPhone: { type: String, required: true }, // calls, whatsapp etc.
  village: String,
  profilePhotoUrl: String,

  passwordHash: String,

  // stored location (no live update API now)
  location: {
    lat: Number,
    lng: Number,
    updatedAt: Date,
  },

  rating: { type: Number, default: 5 },
  ratingCount: { type: Number, default: 0 },
  blocked: { type: Boolean, default: false },
});

const equipmentSchema = new mongoose.Schema({
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  category: {
    type: String,
    enum: ['tractor', 'harvester', 'drone', 'lorry', 'planting'],
    required: true,
  },
  imageUrl: String,
  items: [
    {
      name: String,
      unit: String,
      price: Number,
      // item-level availability
      available: { type: Boolean, default: true },
    },
  ],
  // equipment-level availability flag
  available: { type: Boolean, default: true },
});

const bookingSchema = new mongoose.Schema({
  customerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  equipmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Equipment' },
  itemName: String,
  date: String,
  time: String,
  status: {
    type: String,
    enum: ['pending', 'accepted', 'completed', 'cancelled'],
    default: 'pending',
  },
  rating: { type: Number, default: null },
});

const User = mongoose.model('User', userSchema);
const Equipment = mongoose.model('Equipment', equipmentSchema);
const Booking = mongoose.model('Booking', bookingSchema);

// ---- HELPER: distance ----
function distanceKm(lat1, lon1, lat2, lon2) {
  if (lat1 == null || lon1 == null || lat2 == null || lon2 == null) return null;
  const R = 6371;
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;

  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.asin(Math.sqrt(a));
  return R * c;
}

// ---- AUTH HELPERS ----
function signToken(user) {
  return jwt.sign(
    { id: user._id.toString(), role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function auth(roles = []) {
  return (req, res, next) => {
    const header = req.headers['authorization'];
    if (!header) return res.status(401).json({ message: 'No auth header' });

    const [type, token] = header.split(' ');
    if (type !== 'Bearer' || !token) {
      return res.status(401).json({ message: 'Bad auth header' });
    }
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (roles.length && !roles.includes(decoded.role)) {
        return res.status(403).json({ message: 'Not allowed' });
      }
      req.user = decoded;
      next();
    } catch (e) {
      return res.status(401).json({ message: 'Invalid token' });
    }
  };
}

// ---- AUTH ROUTES ----
app.post('/auth/register', async (req, res) => {
  try {
    const { role, name, phone, password, village } = req.body;
    if (!role || !name || !phone || !password) {
      return res
        .status(400)
        .json({ message: 'role, name, phone, password required' });
    }
    const existing = await User.findOne({ phone });
    if (existing) {
      return res.status(400).json({ message: 'Phone already registered' });
    }
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({
      role,
      name,
      phone,           // login phone (fixed)
      contactPhone: phone, // contact same as login (permanent)
      passwordHash: hash,
      village,
    });
    const token = signToken(user);
    res.json({
      token,
      role: user.role,
      name: user.name,
      village: user.village,
      phone: user.phone,
      contactPhone: user.contactPhone,
      profilePhotoUrl: user.profilePhotoUrl || null,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    const user = await User.findOne({ phone }); // LOGIN always by fixed phone
    if (!user) return res.status(400).json({ message: 'User not found' });
    if (user.blocked) return res.status(403).json({ message: 'Account blocked' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(400).json({ message: 'Wrong password' });

    const token = signToken(user);
    res.json({
      token,
      role: user.role,
      name: user.name,
      village: user.village,
      phone: user.phone,
      contactPhone: user.contactPhone,
      profilePhotoUrl: user.profilePhotoUrl || null,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/me', auth(), async (req, res) => {
  const user = await User.findById(req.user.id).select('-passwordHash');
  res.json(user);
});

// NOTE: /me/profile route REMOVED → profile edit not allowed, permanent profile
// NOTE: /location/update route REMOVED → no live location update, but location field can exist from other sources

// ---- OWNER ROUTES ----
app.post('/owner/equipment', auth(['owner']), async (req, res) => {
  try {
    const { category, imageUrl, items } = req.body;
    if (!category || !items || !Array.isArray(items) || !items.length) {
      return res
        .status(400)
        .json({ message: 'Category + at least 1 item required' });
    }
    const eq = await Equipment.create({
      ownerId: req.user.id,
      category,
      imageUrl: imageUrl || '',
      items, // each item: {name, unit, price, available(optional)}
    });
    res.json(eq);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/owner/equipment', auth(['owner']), async (req, res) => {
  const list = await Equipment.find({ ownerId: req.user.id });
  res.json(list);
});

// equipment availability ON/OFF
app.post(
  '/owner/equipment/:id/availability',
  auth(['owner']),
  async (req, res) => {
    try {
      const { available } = req.body;
      const eq = await Equipment.findOne({
        _id: req.params.id,
        ownerId: req.user.id,
      });
      if (!eq) return res.status(404).json({ message: 'Equipment not found' });

      eq.available = !!available;
      await eq.save();
      res.json({ message: 'Availability updated', available: eq.available });
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// item availability ON/OFF
app.post(
  '/owner/equipment/:id/item/:index/availability',
  auth(['owner']),
  async (req, res) => {
    try {
      const { available } = req.body;
      const idx = parseInt(req.params.index, 10);

      const eq = await Equipment.findOne({
        _id: req.params.id,
        ownerId: req.user.id,
      });
      if (!eq) return res.status(404).json({ message: 'Equipment not found' });

      if (!Array.isArray(eq.items) || idx < 0 || idx >= eq.items.length) {
        return res.status(400).json({ message: 'Invalid item index' });
      }

      eq.items[idx].available = !!available;
      await eq.save();

      res.json({
        message: 'Item availability updated',
        itemIndex: idx,
        available: eq.items[idx].available,
      });
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// OWNER: bookings (owner ki customer contactPhone + location + photo kavali)
app.get('/owner/bookings', auth(['owner']), async (req, res) => {
  try {
    const list = await Booking.find({ ownerId: req.user.id })
      .populate(
        'customerId',
        'name contactPhone village location profilePhotoUrl'
      )
      .populate('equipmentId', 'category')
      .sort({ createdAt: -1 });

    res.json(list);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/owner/bookings/:id/accept', auth(['owner']), async (req, res) => {
  const b = await Booking.findById(req.params.id);
  if (!b) return res.status(404).json({ message: 'Booking not found' });
  if (b.ownerId.toString() !== req.user.id)
    return res.status(403).json({ message: 'Not your booking' });
  b.status = 'accepted';
  await b.save();
  res.json(b);
});

app.post('/owner/bookings/:id/complete', auth(['owner']), async (req, res) => {
  const b = await Booking.findById(req.params.id);
  if (!b) return res.status(404).json({ message: 'Booking not found' });
  if (b.ownerId.toString() !== req.user.id) {
    return res.status(403).json({ message: 'Not your booking' });
  }
  b.status = 'completed';
  await b.save();
  res.json(b);
});

// ---- CUSTOMER ROUTES ----
app.get('/customer/equipment', auth(['customer']), async (req, res) => {
  try {
    const { category } = req.query;
    const radiusKm = Number(req.query.radiusKm) || 10;

    const customer = await User.findById(req.user.id);
    const cLoc = customer.location;

    const filter = { available: true }; // only equipment ON
    if (category) filter.category = category;

    const list = await Equipment.find(filter).populate(
      'ownerId',
      'name village rating ratingCount location contactPhone profilePhotoUrl'
    );

    const result = [];

    list.forEach((eq) => {
      // item-level: only ON items
      const visibleItems = (eq.items || []).filter(
        (it) => it.available !== false
      );
      if (!visibleItems.length) return;

      const oLoc = eq.ownerId.location;
      const d =
        cLoc && cLoc.lat != null && cLoc.lng != null
          ? distanceKm(cLoc.lat, cLoc.lng, oLoc?.lat, oLoc?.lng)
          : null;

      if (d != null && d > radiusKm) return;

      const obj = eq.toObject();
      obj.items = visibleItems;
      if (d != null) obj.distanceKm = d;
      result.push(obj);
    });

    res.json(result);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/customer/book', auth(['customer']), async (req, res) => {
  try {
    const { equipmentId, itemName, date, time } = req.body;
    const eq = await Equipment.findById(equipmentId);
    if (!eq) return res.status(404).json({ message: 'Equipment not found' });
    const booking = await Booking.create({
      customerId: req.user.id,
      ownerId: eq.ownerId,
      equipmentId: eq._id,
      itemName,
      date,
      time,
      status: 'pending',
    });
    res.json(booking);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// CUSTOMER: bookings (customer ki owner contactPhone + location + photo kavali)
app.get('/customer/bookings', auth(['customer']), async (req, res) => {
  try {
    const list = await Booking.find({ customerId: req.user.id })
      .populate(
        'ownerId',
        'name contactPhone village location profilePhotoUrl'
      )
      .populate('equipmentId', 'category')
      .sort({ createdAt: -1 });

    res.json(list);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/customer/rate', auth(['customer']), async (req, res) => {
  try {
    const { bookingId, rating } = req.body;
    if (!rating || rating < 1 || rating > 5) {
      return res.status(400).json({ message: 'Rating must be 1-5' });
    }
    const b = await Booking.findById(bookingId);
    if (!b) return res.status(404).json({ message: 'Booking not found' });
    if (b.customerId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Not your booking' });
    }
    if (b.status !== 'completed') {
      return res
        .status(400)
        .json({ message: 'Can rate only completed bookings' });
    }
    if (b.rating) {
      return res.status(400).json({ message: 'Already rated' });
    }

    b.rating = rating;
    await b.save();

    const owner = await User.findById(b.ownerId);
    const total = owner.rating * owner.ratingCount + rating;
    const count = owner.ratingCount + 1;
    owner.rating = total / count;
    owner.ratingCount = count;

    if (owner.ratingCount >= 2 && owner.rating < 1) {
      owner.blocked = true;
    }
    await owner.save();

    res.json({
      message: 'Rating saved',
      newRating: owner.rating,
      blocked: owner.blocked,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// ---- START ----
const port = process.env.PORT || 4000;
app.listen(port, () => console.log('Backend running on', port));